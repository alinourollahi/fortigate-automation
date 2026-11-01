"""Standalone FortiGate full/limited internet access; standard library only.

Run this file for interactive get/add/delete prompts. Connection settings and
group names come from the JSON file entered at the first prompt; see README.md for configuration and usage.
"""

import ipaddress
import json
import re
import ssl
import sys
from pathlib import Path
import urllib.error
import urllib.request
from urllib.parse import quote, urlencode


# Error handling and validation
##############################################


# Check the HTTP status and JSON response returned by FortiGate.
# Output: The parsed API response; unsuccessful requests raise an error.
def handle_error(response, comment):
    code = response.getcode()

    if not 200 <= code < 300:
        hint = "Check the API request."

        if code == 401:
            hint = "Check the API token."
        elif code == 403:
            hint = (
                "Check API permissions, VDOM access and trusted hosts. "
                "Changes require write permissions."
            )

        raise RuntimeError(
            "%s: HTTP %s. %s" % (comment, code, hint)
        )

    try:
        result = json.load(response)
    except ValueError:
        raise RuntimeError(
            comment + ": invalid JSON response."
        ) from None

    if not isinstance(result, dict) or result.get("status") != "success":
        raise RuntimeError(
            comment + ": FortiGate did not report success."
        )

    return result


# Validate generic IPv4 address/subnet syntax.
# Accepts a single IP, CIDR notation, or an IP followed by a dotted subnet mask.
# Output: True for valid IPv4 subnet syntax, otherwise False.
def validate_subnet(subnet):
    if not isinstance(subnet, str) or not subnet.strip():
        return False

    value = subnet.strip()
    parts = value.split()

    if len(parts) == 2:
        value = parts[0] + "/" + parts[1]
    elif len(parts) != 1:
        return False

    try:
        ipaddress.IPv4Network(value, strict=False)
    except ValueError:
        return False

    return True


# Validate the syntax of one FQDN without performing a DNS lookup.
# IPs, URLs, ports, wildcards and single-label names are rejected.
# Output: True for valid FQDN syntax, otherwise False.
def validate_fqdn(fqdn):
    if not isinstance(fqdn, str):
        return False

    hostname = fqdn.strip()

    if hostname.endswith("."):
        hostname = hostname[:-1]

    if not hostname:
        return False

    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        return False

    try:
        hostname = hostname.encode("idna").decode("ascii")
    except UnicodeError:
        return False

    if len(hostname) > 253:
        return False

    labels = hostname.split(".")

    if len(labels) < 2:
        return False

    label_pattern = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"

    if not all(
        re.fullmatch(label_pattern, label)
        for label in labels
    ):
        return False

    if not re.search(r"[A-Za-z]", labels[-1]):
        return False

    return True


# Validate and normalize one address-group member.
# Only a single IPv4 address or FQDN is accepted, without subnet masks or URLs.
# IPv4 inputs represent individual /32 hosts, not subnets.
# Output: A tuple containing the normalized value and its FortiGate object type.
def normalize_address(destination):
    if not isinstance(destination, str) or not destination.strip():
        raise ValueError(
            "Enter one IPv4 address or FQDN."
        )

    value = destination.strip()

    if validate_subnet(value):
        try:
            address = ipaddress.IPv4Address(value)
        except ValueError:
            raise ValueError(
                "Enter one IPv4 address without a subnet mask."
            ) from None

        return str(address), "ipmask"

    if validate_fqdn(value):
        fqdn = value.rstrip(".").encode("idna").decode("ascii").lower()
        return fqdn, "fqdn"

    raise ValueError(
        "Enter one IPv4 address or FQDN, "
        "without a subnet mask, URL or port."
    )


# Validate and parse the IPv4 subnet stored in an address object.
# Output: An IPv4Network; other object types or invalid subnets raise an error.
def parse_address_subnet(address_object):
    if address_object.get("type", "ipmask") != "ipmask":
        raise RuntimeError(
            "Expected a subnet address object: " + address_object["name"]
        )

    try:
        subnet = address_object["subnet"]

        if isinstance(subnet, list):
            subnet = "/".join(subnet)
        elif isinstance(subnet, str):
            subnet = "/".join(subnet.split())
        else:
            raise ValueError("Invalid subnet value.")

        if not validate_subnet(subnet):
            raise ValueError("Invalid IPv4 subnet.")

        return ipaddress.IPv4Network(subnet, strict=False)

    except (ValueError, KeyError, TypeError):
        raise RuntimeError(
            "Invalid subnet in object: " + address_object["name"]
        ) from None


# Check that an existing object represents the requested IPv4 host or FQDN.
# Output: Nothing; conflicting object types or values raise an error.
def validate_address_object(address_object, value, address_type):
    if address_type == "ipmask":
        expected = ipaddress.IPv4Network(value + "/32")

        if parse_address_subnet(address_object) != expected:
            raise RuntimeError(
                "Existing address object conflicts with "
                + value
                + "/32: "
                + address_object["name"]
            )

        return

    existing_fqdn = address_object.get("fqdn")

    if (
        address_object.get("type") != "fqdn"
        or not validate_fqdn(existing_fqdn)
    ):
        raise RuntimeError(
            "Existing object is not the requested FQDN object: "
            + address_object["name"]
        )

    normalized = (
        existing_fqdn.strip()
        .rstrip(".")
        .encode("idna")
        .decode("ascii")
        .lower()
    )

    if normalized != value:
        raise RuntimeError(
            "Existing FQDN object has a different value: "
            + address_object["name"]
        )


# HTTP connection configuration
##############################################


# Block redirects so authentication tokens are not forwarded elsewhere.
class NoRedirect(urllib.request.HTTPRedirectHandler):
    # Refuse every HTTP redirect.
    # Output: None; urllib raises an HTTP error for the redirect response.
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


# Configure HTTPS certificate verification and redirect handling.
# Output: An HTTP opener. This function does not send requests.
def build_https_opener(verify_tls):
    context = ssl.create_default_context()

    if not verify_tls:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    return urllib.request.build_opener(
        NoRedirect(),
        urllib.request.HTTPSHandler(context=context),
    )


# FortiGate API functions
##############################################


# Add an IPv4 subnet or FQDN address object to FortiGate using POST.
# address_type: "ipmask" or "fqdn". The mask applies only to subnet objects.
# Output: The successful API response. Existing objects are never overwritten.
def add_address_object_to_FG(
    fw_info,
    name,
    value,
    address_type="ipmask",
    mask="255.255.255.255",
    verify_tls=False,
):
    if address_type == "ipmask":
        if (
            not isinstance(value, str)
            or not isinstance(mask, str)
            or not validate_subnet(value + "/" + mask)
        ):
            raise ValueError("Invalid IPv4 address or subnet mask.")

        payload = {
            "name": name,
            "type": "ipmask",
            "subnet": value + " " + mask,
        }

    elif address_type == "fqdn":
        if not validate_fqdn(value):
            raise ValueError("Enter one valid FQDN.")

        fqdn = value.strip().rstrip(".").encode("idna").decode("ascii").lower()

        payload = {
            "name": name,
            "type": "fqdn",
            "fqdn": fqdn,
        }

    else:
        raise ValueError("address_type must be ipmask or fqdn.")

    fg_url = fw_info["url"] + "/api/v2/cmdb/firewall/address"

    if fw_info["vdom"]:
        fg_url += "?" + urlencode({"vdom": fw_info["vdom"]})

    headers = {
        "Authorization": "Bearer " + fw_info["token"],
        "Content-Type": "application/json",
    }

    request = urllib.request.Request(
        fg_url,
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )

    comment = fw_info["name"] + ": creating address " + name
    opener = build_https_opener(verify_tls)

    try:
        with opener.open(request, timeout=30) as response:
            return handle_error(response, comment)

    except urllib.error.HTTPError as error:
        handle_error(error, comment)

    except (urllib.error.URLError, OSError):
        raise RuntimeError(
            comment
            + ": request failed or its response was lost. "
            "Check the firewall before retrying."
        ) from None


# Get subnet address objects, or one named address object, using GET.
# Without object_name, subnet objects are read in pages of up to 500.
# Output: A list of addresses; an optional missing named address returns [].
def get_addresses_from_FG(
    fw_info,
    object_name=None,
    verify_tls=False,
    allow_missing=False,
):
    fg_url = fw_info["url"] + "/api/v2/cmdb/firewall/address"

    if object_name is not None:
        fg_url += "/" + quote(object_name, safe="")

    headers = {
        "Authorization": "Bearer " + fw_info["token"]
    }

    comment = (
        fw_info["name"]
        + ": reading address/"
        + (object_name or "subnet objects")
    )

    opener = build_https_opener(verify_tls)
    addresses = []
    start = 0

    while True:
        params = {"vdom": fw_info["vdom"]} if fw_info["vdom"] else {}

        if object_name is None:
            params.update({
                "filter": "type==ipmask",
                "start": start,
                "count": 500,
            })

        url = fg_url + ("?" + urlencode(params) if params else "")

        request = urllib.request.Request(
            url,
            headers=headers,
            method="GET",
        )

        try:
            with opener.open(request, timeout=30) as response:
                result = handle_error(response, comment)

        except urllib.error.HTTPError as error:
            if (
                error.code == 404
                and object_name is not None
                and allow_missing
            ):
                return []

            handle_error(error, comment)

        except (urllib.error.URLError, OSError):
            raise RuntimeError(
                comment + ": connection failed."
            ) from None

        page = result.get("results")

        if not isinstance(page, list) or any(
            not isinstance(address, dict)
            or not isinstance(address.get("name"), str)
            for address in page
        ):
            raise RuntimeError(comment + ": invalid object list.")

        if object_name is not None:
            if len(page) != 1 or page[0]["name"] != object_name:
                raise RuntimeError(
                    comment + ": the requested address was not returned."
                )

            return page

        addresses.extend(page)

        if not result.get("limit_reached", False):
            return addresses

        next_idx = result.get("next_idx")

        if type(next_idx) is not int or next_idx <= start:
            raise RuntimeError(comment + ": invalid pagination information.")

        start = next_idx


# Get one address group from FortiGate using its exact name.
# Output: The group dictionary, or None on HTTP 404 when allow_missing=True.
def get_addrgrp_from_FG(
    fw_info,
    group_name,
    verify_tls=False,
    allow_missing=False,
):
    fg_url = (
        fw_info["url"]
        + "/api/v2/cmdb/firewall/addrgrp/"
        + quote(group_name, safe="")
    )

    if fw_info["vdom"]:
        fg_url += "?" + urlencode({"vdom": fw_info["vdom"]})

    headers = {
        "Authorization": "Bearer " + fw_info["token"]
    }

    request = urllib.request.Request(
        fg_url,
        headers=headers,
        method="GET",
    )

    comment = fw_info["name"] + ": reading group " + group_name
    opener = build_https_opener(verify_tls)

    try:
        with opener.open(request, timeout=30) as response:
            result = handle_error(response, comment)

    except urllib.error.HTTPError as error:
        if error.code == 404 and allow_missing:
            return None

        handle_error(error, comment)

    except (urllib.error.URLError, OSError):
        raise RuntimeError(
            comment + ": connection failed."
        ) from None

    groups = result.get("results")

    if (
        not isinstance(groups, list)
        or len(groups) != 1
        or not isinstance(groups[0], dict)
        or groups[0].get("name") != group_name
    ):
        raise RuntimeError(
            comment + ": the requested group was not returned."
        )

    return groups[0]


# Check and apply exactly one member addition or removal using PUT.
# Preserve every other member and verify the entire resulting member list.
# Output: The successful API response; mismatches raise an error without rollback.
def update_addrgrp_in_FG(
    fw_info,
    group_name,
    current_members,
    new_members,
    member_name,
    action,
    verify_tls=False,
):
    for members in (current_members, new_members):
        if not isinstance(members, list) or any(
            not isinstance(name, str) or not name.strip()
            for name in members
        ):
            raise ValueError("Member lists must contain nonempty names.")

        if len(members) != len(set(members)):
            raise ValueError("Duplicate group member names are not allowed.")

    if not isinstance(member_name, str) or not member_name.strip():
        raise ValueError("The requested member name must be nonempty.")

    before = set(current_members)
    proposed = set(new_members)

    if action == "add":
        valid_change = (
            len(new_members) == len(current_members) + 1
            and proposed - before == {member_name}
            and not before - proposed
        )

    elif action == "delete":
        valid_change = (
            len(new_members) == len(current_members) - 1
            and before - proposed == {member_name}
            and not proposed - before
        )

    else:
        raise ValueError("Group update action must be add or delete.")

    if not valid_change:
        raise RuntimeError(
            "%s: refusing to update %s. "
            "The proposed list must %s only '%s' "
            "and preserve every other member."
            % (
                fw_info["name"],
                group_name,
                action,
                member_name,
            )
        )

    fg_url = (
        fw_info["url"]
        + "/api/v2/cmdb/firewall/addrgrp/"
        + quote(group_name, safe="")
    )

    if fw_info["vdom"]:
        fg_url += "?" + urlencode({"vdom": fw_info["vdom"]})

    headers = {
        "Authorization": "Bearer " + fw_info["token"],
        "Content-Type": "application/json",
    }

    payload = {
        "member": [{"name": name} for name in new_members]
    }

    request = urllib.request.Request(
        fg_url,
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="PUT",
    )

    comment = fw_info["name"] + ": updating group " + group_name
    opener = build_https_opener(verify_tls)

    try:
        with opener.open(request, timeout=30) as response:
            result = handle_error(response, comment)

    except urllib.error.HTTPError as error:
        handle_error(error, comment)

    except (urllib.error.URLError, OSError):
        raise RuntimeError(
            comment
            + ": request failed or its response was lost. "
            "Check the firewall before retrying."
        ) from None

    actual_members = read_group_members(
        fw_info,
        group_name,
        verify_tls,
    )

    actual = set(actual_members)

    if len(actual_members) != len(new_members) or actual != proposed:
        raise RuntimeError(
            "%s: verification failed for %s after PUT. "
            "Expected %s members, received %s. "
            "Missing: %s. Unexpected: %s. "
            "Inspect the group before retrying."
            % (
                fw_info["name"],
                group_name,
                len(new_members),
                len(actual_members),
                sorted(proposed - actual),
                sorted(actual - proposed),
            )
        )

    return result


# Read valid unique member names from one static address group.
# A missing member field is rejected; an explicit empty list is accepted.
# Output: A list of member names.
def read_group_members(fw_info, group_name, verify_tls):
    group = get_addrgrp_from_FG(
        fw_info,
        group_name,
        verify_tls,
    )

    if (
        group.get("type", "default") != "default"
        or group.get("exclude") == "enable"
    ):
        raise RuntimeError(
            "Use a static group without exclusions: " + group_name
        )

    if "member" not in group:
        raise RuntimeError(
            "Incomplete group response: missing member field in " + group_name
        )

    members = group["member"]

    if not isinstance(members, list) or any(
        not isinstance(member, dict)
        or not isinstance(member.get("name"), str)
        or not member["name"].strip()
        for member in members
    ):
        raise RuntimeError(
            "Invalid member list in group: " + group_name
        )

    names = [member["name"] for member in members]

    if len(names) != len(set(names)):
        raise RuntimeError(
            "Duplicate member names in group: " + group_name
        )

    return names


# Add one existing address object to a group using the checked update function.
# Output: "added" or "already_present".
def add_member_to_group(fw_info, group_name, member_name, verify_tls):
    members = read_group_members(
        fw_info,
        group_name,
        verify_tls,
    )

    if member_name in members:
        return "already_present"

    update_addrgrp_in_FG(
        fw_info,
        group_name,
        current_members=members,
        new_members=members + [member_name],
        member_name=member_name,
        action="add",
        verify_tls=verify_tls,
    )

    return "added"


def firewall_connection(ip, port, key, vdom=None):
    """Build connection settings from explicit inputs, without making requests."""
    name = "FortiGate"
    if not isinstance(ip, str):
        raise ValueError(name + ': enter a FortiGate IP address.')
    try:
        address = ipaddress.ip_address(ip.strip())
    except ValueError:
        raise ValueError(name + ': enter a FortiGate IP address, without a URL or port.') from None
    if isinstance(port, bool) or not isinstance(port, (str, int)):
        raise ValueError(name + ': port must be an integer from 1 to 65535.')
    if isinstance(port, str) and not port.strip().isascii():
        raise ValueError(name + ': invalid port.')
    if isinstance(port, str) and not port.strip().isdigit():
        raise ValueError(name + ': invalid port.')
    port = int(port)
    if not 1 <= port <= 65535:
        raise ValueError(name + ': port must be an integer from 1 to 65535.')
    if not isinstance(key, str) or not key.strip() or any(c.isspace() for c in key.strip()):
        raise ValueError(name + ': API key must be nonempty and contain no whitespace.')
    if vdom is not None:
        if not isinstance(vdom, str):
            raise ValueError(name + ': VDOM must be a string or None.')
        vdom = vdom.strip() or None
        if vdom and any(ord(c) < 32 or ord(c) == 127 for c in vdom):
            raise ValueError(name + ': invalid VDOM.')
    hostname = '[' + str(address) + ']' if address.version == 6 else str(address)
    return dict(name=name, url='https://%s:%s' % (hostname, port), token=key.strip(), vdom=vdom)


# Configuration and workflows
##############################################


def load_config(config_path):
    """Read local settings. Do not print or return API keys in action results."""
    try:
        with open(config_path, encoding='utf-8') as stream:
            config = json.load(stream)
    except (OSError, ValueError):
        raise ValueError('Cannot read config JSON. Copy config.example.json to config.json and fill it in.') from None
    return validate_config(config)


def validate_config(config):
    if not isinstance(config, dict):
        raise ValueError('Config must be a JSON object.')
    firewall = config.get('firewall')
    groups = config.get('groups')
    if not isinstance(firewall, dict) or not isinstance(groups, dict):
        raise ValueError('Config requires firewall and groups objects.')
    key = firewall.get('api_key')
    if key == 'REPLACE_WITH_YOUR_API_KEY':
        raise ValueError('Fill in the API key in your private config.json.')
    fw_info = firewall_connection(firewall.get('ip'), firewall.get('port'), key, firewall.get('vdom'))
    names = {}
    for name in ('full', 'limited_source', 'limited_destination'):
        value = groups.get(name)
        if not isinstance(value, str) or not value.strip():
            raise ValueError('Missing group name: ' + name)
        value = value.strip()
        if any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError('Invalid group name: ' + name)
        names[name] = value
    if len(set(names.values())) != 3:
        raise ValueError('Full, limited-source and limited-destination groups must be distinct.')
    verify_tls = config.get('verify_tls', False)
    if type(verify_tls) is not bool:
        raise ValueError('verify_tls must be a JSON boolean.')
    cidrs = config.get('allowed_source_networks')
    if not isinstance(cidrs, list) or any(not isinstance(cidr, str) for cidr in cidrs):
        raise ValueError('allowed_source_networks must be a list of IPv4 CIDRs; [] allows any IPv4 host.')
    try:
        networks = tuple(ipaddress.IPv4Network(cidr, strict=True) for cidr in cidrs)
    except ValueError:
        raise ValueError('Invalid allowed_source_networks IPv4 CIDR.') from None
    return dict(firewall=fw_info, groups=names, verify_tls=verify_tls, networks=networks)


def input_values(values):
    """Accept a comma-separated string or a list of individual strings."""
    if isinstance(values, str):
        values = [value.strip() for value in values.split(',')] if values.strip() else []
    if not isinstance(values, (list, tuple)) or any(not isinstance(value, str) for value in values):
        raise ValueError('Enter addresses as strings separated by commas.')
    return values


def parse_sources(values, networks):
    sources = []
    for value in input_values(values):
        try:
            address = ipaddress.IPv4Address(value.strip())
        except ValueError:
            raise ValueError('Source must be one IPv4 host without a mask: ' + value) from None
        if networks and not any(address in network for network in networks):
            raise ValueError('Source is outside allowed_source_networks: ' + str(address))
        if str(address) not in sources:
            sources.append(str(address))
    if not sources:
        raise ValueError('Enter at least one source IPv4 address.')
    return sources


def parse_destinations(values):
    destinations = {}
    for value in input_values(values):
        normalized, kind = normalize_address(value)
        destinations[normalized] = kind
    if not destinations:
        raise ValueError('Limited add requires at least one destination IPv4 address or FQDN.')
    return destinations


def source_ips_in_group(fw_info, members, verify_tls, networks):
    """Read actual object values; require direct single-host IPv4 source members."""
    addresses = get_addresses_from_FG(fw_info, verify_tls=verify_tls)
    by_name = {address['name']: address for address in addresses}
    ips = set()
    for name in members:
        address = by_name.get(name)
        if address is None:
            address = get_addresses_from_FG(fw_info, name, verify_tls)[0]
        subnet = parse_address_subnet(address)
        if subnet.prefixlen != 32:
            raise RuntimeError('Expected a /32 source address object: ' + name)
        ip = subnet.network_address
        if not networks or any(ip in network for network in networks):
            ips.add(ip)
    return [str(ip) for ip in sorted(ips)]


def execute(settings, action, access_mode, sources='', destinations=''):
    """Execute one validated batch on one firewall; each PUT changes one member.

    All inputs and required groups/objects are checked before any writes. Batches
    are not atomic and do not provide concurrency protection or automatic rollback.
    """
    if not isinstance(action, str) or action.strip().lower() not in ('get', 'add', 'delete'):
        raise ValueError('Action must be get, add or delete.')
    if not isinstance(access_mode, str) or access_mode.strip().lower() not in ('full', 'limited'):
        raise ValueError('Access mode must be full or limited.')
    action, access_mode = action.strip().lower(), access_mode.strip().lower()
    fw = settings['firewall']
    groups = settings['groups']
    tls = settings['verify_tls']
    networks = settings['networks']
    source_group = groups['full' if access_mode == 'full' else 'limited_source']
    source_values = parse_sources(sources, networks) if action != 'get' else []
    destination_values = parse_destinations(destinations) if action == 'add' and access_mode == 'limited' else {}

    # For every add, reject the entire batch if any source already has full access.
    if action == 'add':
        full_members = read_group_members(fw, groups['full'], tls)
        blocked = [value for value in source_values if value in full_members]
        if blocked:
            message = '%s already has full access through %s. No changes were made.' % (', '.join(blocked), groups['full'])
            print(message)
            raise RuntimeError(message)
    members = read_group_members(fw, source_group, tls)
    destination_members = None
    if access_mode == 'limited' and action != 'delete':
        destination_members = read_group_members(fw, groups['limited_destination'], tls)
    if action == 'get':
        ips = source_ips_in_group(fw, members, tls, networks)
        result = dict(action=action, access_mode=access_mode, group=source_group,
                      source_ips=ips, count=len(ips), members=members)
        print('Source IPs in %s:' % source_group)
        for ip in ips:
            print(ip)
        print('Total: %s' % len(ips))
        if destination_members is not None:
            result['destinations'] = destination_members
            print('Shared destinations in %s: %s' % (groups['limited_destination'], ', '.join(destination_members)))
        return result

    required = {value: 'ipmask' for value in source_values if action == 'add' or value in members}
    required.update(destination_values)
    existing = {}
    # Every required object is checked before creating any object or changing groups.
    for value, kind in required.items():
        objects = get_addresses_from_FG(fw, value, tls, allow_missing=action == 'add')
        if objects:
            validate_address_object(objects[0], value, kind)
        elif get_addrgrp_from_FG(fw, value, tls, allow_missing=True) is not None:
            raise RuntimeError('A group already uses the object name ' + value)
        existing[value] = bool(objects)

    completed = []
    results = dict(sources={}, destinations={})
    try:
        if action == 'add':
            for value, kind in required.items():
                if not existing[value]:
                    add_address_object_to_FG(fw, value, value, kind, verify_tls=tls)
                    completed.append('created address ' + value)
                    obj = get_addresses_from_FG(fw, value, tls)[0]
                    validate_address_object(obj, value, kind)
            # Destinations are intentionally shared by all limited source members.
            for value in destination_values:
                status = add_member_to_group(fw, groups['limited_destination'], value, tls)
                results['destinations'][value] = status
                completed.append('%s %s in %s' % (status, value, groups['limited_destination']))
            for value in source_values:
                status = add_member_to_group(fw, source_group, value, tls)
                results['sources'][value] = status
                completed.append('%s %s in %s' % (status, value, source_group))
        else:
            for value in source_values:
                current = read_group_members(fw, source_group, tls)
                if value not in current:
                    status = 'already_absent'
                else:
                    update_addrgrp_in_FG(fw, source_group, current,
                                        [name for name in current if name != value], value, 'delete', tls)
                    status = 'deleted'
                results['sources'][value] = status
                completed.append('%s %s in %s' % (status, value, source_group))
    except RuntimeError as error:
        raise RuntimeError(
            '%s Completed steps: %s. A failed request may already have applied. '
            'Inspect the firewall before retrying; there is no automatic rollback.'
            % (error, '; '.join(completed) or 'none confirmed')
        ) from None
    print('%s %s: %s' % (action, access_mode, results))
    return dict(action=action, access_mode=access_mode, group=source_group, results=results)


def run(config, action, access_mode, sources='', destinations=''):
    """Programmatic entry point taking the same JSON configuration as the CLI."""
    return execute(validate_config(config), action, access_mode, sources, destinations)


def main():
    """Admin settings are local; runtime prompts contain only operation inputs."""
    config_input = input('JSON config file path: ').strip()
    if not config_input:
        raise ValueError('Enter the path to your JSON config file.')
    config_path = Path(config_input).expanduser()
    settings = load_config(config_path)
    action = input('Action (get/add/delete): ').strip().lower()
    mode = input('Access (full/limited): ').strip().lower()
    if action not in ('get', 'add', 'delete') or mode not in ('full', 'limited'):
        raise ValueError('Choose get/add/delete and full/limited.')
    sources = input('Source IPv4 addresses (comma separated): ') if action != 'get' else ''
    destinations = input('Destination IPv4 addresses or FQDNs (comma separated): ') if action == 'add' and mode == 'limited' else ''
    if not settings['verify_tls']:
        print('TLS certificate verification is disabled in config.json.')
    return execute(settings, action, mode, sources, destinations)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, RuntimeError) as error:
        print('Error: ' + str(error), file=sys.stderr)
        sys.exit(1)
    except (KeyboardInterrupt, EOFError):
        print('\nCancelled.', file=sys.stderr)
        sys.exit(130)
