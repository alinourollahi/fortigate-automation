"""Standalone FortiGate static URL filter manager; standard library only.

Run with: python3 manage_webfilter_static_urls.py
Prompts: JSON config file path, get/add/delete, domains for add/delete.
Uses a single firewall and follows profile_name's web.urlfilter-table link.
Example configuration:
{
  "firewall": {
    "ip": "192.0.2.1", "port": 443,
    "api_key": "REPLACE_WITH_YOUR_API_KEY", "vdom": "root"
  },
  "profile_name": "REPLACE_WITH_YOUR_WEBFILTER_PROFILE_NAME",
  "verify_tls": true
}
Omitting verify_tls defaults to false.
The config may include the existing groups and allowed_source_networks fields;
this script ignores those fields. Keep the API key in a private config file.
Add/delete accept domains only, including wildcard domains; regex is read-only.
A linked table shared with other profiles affects those profiles too.
"""

import ipaddress
import json
import sys
from pathlib import Path
import re
import ssl
import urllib.error
import urllib.request
from urllib.parse import quote, urlencode


COLUMNS = ("URL", "Type", "Action", "Status")


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


# Validate one domain or wildcard pattern without performing a DNS lookup.
# IPs, URL schemes, paths, ports and single-label names are rejected.
# Output: True for valid domain syntax, otherwise False.

def validate_url(url):
    if not isinstance(url, str):
        return False

    # Substitute stars only for hostname validation; preserve the stored pattern.
    hostname = url.replace("*", "a").strip()

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


# Validate and normalize one domain or wildcard pattern.
# Output: A tuple containing the normalized domain and FortiGate entry type.

def parse_url(url):
    if not validate_url(url):
        raise ValueError(
            "Enter one domain or wildcard domain, "
            "without a URL scheme, path or port."
        )

    value = url.strip().rstrip(".").encode("idna").decode("ascii").lower()
    url_type = "wildcard" if "*" in value else "simple"

    return value, url_type


# Validate a comma-separated list before any API requests.
# Empty entries are rejected and duplicate inputs are removed.
# Output: Unique normalized (domain, type) tuples in input order.

def parse_urls(urls):
    if isinstance(urls, (list, tuple)) and all(isinstance(item, str) and "," not in item for item in urls):
        urls = ",".join(urls)
    if not isinstance(urls, str) or not urls.strip():
        raise ValueError(
            "Add and delete require one domain or comma-separated domains."
        )

    parsed_urls = []
    seen = set()
    for item in urls.split(","):
        key = parse_url(item)
        if key not in seen:
            seen.add(key)
            parsed_urls.append(key)
    return parsed_urls


# Require unique positive FortiGate IDs so updates target specific entries.
# Output: An ID-to-entry dictionary; missing, invalid or duplicate IDs raise an error.

def validate_url_entry_ids(entries):
    result = {}
    for entry in entries:
        entry_id = entry.get("id")
        if isinstance(entry_id, str) and entry_id.isascii() and entry_id.isdecimal():
            entry_id = int(entry_id)
        if type(entry_id) is not int or not 1 <= entry_id <= 4294967295 or entry_id in result:
            raise RuntimeError("Missing, invalid or duplicate URL entry IDs; no safe update is possible.")
        result[entry_id] = entry
    return result


# FortiGate API functions
##############################################


# Add one static URL filter entry to FortiGate using POST.
# Output: The successful API response; unsuccessful requests raise an error.

def add_urlfilter_entry_to_FG(fw_info, table_id, entry, verify_tls=False):
    fg_url = build_webfilter_url(fw_info, "urlfilter", table_id, "/entries")
    headers = {
        "Authorization": "Bearer " + fw_info["token"],
        "Content-Type": "application/json",
    }
    payload = entry
    request = urllib.request.Request(
        fg_url,
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    comment = fw_info["name"] + ": adding URL " + entry["url"]
    opener = build_https_opener(verify_tls)

    try:
        with opener.open(request, timeout=30) as response:
            return handle_error(response, comment)

    except urllib.error.HTTPError as error:
        handle_error(error, comment)

    except (urllib.error.URLError, OSError):
        raise RuntimeError(
            comment + ": request failed or its response was lost. "
            "Check the firewall before retrying."
        ) from None


# Get one webfilter profile from FortiGate using its exact name.
# Output: The profile dictionary; missing or incomplete responses raise an error.

def get_webfilter_profile_from_FG(fw_info, profile_name, verify_tls=False):
    fg_url = build_webfilter_url(fw_info, "profile", profile_name)
    headers = {"Authorization": "Bearer " + fw_info["token"]}
    request = urllib.request.Request(fg_url, headers=headers, method="GET")
    comment = fw_info["name"] + ": reading webfilter/profile/" + str(profile_name)
    opener = build_https_opener(verify_tls)

    try:
        with opener.open(request, timeout=30) as response:
            result = handle_error(response, comment)

    except urllib.error.HTTPError as error:
        handle_error(error, comment)

    except (urllib.error.URLError, OSError):
        raise RuntimeError(comment + ": connection failed.") from None

    if result.get("limit_reached"):
        raise RuntimeError(comment + ": FortiGate returned an incomplete object.")

    objects = result.get("results")
    if isinstance(objects, dict):
        objects = [objects]
    if (
        not isinstance(objects, list)
        or len(objects) != 1
        or not isinstance(objects[0], dict)
        or str(objects[0].get("name")) != str(profile_name)
    ):
        raise RuntimeError(comment + ": the requested object was not returned.")

    return objects[0]


# Get one static URL filter table from FortiGate using its exact ID.
# Output: The table dictionary; missing or incomplete responses raise an error.

def get_urlfilter_from_FG(fw_info, table_id, verify_tls=False):
    fg_url = build_webfilter_url(fw_info, "urlfilter", table_id)
    headers = {"Authorization": "Bearer " + fw_info["token"]}
    request = urllib.request.Request(fg_url, headers=headers, method="GET")
    comment = fw_info["name"] + ": reading webfilter/urlfilter/" + str(table_id)
    opener = build_https_opener(verify_tls)

    try:
        with opener.open(request, timeout=30) as response:
            result = handle_error(response, comment)

    except urllib.error.HTTPError as error:
        handle_error(error, comment)

    except (urllib.error.URLError, OSError):
        raise RuntimeError(comment + ": connection failed.") from None

    if result.get("limit_reached"):
        raise RuntimeError(comment + ": FortiGate returned an incomplete object.")

    objects = result.get("results")
    if isinstance(objects, dict):
        objects = [objects]
    if (
        not isinstance(objects, list)
        or len(objects) != 1
        or not isinstance(objects[0], dict)
        or str(objects[0].get("id")) != str(table_id)
    ):
        raise RuntimeError(comment + ": the requested object was not returned.")

    return objects[0]


# Delete one static URL filter entry from FortiGate using its ID.
# Other entries and table settings are retained.
# Output: The successful API response; unsuccessful requests raise an error.

def delete_urlfilter_entry_from_FG(fw_info, table_id, entry_id, verify_tls=False):
    fg_url = build_webfilter_url(fw_info, "urlfilter", table_id, "/entries/" + str(entry_id))
    headers = {"Authorization": "Bearer " + fw_info["token"]}
    request = urllib.request.Request(fg_url, headers=headers, method="DELETE")
    comment = fw_info["name"] + ": deleting URL entry " + str(entry_id)
    opener = build_https_opener(verify_tls)

    try:
        with opener.open(request, timeout=30) as response:
            return handle_error(response, comment)

    except urllib.error.HTTPError as error:
        handle_error(error, comment)

    except (urllib.error.URLError, OSError):
        raise RuntimeError(
            comment + ": request failed or its response was lost. "
            "Check the firewall before retrying."
        ) from None


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

def build_https_opener(verify_tls=True):
    context = ssl.create_default_context()
    if not verify_tls:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    return urllib.request.build_opener(
        NoRedirect(),
        urllib.request.HTTPSHandler(context=context),
    )


# Local configuration and URL filter helpers
##############################################


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



# Build a webfilter API URL with an optional entry path and VDOM.
# Output: The request URL. This function does not send requests.

def build_webfilter_url(fw_info, table, key, suffix=""):
    fg_url = (
        fw_info["url"]
        + "/api/v2/cmdb/webfilter/"
        + table
        + "/"
        + quote(str(key), safe="")
        + suffix
    )
    if fw_info["vdom"]:
        fg_url += "?" + urlencode({"vdom": fw_info["vdom"]})
    return fg_url


# Read the profile and follow its static URL filter table reference.
# Retain entry order, disabled entries and all URL pattern types.
# Output: The table ID and entries, or (0, []) when no table is linked.

def read_urlfilter_entries(fw_info, verify_tls=False):
    profile_name = fw_info["profile_name"]
    profile = get_webfilter_profile_from_FG(fw_info, profile_name, verify_tls)
    if profile.get("name") != profile_name:
        raise RuntimeError("FortiGate returned a different webfilter profile.")

    web = profile.get("web")
    if not isinstance(web, dict) or "urlfilter-table" not in web:
        raise RuntimeError("Incomplete profile response: missing web.urlfilter-table.")

    table_id = web["urlfilter-table"]
    # FortiOS uses zero when no static URL filter table is linked.
    if isinstance(table_id, str) and table_id.isascii() and table_id.isdecimal():
        table_id = int(table_id)
    if type(table_id) is not int or table_id < 0:
        raise RuntimeError("Invalid static URL filter table ID in profile.")
    if table_id == 0:
        return 0, []

    table = get_urlfilter_from_FG(fw_info, table_id, verify_tls)
    if str(table.get("id")) != str(table_id):
        raise RuntimeError("FortiGate returned a different static URL filter table.")

    entries = table.get("entries")
    if not isinstance(entries, list):
        raise RuntimeError("Incomplete URL filter response: missing or invalid entries.")

    for entry in entries:
        fields = ("url", "type", "action", "status")
        if not isinstance(entry, dict) or any(
            not isinstance(entry.get(field), str) or not entry[field]
            for field in fields
        ):
            raise RuntimeError("Invalid URL filter entry: expected url, type, action and status.")
    return table_id, entries


# Normalize the stored URL and pair it with its type for exact matching.
# Output: A (domain, type) tuple. Wildcard coverage is not evaluated.

def get_url_entry_key(entry):
    return entry["url"].lower().rstrip("."), entry["type"]


# Convert static URL entries into rows for the output table.
# Output: A list of dictionaries with URL, Type, Action and Status columns.

def format_urlfilter_entries(entries):
    return [
        dict(zip(COLUMNS, (entry[field] for field in ("url", "type", "action", "status"))))
        for entry in entries
    ]


# Print the URL rows as an aligned text table with a total count.
# Output: None. The supplied rows are not modified.

def print_url_table(rows):
    # Escape control characters in display only; returned rows retain raw values.
    values = [
        [
            "".join(char if char.isprintable() else repr(char)[1:-1] for char in row[column])
            for column in COLUMNS
        ]
        for row in rows
    ]
    widths = [
        max([len(column)] + [len(row[index]) for row in values])
        for index, column in enumerate(COLUMNS)
    ]
    border = "+-" + "-+-".join("-" * width for width in widths) + "-+"

    # Print one row using the calculated column widths.
    # Output: None.

    def print_row(row):
        print("| " + " | ".join(value.ljust(width) for value, width in zip(row, widths)) + " |")

    print(border)
    print_row(COLUMNS)
    print(border)
    for row in values:
        print_row(row)
    print(border)
    print("Total: %s" % len(rows))


# Webfilter workflows
##############################################


# Read the configured static URL entries and format them for display.
# Output: A list of URL, Type, Action and Status rows.

def read_webfilter_urls(fw_info, verify_tls=False):
    _, entries = read_urlfilter_entries(fw_info, verify_tls)
    return format_urlfilter_entries(entries)


# Add missing URLs or delete existing exact URL/type matches.
# Preserve unrelated entries and verify the resulting table after changes.
# Output: The resulting table rows. Partial failures report completed steps.

def update_webfilter_urls(fw_info, action, parsed_urls, verify_tls=False):
    if action not in ("add", "delete"):
        raise ValueError("Change action must be add or delete.")
    table_id, entries = read_urlfilter_entries(fw_info, verify_tls)
    if table_id == 0:
        raise RuntimeError("The profile has no linked static URL filter table. Configure one first.")

    expected_entries = validate_url_entry_ids(entries).copy()
    next_entry_id = max(expected_entries, default=0) + 1
    pending_changes = []
    messages = []
    # Compare the entire batch with the current table before sending writes.
    for domain, url_type in parsed_urls:
        matches = [entry for entry in entries if get_url_entry_key(entry) == (domain, url_type)]

        if action == "add":
            if matches:
                messages.append(domain + ": already present")
                continue
            if next_entry_id > 4294967295:
                raise RuntimeError("No available URL entry ID above the existing entries.")
            entry = {"id": next_entry_id, "url": domain, "type": url_type, "action": "allow", "status": "enable"}
            pending_changes.append(("POST", next_entry_id, entry))
            expected_entries[next_entry_id] = entry
            next_entry_id += 1
        elif matches:
            for entry in matches:
                entry_id = int(entry["id"])
                pending_changes.append(("DELETE", entry_id, entry))
                del expected_entries[entry_id]
        else:
            messages.append(domain + ": already absent")

    completed_steps = []
    try:
        for method, entry_id, entry in pending_changes:
            comment = "%s URL %s" % (action, entry["url"])
            if method == "POST":
                add_urlfilter_entry_to_FG(fw_info, table_id, entry, verify_tls)
            else:
                delete_urlfilter_entry_from_FG(fw_info, table_id, entry_id, verify_tls)
            completed_steps.append(comment)

        if pending_changes:
            actual_table_id, actual_entries = read_urlfilter_entries(fw_info, verify_tls)
            actual_entries_by_id = validate_url_entry_ids(actual_entries)
            fields = ("url", "type", "action", "status")
            if (
                actual_table_id != table_id
                or actual_entries_by_id.keys() != expected_entries.keys()
                or any(
                    any(actual_entries_by_id[key][field] != expected_entries[key][field] for field in fields)
                    for key in expected_entries
                )
            ):
                raise RuntimeError("Verification failed: the URL filter table differs from the expected result.")
            entries = actual_entries
    except RuntimeError as error:
        raise RuntimeError(
            "%s Completed requests: %s. A failed request may already have applied. "
            "Inspect the table with get before retrying; no automatic rollback is performed."
            % (error, "; ".join(completed_steps) or "none confirmed")
        ) from None

    for message in messages + completed_steps:
        print(message)
    return format_urlfilter_entries(entries)


def validate_config(config):
    """Validate local settings without contacting the firewall."""
    if not isinstance(config, dict):
        raise ValueError("Config must be a JSON object.")
    firewall = config.get("firewall")
    if not isinstance(firewall, dict):
        raise ValueError("Config requires a firewall object.")
    key = firewall.get("api_key")
    if key == "REPLACE_WITH_YOUR_API_KEY":
        raise ValueError("Fill in the API key in your private config JSON.")
    fw = firewall_connection(
        firewall.get("ip"), firewall.get("port"), key, firewall.get("vdom")
    )
    profile = config.get("profile_name", "REPLACE_WITH_YOUR_WEBFILTER_PROFILE_NAME")
    if not isinstance(profile, str) or not profile.strip():
        raise ValueError("profile_name must be a nonempty string.")
    profile = profile.strip()
    if any(ord(char) < 32 or ord(char) == 127 for char in profile):
        raise ValueError("Invalid profile_name.")
    fw["profile_name"] = profile
    verify_tls = config.get("verify_tls", False)
    if type(verify_tls) is not bool:
        raise ValueError("verify_tls must be a JSON boolean.")
    return dict(firewall=fw, verify_tls=verify_tls)


def load_config(config_path):
    """Read local configuration without printing its contents."""
    try:
        with open(config_path, encoding="utf-8") as stream:
            config = json.load(stream)
    except (OSError, ValueError):
        raise ValueError("Cannot read config JSON. Check the file path and JSON syntax.") from None
    return validate_config(config)


def execute(settings, action, urls=""):
    """Execute one batch on the configured firewall and webfilter profile.

    Batches are individual requests, without concurrency protection or rollback.
    Existing entries keep their action/status. New entries use allow/enable.
    """
    if not isinstance(action, str) or action.strip().lower() not in ("get", "add", "delete"):
        raise ValueError("Action must be get, add or delete.")
    action = action.strip().lower()
    parsed_urls = parse_urls(urls) if action != "get" else []
    fw = settings["firewall"]
    tls = settings["verify_tls"]
    if action == "get":
        rows = read_webfilter_urls(fw, tls)
    else:
        rows = update_webfilter_urls(fw, action, parsed_urls, tls)
    print("Webfilter profile: " + fw["profile_name"])
    print_url_table(rows)
    return rows


def run(config, action="get", urls=""):
    """Programmatic entry point using the same JSON structure as the CLI."""
    return execute(validate_config(config), action, urls)


def main():
    """Keep connection settings in JSON and prompt for operation inputs."""
    config_input = input("JSON config file path: ").strip()
    if not config_input:
        raise ValueError("Enter the path to your JSON config file.")
    settings = load_config(Path(config_input).expanduser())
    action = input("Action (get/add/delete): ").strip().lower()
    if action not in ("get", "add", "delete"):
        raise ValueError("Choose get, add or delete.")
    urls = input("Domains or wildcard domains (comma separated): ") if action != "get" else ""
    if not settings["verify_tls"]:
        print("TLS certificate verification is disabled in the JSON config.")
    return execute(settings, action, urls)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, RuntimeError) as error:
        print("Error: " + str(error), file=sys.stderr)
        sys.exit(1)
    except (KeyboardInterrupt, EOFError):
        print("\nCancelled.", file=sys.stderr)
        sys.exit(130)
