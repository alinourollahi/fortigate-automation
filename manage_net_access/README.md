# manage_net_access

The **manage_net_access** directory contains one script for managing full or limited internet access on a Fortigate firewall. It supports adding, listing and deleting source IP memberships using existing address groups.

### Prerequisites

Before using the script, make sure you have the following prerequisites in place:

1. Install Python 3.10 or later. No external Python packages are required.
2. Create three separate static address groups for full-access sources, limited-access sources and limited-access destinations.
3. Configure firewall policies to allow full access for the full-access source group and limited access from the limited-source group to the limited-destination group.
4. Create a Fortigate user (REST API Admin) with read/write access to address objects and address groups in the selected VDOM.

The script manages objects and group memberships. It does not create firewall policies or address groups.

## Configuration

Copy the sample configuration from this directory:

```bash
cp config.example.json config.json
```

Edit `config.json` with your own settings:

- **firewall.ip:** Management IP address of your Fortigate device.
- **firewall.port:** HTTPS API port.
- **firewall.api_key:** API key for authentication.
- **firewall.vdom:** VDOM name, or `null` to use the API default.
- **groups.full:** Full-access source group name.
- **groups.limited_source:** Limited-access source group name.
- **groups.limited_destination:** Shared limited-access destination group name.
- **allowed_source_networks:** Allowed source networks. The sample uses `192.168.0.0/24`, `192.168.1.0/24` and `192.168.2.0/24`. Set this to `[]` to allow any source IPv4 address.
- **verify_tls:** Set to `true` to verify the firewall certificate. The sample uses `false`, which disables certificate verification.

Keep the filled-in configuration private and exclude it from Git because it contains your API key. The sample file contains only a placeholder key.

## Usage

Execute the script from this directory:

```bash
python3 manage_net_access.py
```

The script will prompt you for the following inputs:

1. **JSON config file path:** Path to your configuration file, such as `config.json`.
2. **Action:** Choose `get`, `add` or `delete`.
3. **Access:** Choose `full` or `limited`.
4. **Source IPv4 addresses:** Required for add/delete. Separate multiple addresses with commas.
5. **Destination IPv4 addresses or FQDNs:** Required only for limited add. Separate multiple destinations with commas.

Example of adding limited access:

```text
JSON config file path: config.json
Action (get/add/delete): add
Access (full/limited): limited
Source IPv4 addresses (comma separated): 192.168.0.10,192.168.1.20
Destination IPv4 addresses or FQDNs (comma separated): 203.0.113.9,example.com
```

For full access, select `add` and `full`; destinations are not requested. For listing access, select `get` and the access mode; source and destination inputs are not requested.

## Behavior

- **Full add:** Adds sources to the full-access group.
- **Limited add:** Adds sources to the limited-source group and destinations to the shared destination group. All limited sources share all destinations in that group.
- **Existing full access:** If any requested source is already in the full-access group, the entire add request is rejected before any writes.
- **Get:** Lists actual source IPv4 addresses and their count in the selected group, filtered by the configured source networks. Limited get also lists shared destination member names.
- **Delete:** Removes source membership only from the selected group. Address objects, the other source group and shared destinations are retained.
- Missing address objects are created with their normalized IPv4 address or FQDN as the exact name. Matching objects are reused; conflicting names or values cause an error.
- Source and destination IPv4 inputs must be individual hosts, without subnet masks. Sources must match the configured allowed ranges. Source groups must contain direct IPv4 `/32` objects; nested groups and FQDN sources are unsupported.
- Every group update preserves unrelated members and verifies the complete membership after writing.

Updates are not atomic and have no automatic rollback or concurrency locking. On a partial failure, inspect the firewall before retrying.

The script has passed offline mock tests and has been successfully tested against a live Fortigate firewall by the repository owner.
