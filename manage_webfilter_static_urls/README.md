# manage_webfilter_static_urls

The **manage_webfilter_static_urls** directory contains one script for managing static URL filter entries on a Fortigate firewall. It supports adding, listing and deleting domains in the URL filter table linked to an existing webfilter profile.

### Prerequisites

Before using the script, make sure you have the following prerequisites in place:

1. Install Python 3.10 or later. No external Python packages are required.
2. Create a webfilter profile and link a static URL filter table to it.
3. Apply the webfilter profile to the relevant firewall policies if you want its rules to affect traffic.
4. Create a Fortigate user (REST API Admin) with read/write access to webfilter profiles in the selected VDOM.

The script manages entries in an existing table. It does not create profiles, tables or firewall policies.

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
- **profile_name:** Exact name of the existing webfilter profile. Replace the sample placeholder with your profile name.
- **verify_tls:** Set to `true` to verify the firewall certificate. The sample uses `true`. Omitting this field defaults to `false`, which disables certificate verification.

Keep the filled-in configuration private and exclude it from Git because it contains your API key. The sample file contains placeholder values.

## Usage

Execute the script from this directory:

```bash
python3 manage_webfilter_static_urls.py
```

The script will prompt you for the following inputs:

1. **JSON config file path:** Path to your configuration file, such as `config.json`.
2. **Action:** Choose `get`, `add` or `delete`.
3. **Domains or wildcard domains:** Required for add/delete. Separate multiple domains with commas.

Example of adding domains:

```text
JSON config file path: config.json
Action (get/add/delete): add
Domains or wildcard domains (comma separated): example.com,*.example.org
```

For listing entries, select `get`; domain input is not requested. For deleting entries, select `delete` and enter the exact domains or wildcard patterns to remove.

## Behavior

- **Get:** Lists URL, Type, Action and Status in a table with a total count. Includes disabled entries and regex entries in their returned order.
- **Add:** Creates missing domain entries with action `allow` and status `enable`. Plain domains use type `simple`; patterns containing `*` use type `wildcard`.
- **Existing entries:** Matching URL/type entries are left unchanged, including blocked or disabled entries. Adding an existing domain does not change its action or enable it.
- **Delete:** Removes all exact URL/type matches. Missing entries are reported as already absent. Regex entries are retained.
- Inputs are normalized to lowercase, trailing dots are removed and duplicate inputs are processed once. Internationalized domains are converted to IDNA ASCII form.
- Add/delete accept domains and wildcard domains only. IP addresses, URL schemes, paths, ports and single-label names are rejected.
- Matching compares normalized domain text and entry type; wildcard coverage is not evaluated. `example.com` and `*.example.com` are separate entries.
- The script follows the profile's `web.urlfilter-table` reference. If no table is linked, `get` returns an empty list and add/delete fail without writing.
- Changes affect every profile sharing the linked table.
- Updates target individual entry IDs. After writes, the script checks the linked table ID, entry IDs and each entry's URL, type, action and status. This check does not verify entry order or other entry options.

Updates are not atomic and have no automatic rollback or concurrency locking. On a partial failure, inspect the firewall with `get` before retrying.

The script has been tested against a live Fortigate firewall.
