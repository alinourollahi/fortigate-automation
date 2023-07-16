# fortigate-automation

This repository focuses on automating repetitive tasks on Fortigate firewalls. Each directory in this repository contains scripts for different goals. All scripts have been tested on FortiOS 7+.

---

## Directory: manage_malicious_IPs

The **manage_malicious_IPs** directory contains scripts to manage malicious IPs on your Fortigate firewall.

### Prerequisites

Before running the scripts in this directory, make sure to complete the following steps:

1. Create an object group named **Malicious_IPs**.
2. Create a deny policy in your Fortigate firewall with the following settings: (this is recommended setting but you can adjust it to your situation)
   - Source interface: any
   - Destination interface: any
   - Source: Malicious_IPs
   - Destination: all
   - Action: deny

### Scripts

1. **add_malicious_ips.py**: Adds malicious IPs to your Fortigate firewall.
2. **delete_malicious_ips.py**: Deletes malicious IPs from your Fortigate firewall.
3. **get_Malicious_IPs.py**: Retrieves malicious IPs from your Fortigate firewall.

---

If you have any questions about this repo, you can reach me at alinourollahi777@gmail.com
