# manage_malicious_IPs

The **manage_malicious_IPs** directory contains scripts to manage malicious IPs on your Fortigate firewall.

### Prerequisites

Before using the script, make sure you have the following prerequisites in place:
1. Create an object group named **Malicious_IPs**.
2. Create a deny policy in your Fortigate firewall with the following settings (recommended settings, adjust as needed):
   - Source interface: any
   - Destination interface: any
   - Source: Malicious_IPs
   - Destination: all
   - Action: deny
3. Create a Fortigate user (REST API Admin) with write access to address objects.
