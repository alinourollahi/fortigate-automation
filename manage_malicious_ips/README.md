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


## Usage

Execute one of the scripts with the following command:   

```bash
python3 add_malicious_ips.py
```
or
```bash
python3 delete_malicious_ips.py
```
or 
```bash
python3 get_malicious_ips.py
```
The script will prompt you for the following inputs:
1. fortigate_url: URL of your Fortigate device.
2. fortigate_vdom: Virtual Domain (VDOM) on Fortigate.
3. fortigate_token: API token for Fortigate authentication.
4. ip: The IP that you want to add or delete from the list (Only for add or delete script)
