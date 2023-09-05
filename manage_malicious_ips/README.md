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

For adding objects to the "Malicious_IPs" group, use the following command:  
```bash
python3 add_malicious_ips.py
```
The script will prompt you for the following inputs:
1. fortigate_url: URL of your Fortigate device.
2. fortigate_vdom: Virtual Domain (VDOM) on Fortigate.
3. fortigate_token: API token for Fortigate authentication.
4. input_count: number of IPs or FQDNs you want to add.
5. Input: The IPs or FQDNs you want to add to the "malicious_IPs" object group.

For deleting an object from the "Malicious_IPs" group, use the following command:  
```bash
python3 del_malicious_ips.py
```
The script will prompt you for the following inputs:
1. fortigate_url: URL of your Fortigate device.
2. fortigate_vdom: Virtual Domain (VDOM) on Fortigate.
3. fortigate_token: API token for Fortigate authentication.
4. Input: The IP or FQDN you want to delete from the "malicious_IPs" object group.


For getting objects of the "Malicious_IPs" group, use the following command:   
```bash
python3 get_malicious_ips.py
```
The script will prompt you for the following inputs:
1. fortigate_url: URL of your Fortigate device.
2. fortigate_vdom: Virtual Domain (VDOM) on Fortigate.
3. fortigate_token: API token for Fortigate authentication.
