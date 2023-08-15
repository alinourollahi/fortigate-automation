# Create SVI on Fortigate

This directory contains a script for creating a new interface vlan as well as a corresponding zone on Fortigate firewalls.  

### Prerequisites
1. Create a Fortigate user (REST API Admin) with write access to the system/configuration. Ensure a "global" scope is selected for this API user.


```bash
python3 create_svi_on_fortigate.py
```
The script will prompt you for the following inputs:
1. fortigate_url: URL of your Fortigate device.
2. fortigate_vdom: Virtual Domain (VDOM) on Fortigate.
3. fortigate_token: API token for Fortigate authentication.
4. interface_name: The interface that SVI will be created on.
5. interface_alias: An alias for the new SVI
6. interface_vid: VLAN ID of the new SVI 
7. interface_ip: IP address with mask of the new SVI
