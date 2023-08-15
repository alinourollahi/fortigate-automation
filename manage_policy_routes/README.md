# manage_policy_routes

This directory contains a script for managing a specific policy_route in Fortigate firewalls.
Let's say that you have a specific policy_route in your Fortigate that grants internet access to VMs. So, if you add a new IP in the source section of this policy_route, the VM with that IP has internet access. In scenarios like this, you can use this script.

### Prerequisites
1. Create a Fortigate user (REST API Admin) with write access to the network/router.
2. Create the policy route that you want to manage.


## Usage

Execute the script with the following command:   

```bash
python3 manage_policy_routes.py
```
The script will prompt you for the following inputs:
1. fortigate_url: URL of your Fortigate device.
2. fortigate_vdom: Virtual Domain (VDOM) on Fortigate.
3. fortigate_token: API token for Fortigate authentication.
4. policy_id: ID of the PBR.
5. action: Choose an action:
    1. "add": Add a new IP to the source list of the PBR.
    2. "get": Retrieve information about the PBR.
    3. "del": Remove an IP from the source list of the PBR.
7. ip: If you selected the "add" or "del" action, provide the IP address to add or remove from the PBR source list.
