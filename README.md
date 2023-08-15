# fortigate-automation

This repository contains scripts for automating repetitive tasks on Fortigate firewalls. Each directory in this repository contains scripts for different goals. All scripts have been tested on FortiOS 7+.

---

## Directory: manage_malicious_IPs

The **manage_malicious_IPs** directory contains scripts to manage malicious IPs on your Fortigate firewall.

### Prerequisites

Before running the scripts in this directory, make sure to complete the following steps:

1. Create an object group named **Malicious_IPs**.
2. Create a deny policy in your Fortigate firewall with the following settings (recommended settings, adjust as needed):
   - Source interface: any
   - Destination interface: any
   - Source: Malicious_IPs
   - Destination: all
   - Action: deny
3. Create a Fortigate user (REST API Admin) with write access to address objects.

### Scripts

1. **add_malicious_ips.py**: Adds malicious IPs to your Fortigate firewall.
2. **delete_malicious_ips.py**: Deletes malicious IPs from your Fortigate firewall.
3. **get_Malicious_ips.py**: Retrieves malicious IPs from your Fortigate firewall.

---

## Directory: add_netbox_objects_to_fortigate

This directory contains a script for adding Netbox VMs to Fortigate.  
This script assumes that only Netbox objects in the `192.168.0.0/16` range need to be added to Fortigate. If you want to add all of the VMs in your inventory to Fortigate, just change `192.168.0.0/255.255.0.0` to `0.0.0.0/0.0.0.0`.

### Prerequisites
1. Create a Fortigate user (REST API Admin) with write access to address objects
2. Create a Netbox token with read access to the virtualization section.

---

## Directory: manage_policy_routes

This directory contains a script for managing a specific policy_route in Fortigate firewalls.
Let's say that you have a specific policy_route in your Fortigate that grants internet access to VMs. So, if you add a new IP in the source section of this policy_route, the VM with that IP has internet access. In scenarios like this, you can use this script.

### Prerequisites
1. Create a Fortigate user (REST API Admin) with write access to the network/router.
2. Create the policy route that you want to manage.


---


## Directory: check_internet_status

This directory contains a script for retrieving a list of all objects with permanent and unlimited internet access.

### Prerequisites
1. Create a Fortigate user (REST API Admin) with read access to the firewall/policy and firewall/address.

---
## Directory: create_svi

This directory contains a script for creating a new interface vlan on Fortigate firewalls.  
This script creates the interface VLAN as well as a corresponding zone.

### Prerequisites
1. Create a Fortigate user (REST API Admin) with write access to the system/configuration. Ensure a "global" scope is selected for this API user.

---
If you have any questions about this repo, feel free to reach me at alinourollahi777@gmail.com.
