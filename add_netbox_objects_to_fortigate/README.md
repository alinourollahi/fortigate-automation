# Add Netbox Objects to Fortigate

This directory contains a script for adding Netbox VMs to Fortigate.  
This script assumes that only Netbox objects in the `192.168.0.0/16` range need to be added to Fortigate. If you want to add all of the VMs in your inventory to Fortigate, just change `192.168.0.0/255.255.0.0` to `0.0.0.0/0.0.0.0`.

## Prerequisites
Before using the script, make sure you have the following prerequisites in place:  
1. Create a Fortigate user (REST API Admin) with write access to address objects
2. Create a Netbox token with read access to the virtualization section.

## Usage

Execute the script with the following command:   

```bash
python3 add_netbox_objects_to_fortigate.py
```
The script will prompt you for the following inputs:
1. fortigate_url: URL of your Fortigate device.
2. fortigate_vdom: Virtual Domain (VDOM) on Fortigate.
3. fortigate_token: API token for Fortigate authentication.
4. netbox_token: Netbox API token for accessing VM information.
5. netbox_url: URL of your Netbox instance.

