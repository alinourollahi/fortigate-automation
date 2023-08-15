# add_netbox_objects_to_fortigate

This directory contains a script for adding Netbox VMs to Fortigate.  
This script assumes that only Netbox objects in the `192.168.0.0/16` range need to be added to Fortigate. If you want to add all of the VMs in your inventory to Fortigate, just change `192.168.0.0/255.255.0.0` to `0.0.0.0/0.0.0.0`.

### Prerequisites
1. Create a Fortigate user (REST API Admin) with write access to address objects
2. Create a Netbox token with read access to the virtualization section.
