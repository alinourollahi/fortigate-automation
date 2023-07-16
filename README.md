# fortigate-automation

This repo focuses on automating repetitive tasks on Fortigate firewalls.  
Each directory on this repository contains scripts for different goals.
I tested all of the scripts on FortiOS 7+.

#

### manage_block_IPs
Prerequisites: You need to do two things before running the scripts in this folder.  
1- You must create an object_group with the name "Malicious_IPs".  
2- You must create a deny policy in your Fortigate firewall. (policy should be something like this: source_interface: any, destination_interface: any, source: Malicious_IPs, destination: all, action: deny)

There are 3 scripts in this folder for managing Malicious IPs on your Fortigate firewall. "add_malicious_ips.py" for adding malicious IPs, "delete_malicious_ips" for deleting malicious IPs and "get_Malicious_IPs" for getting malicious IPs from your Fortigate firewall.

