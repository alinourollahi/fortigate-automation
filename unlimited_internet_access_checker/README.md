# Unlimited Internet Access Checker

This directory contains a script for retrieving a list of all objects with permanent and unlimited internet access. 

## Prerequisites
Before using the script, make sure you have the following prerequisites in place:
1. Create a Fortigate user (REST API Admin) with read access to the firewall/policy and firewall/address.


## Usage

Execute the script with the following command:   

```bash
python3 unlimited_internet_access_checker.py
```
The script will prompt you for the following inputs:
1. fortigate_url: URL of your Fortigate device.
2. fortigate_vdom: Virtual Domain (VDOM) on Fortigate.
3. fortigate_token: API token for Fortigate authentication.
