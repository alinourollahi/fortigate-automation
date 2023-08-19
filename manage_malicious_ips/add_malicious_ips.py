#!/usr/bin/python3 

from xmlrpc.client import boolean
import json
import requests
import urllib3
import ipaddress 
import sys
import re
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# Validation Function
##############################################
def is_ip_address_valid(address):
    try:
        ip = ipaddress.ip_address(address)
        return True
    except ValueError:
        is_fqdn_valid(address)

def is_fqdn_valid(fqdn):
    # Define a regular expression pattern for FQDN validation
    fqdn_pattern = r"^(?=.{1,255}$)([a-zA-Z0-9_][a-zA-Z0-9_-]*\.)*[a-zA-Z0-9_][a-zA-Z0-9_-]*\.[a-zA-Z]{2,}$"

    # Use the re.match function to check if the input matches the pattern
    if re.match(fqdn_pattern, fqdn):
        return False
    else:
        print("{} is not a valid IP or FQDN!".format(fqdn))
        sys.exit(-1)

# End of validation function
##############################################


# Error_Handling function
##############################################
def handle_error(response , comment):
    code = response.status_code 
    if code == 401:
        print( 'Check your Token!')
        print(comment)
        sys.exit(-1)
    if code < 200 or code >= 300:
        print('Try again later (status code:' , code , ')')
        print(comment)
        if 'cli_error' in response:
            print(response['cli_error'])
        sys.exit(-1)
# End of Error_Handling function
##############################################


# Updating malicious_IP object_group
# Note that you must create an object_group on your firewall with this name before running this script
# Output: this function returns nothing
def update_malicious_IP_object_group_in_FG(fw_info, names):
    fg_url = "https://%s/api/v2/cmdb/firewall/addrgrp/Malicious_IPs?with_meta=1&datasource=1&skip=1&vdom=%s"  %(fw_info['url'] ,fw_info['vdom'])

    payload={}

    headers = {
        'Authorization': 'Bearer '+ fw_info["token"] 
    }
    response = requests.request("GET", fg_url, headers=headers, data=payload, verify=False)
    handle_error(response, "Getting Malicious_IPs group_object from FG")
    address = response.json()

    members = address["results"][0]["member"]
    
    for name in names:
        c = True
        for member in members:
            if member["name"] == name["value"]:
                c = False
                break
        if c:
            member = {
                "name": name["value"]
            }
            members.append(member)
    payload = {
        "member":members
    }

    payload = json.dumps(payload)

    response = requests.request("put", fg_url, headers=headers, data=payload, verify=False)
    handle_error(response, "Updating Malicious_IPs object_group")
    print("Object_Group Malicious IPs Updated!")


# Post objects to Fortigate
# This function posts one or more objects to Fortigate
# Output: this function return nothing
def add_malicious_objects_to_FG(fw_info, names):
    fg_url = "https://%s/api/v2/cmdb/firewall/address?with_meta=1&datasource=1&skip=1&vdom=%s" %(fw_info['url'] ,fw_info['vdom'])

    payload={}

    headers = {
        'Authorization': 'Bearer '+ fw_info["token"]  
    }

    ### Getting address objects from FG
    response = requests.request("GET", fg_url, headers=headers, data=payload, verify=False)
    handle_error(response, "Getting address objects from FG")

    addresses = response.json()["results"]
    old_names = []
    for i in range(len(names)):
        for address in addresses:
            if address["name"] == names[i]["value"]:
                old_names.append(names[i])
                break
    new_names = []

    if(len(old_names) == 0):
        new_names = names

    for i in range(len(names)):
        for j in range(len(old_names)):
            if names[i]["value"] == old_names[j]["value"]:
                break;
            if(j == len(old_names)-1):
                new_names.append(names[i])

    if(len(new_names) ==0):
        return
    
    fg_url = "https://%s/api/v2/cmdb/firewall/address?with_meta=1&datasource=1&skip=1&vdom=%s" %(fw_info['url'] ,fw_info['vdom'])
    headers = {
        'Authorization': 'Bearer '+ fw_info["token"]   
    }

    payload = "["
    for name in new_names:
        if name["type"] == "ip":
            payload+='{"name": "%s", "subnet": "%s"},' % (name["value"], name["value"])   
        else: 
            payload+='{"name": "%s", "type": "fqdn", "fqdn": "%s"},' % (name["value"], name["value"])
    payload += ']'

    response = requests.request("POST", fg_url, headers=headers, data=payload, verify=False)
    handle_error(response, "Adding address objects to FG")
    print("Objects added!")
    return 


def main():
    url = input("Enter fortigate url\n")
    vdom = input("Enter VDOM\n")
    token = input("Enter token\n")

    fw_info = {
        "url": url,
        "vdom": vdom,
        "token": token
    }

    counter_of_inputs = input("Enter number of Inputs (IP addresses or FQDNs):\n")

    try:
        counter_of_inputs = int(counter_of_inputs)
    except ValueError:
        print("Please Enter number!")
        sys.exit(-1)

    inputs = []
    is_input_IP_address = False

    for i in range(counter_of_inputs):
        IP_or_FQDN = input()
        is_input_IP_address = is_ip_address_valid(IP_or_FQDN)
        if is_input_IP_address:
            IP_or_FQDN = IP_or_FQDN + '/32'
            inputs.append({"type": "ip", "value": IP_or_FQDN})
        else:
            inputs.append({"type": "fqdn", "value": IP_or_FQDN})


    add_malicious_objects_to_FG(fw_info, inputs)
   
    update_malicious_IP_object_group_in_FG(fw_info, inputs)


if __name__ == "__main__":
    main()
