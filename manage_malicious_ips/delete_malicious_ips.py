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


# Get malicious_IPs_group from Frotigate, remove the given object from this object_group and update the object_group
# Output: This function returns nothing
def update_malicious_IP_group_in_FG(fw_info, input):
    fg_url = "https://%s/api/v2/cmdb/firewall/addrgrp/Malicious_IPs?with_meta=1&datasource=1&skip=1&vdom=%s" %(fw_info['url'] ,fw_info['vdom'])
    payload={}

    headers = {
        'Authorization': 'Bearer '+ fw_info["token"] 
    }

    response = requests.request("GET", fg_url, headers=headers, data=payload, verify=False)
    handle_error(response, "Getting Malicious_IPs group_object from FG")
    members = response.json()["results"][0]["member"]
    
    l = len(members)
    for i in range(l):
        if members[i]["name"] == input:
            members.remove(members[i])
            break
        if i == l-1:
            print("Address not found!")
            return -1

    payload = {
        "member":members
    }

    payload = json.dumps(payload)

    response = requests.request("put", fg_url, headers=headers, data=payload, verify=False)
    handle_error(response, "Updating Malicious_IPs group_object")
    print("Object_Group Malicious IPs Updated!")


def main():
    url = input("Enter fortigate url\n")
    vdom = input("Enter VDOM\n")
    token = input("Enter token\n")

    fw_info = {
        "url": url,
        "vdom": vdom,
        "token": token
    }

    IP_or_FQDN = input("Enter an IP or FQDN address\n")
    is_input_IP_address = is_ip_address_valid(IP_or_FQDN)

    if is_input_IP_address:
        IP_or_FQDN += '/32'

    update_malicious_IP_group_in_FG(fw_info, IP_or_FQDN)
    return

if __name__ == "__main__":
    main()
