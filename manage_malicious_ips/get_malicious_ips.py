#!/usr/bin/python3 

import ipaddress
from xmlrpc.client import boolean
import requests
import urllib3
import sys
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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


# Get object_group "Malicious_IPs" from Fortigate firewall and Print it
# Output: This function return nothing
def get_malicious_IP_group_From_FG(fw_info):
    fg_url = "https://%s/api/v2/cmdb/firewall/addrgrp/Malicious_IPs?with_meta=1&datasource=1&skip=1&vdom=%s"  %(fw_info['url'] ,fw_info['vdom'])

    payload={}

    headers = {
        'Authorization': 'Bearer '+ fw_info["token"] 
    }

    response = requests.request("GET", fg_url, headers=headers, data=payload, verify=False)
    handle_error(response, "Getting Malicious_IPs group_object from FG")
    res = response.json()["results"][0]["member"]
    address_list = []
    for r in res:
        address_list.append(r["name"])   
    
    print(address_list)


def main():
    url = input("Enter fortigate url\n")
    vdom = input("Enter VDOM\n")
    token = input("Enter token\n")

    fw_info = {
        "url": url,
        "vdom": vdom,
        "token": token
    }

    get_malicious_IP_group_From_FG(fw_info)
    return

if __name__ == "__main__":
    main()
