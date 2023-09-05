from http import server
from lib2to3.pgen2 import token
from os import confstr, name, utime
from pydoc import describe
from threading import local
from traceback import print_tb
import requests
import json
import sys
import urllib3
import ipaddress 
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Validation Functions
##############################################
def is_ip_address_valid(address):
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        print("IP address '{}' is not valid!".format(address)) 
        sys.exit(-1)

def is_port_valid(port):
    try:
        if int(port) > 0 and int(port) < 65536:
            return
    except ValueError:
        print("Port number must be between 1 and 65535")

    print("Port '{}' is not valid!".format(port))
    sys.exit(-1)

# End of validation functions
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
    
    
# Get destination interface based on IP
# This function searchs for the giving IP in routing monitor to find the outgoing interface
# Output: Destination interface
def get_dst_interface(fw_info, ip):

    fg_url = "https://%s/api/v2/monitor/router/lookup?destination=%s&vdom=%s" %(fw_info['url'],ip ,fw_info['vdom'])
    myToken = fw_info['token']
    payload={}

    headers = {
        'Authorization': 'Bearer '+ myToken 
    }
    response = requests.request("GET", fg_url, headers=headers, data=payload, verify=False)
    handle_error(response, "Getting destination interface from FG")

    routes = response.json()['results']
    
    return routes["interface"]



# Get the zone of the giving interface
# This function searchs in zones to find the zone of the giving interface
# Output: Zone of the giving interface
def get_zone(fw_info, intf):
    fg_url = "https://%s/api/v2/cmdb/system/zone?datasource=1&with_meta=1&vdom=%s" %(fw_info['url'], fw_info['vdom'])
    
    headers = {
        'Authorization': 'Bearer '+ fw_info["token"] 
    }

    payload = {}
    response = requests.request("GET", fg_url, headers=headers, data=payload, verify=False)
    handle_error(response, "Getting zone of interface from FG")

    zones = response.json()["results"]

    for z in zones:
        interfaces = z["interface"]
        for i in interfaces:
            if i["interface-name"] == intf:
                return z["name"]

    return -1