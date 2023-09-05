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



# Post a VIP to Fortigate
# This function posts one VIP or multiple VIPs (based on port_forward value) and then add a VIP_GRP.
# Output: This function returns nothing
def post_vip_to_FG(fw_info, name, publish_ip, local_ip, port_forward, ports):
    headers = {
        'Authorization': 'Bearer '+ fw_info["token"]
    }   
    url = "https://%s/api/v2/cmdb/firewall/vip?with_meta=1&datasource=1&vdom=%s" %(fw_info['url'], fw_info['vdom'])

    members = []
    if(port_forward == 'True'):
        for port in ports:
            vip_name = name + '-Port' + port["number"]
     
            if port["protocol"] == 'udp':
                vip_name += 'udp'
            payload= {
                "name": vip_name,
                "extip": publish_ip,
                "mappedip":[{"range": '%s' %(local_ip)}],
                "extintf":{"name":"any","q_origin_key":"any","interface-name":"any"},
                "portforward": "enable",
                "protocol": port["protocol"],
                "extport": port["number"],
                "mappedport": port["number"],
            }
            payload = json.dumps(payload)

            response = requests.request("POST", url, headers=headers, data=payload, verify=False)
            handle_error(response, "Posting VIP to FG")

            print("VIP for port " + str(port["number"]) + "/" + str(port["protocol"]) + " added")
            
            members.append({"name": vip_name})

    else:
        vip_name = name + '-Full_Port'
        payload= {
            "name": vip_name,
            "extip": publish_ip,
            "mappedip":[{"range": '%s' %(local_ip)}],
            "extintf":{"name":"any","q_origin_key":"any","interface-name":"any"},
            "portforward": "disable",
        }

        payload = json.dumps(payload)

        response = requests.request("POST", url, headers=headers, data=payload, verify=False)
        handle_error(response, "Posting VIP to FG")
        print("VIP '{}' Added".format(vip_name))
        members.append({"name": vip_name})
        

    # Posting VIPGRP
    url_vipgrp = "https://%s/api/v2/cmdb/firewall/vipgrp?skip=1&vdom=%s&datasource=1" %(fw_info['url'], fw_info['vdom'])

    payload = {
        "name": name + " - VIPGRP",
        "interface": {
            "q_origin_key": "any",
            "name": "any",
            "datasource": "system.interface"
        },
        "color": 0,
        "comments": "",
        "member": members
    }
    
    payload = json.dumps(payload)
    response = requests.request("POST", url_vipgrp, headers=headers, data=payload, verify=False)
    handle_error(response, "Posting VIPGRP to FG")
    print("VIPGRP for " + str(publish_ip) + " added")
