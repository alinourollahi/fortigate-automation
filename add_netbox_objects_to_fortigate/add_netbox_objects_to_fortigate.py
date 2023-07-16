from os import confstr
import requests
import json
from ipaddress import IPv4Address
from ipaddress import IPv4Network
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


# Get Objects list from netbox
# This script assumes that Only Objects in the range of 192.168.0.0/16 need to be added to Fortigate
# If you want to add all of the VMs in your inventory to Fortigate, just change the 192.168.0.0/255.255.0.0 to 0.0.0.0/0.0.0.0
# Each GET request to netbox returns 1000 VMs tops. So we send 2 GET requests to support 2000 VMs. If you have more VMs, you should repeat the last part of this function.
# Output: An array with name and IP of each object (netbox_VMs)
def get_VMs_from_netbox(netbox_url, netbox_token):
    netbox_url = "https://%s/api/virtualization/virtual-machines/?limit=1000" %(netbox_url)
    
    headers = {
        'Accept': 'application/json',
        'Authorization': 'Token '+ netbox_token,
        'Content-Type': 'application/json'
    }
    payload = {}

    response = requests.request("GET", netbox_url, headers=headers, data=payload, verify=False)
    results = response.json()["results"]

    netbox_VMs = []

    VMs_Range = IPv4Network("192.168.0.0/255.255.0.0")

    for vm in results:
        if vm["primary_ip"] is None:
            continue
        
        name = vm["display"]
        ip = vm["primary_ip"]["address"].split('/')[0]
        if IPv4Address(ip) not in VMs_Range:
            continue

        VM = {
            "name": name,
            "ip": ip
        }

        netbox_VMs.append(VM)

    netbox_url += '&offset=1000'
    response = requests.request("GET", netbox_url, headers=headers, data=payload, verify=False)
    results = response.json()["results"]

    for vm in results:
        if vm["primary_ip"] is None:
            continue
        
        name = vm["display"]
        ip = vm["primary_ip"]["address"].split('/')[0]
        if IPv4Address(ip) not in VMs_Range:
            continue

        VM = {
            "name": name,
            "ip": ip
        }

        netbox_VMs.append(VM)
    
    return netbox_VMs


# Get VMs list from Fortigate
# Only VMs in the range of 192.168.0.0/16, If your VMs are in different range, you need to change this part.
# Output: An array with name, IP and ref_count of each VM (FG_VMs)
def get_addresses_from_FG(fw_info):
    fg_url = "https://%s/api/v2/cmdb/firewall/address?with_meta=1&datasource=1&skip=1&vdom=%s" %(fw_info["url"], fw_info["vdom"])
    payload={}

    headers = {
        'Authorization': 'Bearer '+ fw_info["token"] 
    }

    response = requests.request("GET", fg_url, headers=headers, data=payload, verify=False)
    handle_error(response, "Getting VMs list from Fortigate")
    address = response.json()

    fg_VMs = []
    address = address["results"]
    
    VMs_Range = IPv4Network("192.168.0.0/255.255.0.0")

    for a in address:
        if a["type"] != 'ipmask':
            continue
        subnet = a["subnet"]
        ip = subnet.split(' ')[0]
        mask = subnet.split(' ')[1]
        
        # Only /32 objects are acceptable
        if mask != "255.255.255.255":
            continue
        
        if IPv4Address(ip) in VMs_Range:
            VM = {
                "name": a["name"],
                "ip": ip,
                "ref": a["q_ref"]
            }
            fg_VMs.append(VM)
    
    return fg_VMs


# Change the name of an object in Fortigate
# This function is called by 'compare_netbox_to_FG' function
def update_FG_object(FG_VM_name, fw_info, name):
    fg_url = "https://%s/api/v2/cmdb/firewall/address/%s?vdom=%s" %(fw_info["url"],FG_VM_name, fw_info["vdom"])
    headers = {
        'Authorization': 'Bearer '+ fw_info["token"]
    }
    payload='{"name":"%s"}' % (name)
    print("Updating: " + name)
    response = requests.request("PUT", fg_url, headers=headers, data=payload, verify=False)
    handle_error(response, "Updating Object's name in Fortigate")


# Delete an object from Fortigate
# This function is called by 'compare_netbox_to_FG' function
def delete_FG_object(FG_VM_name, fw_info):
    fg_url = "https://%s/api/v2/cmdb/firewall/address/%s?vdom=%s" %(fw_info["url"],FG_VM_name, fw_info["vdom"])
    headers = {
        'Authorization': 'Bearer '+ fw_info["token"]
    }
    payload='{"name":"%s"}' % (FG_VM_name)
    print("Deleting: " + FG_VM_name)
    response = requests.request("DELETE", fg_url, headers=headers, data=payload, verify=False)
    handle_error(response, "Deleting an object from Fortigate")


# Add an object to Fortigate
# This function is called by 'compare_netbox_to_FG' function    
def add_FG_object(name, fw_info, ip):
    fg_url = "https://%s/api/v2/cmdb/firewall/address?with_meta=1&datasource=1&skip=1&vdom=%s" %(fw_info["url"], fw_info["vdom"])
    headers = {
        'Authorization': 'Bearer '+ fw_info["token"]
    }
    payload='{"name":"%s","subnet":"%s/32"}' % (name, ip)
    print("Adding: " + name)    
    response = requests.request("POST", fg_url, headers=headers, data=payload, verify=False)
    handle_error(response, "Adding an object to Fortigate")


# Compare the output of the 'get_VMs_from_netbox' and 'get_addresses_from_FG' functions
# If name of an object from Fortigate and netbox does not match, this function calls 'update_FG_object' function
# If an object from Fortigate does not exist on netbox and that object has zero refrence, this function calls 'delete_FG_object' function.
# If an object from netbox does not exist on Fortigate, this function calls 'add_FG_object' function.
# Output: an array with name, IP and ref_count of VMs from Fortigate which does not exist on netbox and have ref_count greater than zero (Old_VMs)
def compare_netbox_to_FG(netbox_VMs, FG_VMs, fw_info):
    print("netbox_VMs:" , len(netbox_VMs))
    print("FG_VMs:" ,len(FG_VMs))
    
    old_VMs = []

    for FG_VM in FG_VMs:
        res = next((sub for sub in netbox_VMs if sub['ip'] == FG_VM["ip"]), None)

        if res is not None:
            netbox_VMs.remove(res)
            name = res['name'].split('.psg.network')[0] + '-local'
            
            if name != FG_VM['name']:
                update_FG_object(FG_VM['name'], fw_info, name)
        else:
            if(FG_VM['ref']!=0):
                old_VMs.append(FG_VM)
            else:
                print(FG_VM)
                delete_FG_object(FG_VM['name'], fw_info)

    for netbox_VM in netbox_VMs:
        name = netbox_VM['name'].split('.psg.network')[0] + '-local'
        add_FG_object(name, fw_info, netbox_VM['ip'])

    return old_VMs
