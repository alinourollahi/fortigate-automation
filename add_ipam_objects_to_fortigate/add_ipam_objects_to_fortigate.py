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


# Get Objects list from IPAM
# This script assumes that Only Objects in the range of 192.168.0.0/16 need to be added to Fortigate
# If you want to add all of the VMs in your inventory to Fortigate, just change the 192.168.0.0/255.255.0.0 to 0.0.0.0/0.0.0.0
# Each GET request to ipam returns 1000 VMs tops. So we send 2 GET requests to support 2000 VMs. If you have more VMs, you should repeat the last part of this function.
# Output: An array with name and IP of each object (ipam_VMs)
def get_VMs_from_ipam(ipamURL, ipamToken):
    ipam_url = "https://%s/api/virtualization/virtual-machines/?limit=1000" %(ipamURL)
    
    headers = {
        'Accept': 'application/json',
        'Authorization': 'Token '+ ipamToken,
        'Content-Type': 'application/json'
    }
    payload = {}

    response = requests.request("GET", ipam_url, headers=headers, data=payload, verify=False)
    results = response.json()["results"]

    ipam_VMs = []

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

        ipam_VMs.append(VM)

    ipam_url += '&offset=1000'
    response = requests.request("GET", ipam_url, headers=headers, data=payload, verify=False)
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

        ipam_VMs.append(VM)
    
    return ipam_VMs

