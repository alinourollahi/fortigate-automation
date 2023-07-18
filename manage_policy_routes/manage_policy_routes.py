from os import confstr
import requests
import json
from ipaddress import IPv4Address
from ipaddress import IPv4Network
import urllib3
import sys
import ipaddress 
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

# Validation function
##############################################
def is_ip_address_valid(address):
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        print("IP address '{}' is not valid!".format(address)) 
        sys.exit(-1)


# This function prints the current situation of the VPN PBR.
def get_PBR_status(site, vdom, token, policy_id):
    fg_url = "https://%s/api/v2/cmdb/router/policy/%s?vdom=%s" %(site, policy_id, vdom)
    payload={}

    headers = {
        'Authorization': 'Bearer '+ token 
    }

    response = requests.request("GET", fg_url, headers=headers, data=payload, verify=False)
    handle_error(response, "Getting current PBR status")

    res = response.json()['results'][0]['src']
    for r in res:
        print(r['subnet'].split('/')[0])


# This function adds a VM to the the PBR.
def add_VM_to_PBR(site, vdom, token, policy_id, vm_ip):
    fg_url = "https://%s/api/v2/cmdb/router/policy/%s?vdom=%s" %(site, policy_id, vdom)
    payload={}

    headers = {
        'Authorization': 'Bearer '+ token 
    }

    response = requests.request("GET", fg_url, headers=headers, data=payload, verify=False)
    handle_error(response, "Getting current PBR status")

    res = response.json()['results'][0]['src']
    
    new_vm = {'subnet': vm_ip + '/255.255.255.255', 'q_origin_key': vm_ip + '/255.255.255.255'}

    res.append(new_vm)

    payload = {
        "src": res
    }

    payload = json.dumps(payload)
    response = requests.request("put", fg_url, headers=headers, data=payload, verify=False)
    handle_error(response, "Updating the PBR")
    print('IP added to the PBR successfully')

