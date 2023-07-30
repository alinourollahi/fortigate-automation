from os import confstr
import requests
import json
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import sys
import pprint

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



# This function find ip addresses for each of the members of "VMs" array
def get_address_of_vms(fw_info, VMs):

    fg_url = "https://%s/api/v2/cmdb/firewall/address?with_meta=1&datasource=1&skip=1&vdom=%s"  %(fw_info['url'] ,fw_info['vdom'])

    payload={}

    headers = {
        'Authorization': 'Bearer '+ fw_info['token']
    }

    response = requests.request("GET", fg_url, headers=headers, data=payload, verify=False)
    addresses = response.json()['results']

    VM_Objects = []
    for VM in VMs:
        for address in addresses:
            if address['type'] == 'ipmask':
                if VM == address['name']:
                    VM_Objects.append({'name': VM, 'ip': address['subnet'].split(' ')[0]})

    print("These VMs have full access to internet permanently:")
    pprint.pprint(VM_Objects)


# This function finds the policies for permanent internet connection
def check_policy(fw_info, wan_interface):

    fg_url = "https://%s/api/v2/cmdb/firewall/policy?vdom=%s" %(fw_info['url'],fw_info['vdom'])
    payload={}

    headers = {
        'Authorization': 'Bearer '+ fw_info['token']
    }

    response = requests.request("GET", fg_url, headers=headers, data=payload, verify=False)
    policies = response.json()['results']

    VMs = []
    
    for policy in policies:
        if policy['dstintf'][0]['name'] == wan_interface and policy['dstaddr'][0]['name'] == 'all' and policy['service'][0]['name'] == 'ALL' and policy['schedule'] == 'always' and policy['status'] == 'enable':
            for src in policy['srcaddr']:
                VMs.append(src['name'])

    VMs = list(set(VMs))

    get_address_of_vms(fw_info, VMs)

