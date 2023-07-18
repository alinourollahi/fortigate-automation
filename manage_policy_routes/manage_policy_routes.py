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
