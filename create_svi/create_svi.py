from os import confstr
import requests
import json
import ipaddress
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import sys

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

# Validation functions
##############################################
def is_ip_address_valid(address):    
    try:
        ip_network = ipaddress.IPv4Network(address, strict=False)
        ip = address.split('/')[0]

        mask = str(ip_network.netmask)
        if mask == "255.255.255.255":
            print("Enter IP with mask. e.g: 192.168.1.254/24")
            sys.exit(-1)

        if ip == str(ip_network.broadcast_address) or ip == str(ip_network.network_address):
            print("Invalid IP!")
            sys.exit(-1)

        
    except ValueError:
        print("'{}' is not a valid IP address!".format(address))
        sys.exit(-1)

def is_vid_valid(vid):
    try:
        vid = int(vid)    
        if(vid < 2 or vid > 4095):
            print("'{}' is not a valid VID!".format(vid))
            sys.exit(-1)
    except ValueError:
        print("VID '{}' is not a valid VID!".format(vid))
        sys.exit(-1)
# End of Validation functions
##############################################

# This function sends a GET request to FG to retreive a list of all interfaces (in all VDOMs).
# This function is called by "add_interface_to_FG" function.
# Output: An array of all interfaces
def get_interfaces_from_FG(fw_info):
    fg_url = "https://%s/api/v2/cmdb/system/interface?vdom=%s" %(fw_info['url'] ,fw_info['vdom'])

    payload={}

    headers = {
        'Authorization': 'Bearer '+ fw_info['token']
    }

    response = requests.request("GET", fg_url, headers=headers, data=payload, verify=False)

    handle_error(response, "getting interfaces from FG")
    interfaces = response.json()['results']

    return interfaces




def main():
    url = input("Enter fortigate url\n")
    vdom = input("Enter VDOM\n")
    token = input("Enter token\n")

    interface = input("Enter fortigate interface\n")
    alias = input("Enter alias\n")
    vid = input("Enter VID\n")
    ip = input("Enter IP\n")

    is_vid_valid(vid)
    is_ip_address_valid(ip)

    fw_info = {
        "site": url,
        "vdom": vdom,
        "token": token
    }

    add_interface_to_FG(fw_info, interface, alias, vid, ip)

    interface_name = "VID-" + vid
    add_zone_to_FG(fw_info, alias, interface_name)


if __name__ == "__main__":
    main()

