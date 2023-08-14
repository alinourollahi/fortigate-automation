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

def main():
    site = input()
    vdom = input()
    token = input()

    interface = input()
    alias = input()
    vid = input()
    ip = input()

    is_vid_valid(vid)
    is_ip_address_valid(ip)

    fw_info = {
        "site": site,
        "vdom": vdom,
        "token": token
    }

    add_interface_to_FG(fw_info, interface, alias, vid, ip)

    interface_name = "VID-" + vid
    add_zone_to_FG(fw_info, alias, interface_name)


if __name__ == "__main__":
    main()

