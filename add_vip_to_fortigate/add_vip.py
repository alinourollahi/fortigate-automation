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
    