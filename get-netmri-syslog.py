#!/usr/bin/env python
"""get-netmri-syslog.py Parse the list of Syslog messages from NetMRI and provide useful output."""

import sys
import getpass
import requests

def post_request(user_name, password, base_url, api_path, payload):
    """Send the request to NetMRI and catch the response coming back."""
    from requests.auth import HTTPBasicAuth
    url = base_url + api_path
    response = requests.post(url, auth=HTTPBasicAuth(user_name, password), \
        json=payload)
    return response

def get_request(user_name, password, base_url, api_path, payload):
    """Send the request to NetMRI and catch the response coming back."""
    from requests.auth import HTTPBasicAuth
    url = base_url + api_path
    if payload == "":
        response = requests.get(url, auth=HTTPBasicAuth(user_name, password))
    else:
        response = requests.get(url, auth=HTTPBasicAuth(user_name, password), \
        json=payload)
    return response

def collect_config_info():
    """ ask the user for info about NetMRI, users, passwords, etc. """
    default_host = "netmri.lwpca.net"
    netmri_host = raw_input("Please enter NetMRI hostname: [%s] " %(default_host))
    if not netmri_host:
        netmri_host = default_host
    netmri_admin_pwd = getpass.getpass('NetMRI admin user password: ')
    netmri_base_url = "https://" + netmri_host + "/api"
    return({"admin_name" : "admin", "admin_pass" : netmri_admin_pwd, "netmri_host": netmri_host, \
    	"base_url": netmri_base_url})

def admin_account_works(collected_input):
    """ Check we can connect to NetMRI using the supplied credentials. """
    result = get_request(collected_input['admin_name'], collected_input['admin_pass'], \
        collected_input['base_url'], '/', "")
    if result.status_code == 403:
        print "Unable to authenticate to NetMRI using user 'admin' and the supplied password."
        print "Please check the password and try again.  Exiting."
        sys.exit(1)


def main():
    """Do the deed."""
    collected_input = collect_config_info()
    # Check if we can authenticate with the admin account.
    admin_account_works(collected_input)
    base_url = "https://%s/" %(collected_input["netmri_host"])
    syslog_doc = get_request(collected_input["admin_name"], collected_input["admin_pass"], \
    	base_url, "netmri/api/change/syslog-config.tdf?contentType=text/json", "")
    print syslog_doc.text

if __name__ == "__main__":
    main()
