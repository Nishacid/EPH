#!/usr/bin/python3
# -*- coding: utf-8 -*- 
# Python Version : 3.X

import os
import mmh3
import codecs
import requests
import argparse
import shodan
import yaml
import sys

# Arguments
def parseArgs():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--api", dest="API", default=None, help="Shodan API Key", required=True)
    parser.add_argument("-o", "--org", dest="org", default=None, help="Targeted organization", required=False)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-u", "--url", dest="url", default=None, help="URL of the favicon")
    group.add_argument("-i", "--img", dest="img", default=None, help="Image source of the favicon")
    group.add_argument("-H", "--hash", dest="hash", default=None, help="Hash of the favicon")
    group.add_argument("-c", "--common", dest="common", default=None, help="Common Favicon Scan", action="store_true")
    return parser.parse_args()

# Calculate the hash of the favicon with an url
def get_hash_from_url(url, verify=False):
    if not verify:
        # Disable warings of insecure connection for invalid certificates
        requests.packages.urllib3.disable_warnings()
        # Allow use of deprecated and weak cipher methods
        requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS += ':HIGH:!DH:!aNULL'
        try:
            requests.packages.urllib3.contrib.pyopenssl.util.ssl_.DEFAULT_CIPHERS += ':HIGH:!DH:!aNULL'
        except AttributeError:
            pass

    # Calcul Hash
    try:
        session = requests.session()
        favdata = session.get(url, verify=verify)
        if 'Content-Type' in favdata.headers:
            if "text/html" not in favdata.headers['Content-Type']:
                favicon = codecs.encode(favdata.content, "base64")
                favhash = mmh3.hash(favicon)
                return favhash
    except requests.ConnectionError:
        print("[-] Error : couldn't connect to server")
        sys.exit()
    except requests.Timeout:
        print("[-] Error : request timeout")
        sys.exit()

# Calculate the hash of the favicon with an image
def get_hash_from_image(image):
    try:
        f = open(image, "rb")
        data = f.read()
        favicon = codecs.encode(data, "base64")
        favhash = mmh3.hash(favicon)
        return favhash
    except FileNotFoundError:
        print("[-] Error : File not found")
        sys.exit()
        
# Scan of the Yaml Database
def common_scan():
    if os.path.exists("database.yml"):
        with open("database.yml", "r") as database:
            try:
                data = yaml.safe_load(database)
            except yaml.YAMLError as e:
                print(f"Error : {e}")
                sys.exit()
            num = 1
            for value in data.items():
                hash = data[num]["hash"]
                name = data[num]["name"]
                print(f"[+] Scanning for {name}")
                scan_shodan(hash, org=options.org)
                num += 1
    else:
        print("[!] database.yml not found !")

# Shodan Scan
def scan_shodan(argument, org=None):
    try:
        if org is not None:
            results = api.search(f'http.favicon.hash:{argument} org:{org}')
        else:
            results = api.search(f'http.favicon.hash:{argument}')
        print(f"[+] Total results found : {results['total']}\n")

        for result in results['matches']:
            ip = result['ip_str']
            print(f"IP : {ip}")
            # print(f"Hostname : {result['hostnames']}")
            port = result['port']
            print(f"Port : {port}")
            # print(f"OS : {result['os']}")
            org = result['org']
            print(f"Organization : {org}\n")
    except shodan.APIError as e:
        print(f"Error : {e}")
        sys.exit()

if __name__ == '__main__':
    try:
        options = parseArgs()

        # A free API key will not working
        SHODAN_API_KEY = options.API
        api = shodan.Shodan(SHODAN_API_KEY)

        if options.common is not None:
            print("[+] Performing a common scan...")
            common_scan()

        # URL Scan
        elif options.url is not None:
            url = options.url
            url_hash = get_hash_from_url(url)
            print(f"[+] The hash of the favicon is : {url_hash}")
            print("[+] Performing a shodan scan...")
            scan_shodan(url_hash, org=options.org)

        # Hash Scan
        elif options.hash is not None:
            hash = options.hash
            print(f"[+] The hash of the favicon is : {hash}")
            print("[+] Performing a shodan scan...")
            scan_shodan(hash, org=options.org)

        # Image Scan
        elif options.img is not None:
            image = options.img
            img_hash = get_hash_from_image(image)
            print(f"[+] The hash of the favicon is : {img_hash}")
            print("[+] Performing a shodan scan...")
            scan_shodan(img_hash, org=options.org)

    except KeyboardInterrupt:
        print("Bye !")
        sys.exit()