#!/usr/bin/python3
# -*- coding: utf-8 -*- 
# Python Version : 3.X

import mmh3
import codecs
import requests
import argparse
import warnings
import shodan
import yaml
import sys

# Arguments
parser = argparse.ArgumentParser()
parser.add_argument("--api", dest="API", help="Shodan API Key", required=True)
parser.add_argument("--org", dest="org", help="Targeted organization", required=False)
parser.add_argument("--url", dest="url", help="URL of the favicon", required=False)
parser.add_argument("--img", dest="img", help="Image source of the favicon", required=False)
parser.add_argument("--hash", dest="hash", help="Hash of the favicon", required=False)
parser.add_argument("--common", dest="common", help="Common Favicon Scan", action="store_true", required=False)
args = parser.parse_args()

# A free API key will not working
SHODAN_API_KEY = args.API
api = shodan.Shodan(SHODAN_API_KEY)

# calculate the hash of the favicon with an url
def get_hash_from_url(url):
    
    # Disable SSL Warning
    warnings.filterwarnings('ignore', message='Unverified HTTPS request')
    
    # Calcul Hash
    session = requests.session()
    favdata = session.get(url, verify=False)
    if 'Content-Type' in favdata.headers:
        if "text/html" not in favdata.headers['Content-Type']:
            favicon = codecs.encode(favdata.content, "base64")
            favhash = mmh3.hash(favicon)
            return favhash
    
# calculate the hash of the favicon with an image
def get_hash_from_image(image):
    f = open(image, "rb")
    data = f.read()
    favicon = codecs.encode(data, "base64")
    favhash = mmh3.hash(favicon)
    return favhash
        
# Shodan Scan
def scan_shodan(argument):
    try:      
        if args.org:
            org = args.org
            results = api.search(f'http.favicon.hash:{argument} org:{org}')
        else:
            results = api.search(f'http.favicon.hash:{argument}')
        print(f"[+] Total results found : {results['total']}\n")
        
        for result in results['matches']:
            print(f"IP : {result['ip_str']}")
            # print(f"Hostname : {result['hostnames']}")
            print(f"Port : {result['port']}")
            # print(f"OS : {result['os']}")
            print(f"Organization : {result['org']}\n")
    except shodan.APIError as e:
            print(f"Error : {e}")
            sys.exit()

# Scan of the Yaml Database    
def common_scan():
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
            scan_shodan(hash)
            num += 1

if __name__ == "__main__": 
    
    if args.common and not (args.hash or args.url or args.img):
        print("[+] Perfoming a common scan...")
        common_scan()
        
    # URL Scan
    elif args.url and not (args.hash or args.img or args.common):
        url = args.url
        url_hash = get_hash_from_url(url)
        print(f"[+] The hash of the favicon is : {url_hash}")
        print("[+] Perfoming a shodan scan...")
        scan_shodan(url_hash)
        
    # Hash Scan
    elif args.hash and not (args.url or args.img or args.common):
        hash = args.hash
        print(f"[+] The hash of the favicon is : {hash}")
        print("[+] Perfoming a shodan scan...")
        scan_shodan(hash)
        
    # Image Scan
    elif args.img and not (args.url or args.hash or args.common):
        image = args.img
        img_hash = get_hash_from_image(image)
        print(f"[+] The hash of the favicon is : {img_hash}")
        print("[+] Perfoming a shodan scan...")
        scan_shodan(img_hash)
        
    # Too many arguments
    elif (args.img and args.url) or (args.img and args.hash) or (args.url and args.hash):
        print("[-] Too many arguments, please choose only --url or --img or --hash")
        sys.exit()
    
    # No arguments
    elif not args.img or not args.url or not args.hash or args.common:
        print("[-] Please choose one argument")
        sys.exit()