#!/usr/bin/env python3

import requests
import argparse
import re
import json
import sys
import os
from base64 import b64encode
import urllib3
from rich.console import Console
from rich.theme import Theme
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Disable insecure request warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Initialize a requests session
# file deepcode ignore MissingClose: <please specify a reason of ignoring this>
req = requests.Session()

# Set up proxy environment variables
http_proxy = ""
os.environ['HTTP_PROXY'] = http_proxy
os.environ['HTTPS_PROXY'] = http_proxy

# Define a custom theme for rich console output
custom_theme = Theme({
    "OK": "bright_green",
    "NOK": "red3"
})

# Function to handle command-line arguments
def manageArgs():
    parser = argparse.ArgumentParser()
    # Positional args
    parser.add_argument("url", help="URL")
    # Optional args
    parser.add_argument("-p", dest='port', metavar='port', type=int, default=5000, help="port to use (default : 5000)")
    # Authentication
    auth = parser.add_argument_group("Authentication")
    auth.add_argument('-U', dest='username', type=str, default="", help='Username')
    auth.add_argument('-P', dest='password', type=str, default="", help='Password')
    # Authorization
    author = parser.add_argument_group("Authorization")
    author.add_argument('-A', dest='authorization', type=str, default="", help='Provide Authorization token')
    # Args Action in opposition
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--dump", metavar="DOCKERNAME", dest='dump', type=str,  help="DockerName")
    action.add_argument("--list", dest='list', action="store_true")
    action.add_argument("--dump_all", dest='dump_all', action="store_true")
    args = parser.parse_args()
    return args

# Function to print the list of Docker images
def printList(dockerlist):
    for element in dockerlist:
        if element:
            console.print(f"[+] {element}", style="OK")
        else:
            console.print(f"[-] No Docker found", style="NOK")

# Function to send a request with proper authentication
def tryReq(url, username=None, password=None, authorization=None):
    try:
        headers = {}
        if username and password and not authorization:
            auth_token = b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
            headers["Authorization"] = f"Basic {auth_token}"
        elif authorization and not (username and password):
            headers["Authorization"] = authorization
        elif (username and password) and authorization:
            raise ValueError("Provide either username/password or Authorization token, not both.")

        if username and password:
            # file deepcode ignore SSLVerificationBypass: <please specify a reason of ignoring this>
            r = req.get(url, verify=False, headers=headers)
        else:
            r = req.get(url, verify=False, headers=headers)

        r.raise_for_status()
    except requests.exceptions.HTTPError as errh:
        console.print(f"Http Error: {errh}", style="NOK")
        sys.exit(1)
    except requests.exceptions.ConnectionError as errc:
        console.print(f"Error Connecting: {errc}", style="NOK")
        sys.exit(1)
    except requests.exceptions.Timeout as errt:
        console.print(f"Timeout Error: {errt}", style="NOK")
        sys.exit(1)
    except requests.exceptions.RequestException as err:
        console.print(f"Something went wrong: {err}", style="NOK")
        sys.exit(1)
    return r

# Function to create a directory if it doesn't exist
def createDir(directoryName):
    if not os.path.exists(directoryName):
        os.makedirs(directoryName)

# Function to download the Docker image blobs
def downloadSha(url, port, docker, sha256, username=None, password=None, authorization=None):
    createDir(docker)
    directory = f"./{docker}/"
    for sha in sha256:
        filenamesha = f"{sha}.tar.gz"
        geturl = f"{url}:{str(port)}/v2/{docker}/blobs/sha256:{sha}"
        r = tryReq(geturl, username, password, authorization)
        if r.status_code == 200:
            console.print(f"    [+] Downloading : {sha}", style="OK")
            # file deepcode ignore PT: <please specify a reason of ignoring this>
            with open(directory+filenamesha, 'wb') as out:
                for bits in r.iter_content():
                    out.write(bits)

# Function to get the list of blob hashes for a Docker image
def getBlob(docker, url, port, username=None, password=None, authorization=None):
    tags = f"{url}:{str(port)}/v2/{docker}/tags/list"
    rr = tryReq(tags, username, password, authorization)
    data = rr.json()
    image = data["tags"][0]
    url = f"{url}:{str(port)}/v2/{docker}/manifests/"+image+""
    r = tryReq(url, username, password, authorization)
    blobSum = []
    if r.status_code == 200:
        regex = re.compile('blobSum')
        for aa in r.text.splitlines():
            match = regex.search(aa)
            if match:
                blobSum.append(aa)
        if not blobSum:
            console.print(f"[-] No blobSum found", style="NOK")
            sys.exit(1)
        else:
            sha256 = []
            cpt = 1
            for sha in blobSum:
                console.print(f"[+] BlobSum found {cpt}", end='\r', style="OK")
                cpt += 1
                a = re.split(':|,', sha)
                sha256.append(a[2].strip("\""))
            print()
            return sha256

# Function to enumerate the list of Docker images available
def enumList(url, port, username=None, password=None, authorization=None, checklist=None):
    url = f"{url}:{str(port)}/v2/_catalog"
    try:
        r = tryReq(url, username, password, authorization)
        catalog2 = re.split(':|,|\n ', r.text)
        catalog3 = []
        for docker in catalog2:
            dockername = docker.strip("[\'\"\n]}{")
            catalog3.append(dockername)
        printList(catalog3[1:])
        return catalog3
    except:
        # file deepcode ignore UpdateAPI: <please specify a reason of ignoring this>
        exit()

# Function to perform the "dump" action
def dump(args):
    if args.username or args.password:
        authorization = None
    elif args.authorization:
        authorization = args.authorization
    else:
        console.print("Provide either username/password or Authorization token.")
        sys.exit(1)

    sha256 = getBlob(args.dump, args.url, args.port, args.username, args.password, authorization)
    console.print(f"[+] Dumping {args.dump}", style="OK")
    downloadSha(args.url, args.port, args.dump, sha256, args.username, args.password, authorization)

# Function to perform the "dump_all" action
def dumpAll(args):
    if args.username or args.password:
        authorization = None
    elif args.authorization:
        authorization = args.authorization
    else:
        console.print("Provide either username/password or Authorization token.")
        sys.exit(1)

    dockerlist = enumList(args.url, args.port, args.username, args.password, authorization)
    for docker in dockerlist[1:]:
        sha256 = getBlob(docker, args.url, args.port, args.username, args.password, authorization)
        console.print(f"[+] Dumping {docker}", style="OK")
        downloadSha(args.url, args.port, docker, sha256, args.username, args.password, authorization)

# Function to handle the selected options
def options():
    args = manageArgs()
    if args.list:
        enumList(args.url, args.port, args.username, args.password, args.authorization)
    elif args.dump_all:
        dumpAll(args)
    elif args.dump:
        dump(args)

if __name__ == '__main__':
    print(f"[+]======================================================[+]")
    print(f"[|]    Docker Registry Grabber v2.0       @0xm3m         [|]")
    print(f"[+]======================================================[+]")
    print()
    urllib3.disable_warnings()
    console = Console(theme=custom_theme)
    options()
