#!/usr/bin/env python3
from email.parser import HeaderParser
from re import sub
import os
import requests
import sys
import argparse
import subprocess
import pyzipper

def check_sha256(s):
    if s == "":
        return
    if len(s) != 64:
        raise argparse.ArgumentTypeError("Please use sha256 value instead of '" + s + "'")
    return str(s)

def runCommand(cmd, verbose = False, *args, **kwargs):
    process = subprocess.Popen(
        cmd,
        stdout = subprocess.PIPE,
        stderr = subprocess.PIPE,
        text = True,
        shell = True
    )
    stdout, stderr = process.communicate()
    if verbose:
        print(stdout.strip, stderr)
    pass

runCommand('wget --post-data "query=get_file_type&file_type=elf&limit=100" https://mb-api.abuse.ch/api/v1/', verbose = False)


ZIP_PASSWORD = b'infected'
headers = { 'API-KEY': '' }

with open('index.html', 'r') as html_file:
    os.makedirs('malware')
    os.chdir('/Users/bai/Desktop/Bazaar/malware')
    for line in html_file:
        if 'sha256_hash' in line:
            str1 = line
            hash_num = str1[28:-3]

            #p = subprocess.Popen("configuration.py -s" + hash_num + "-u", shell = True)

            #parser = argparse.ArgumentParser(description='Download a malware sample from Malware Bazaar by abuse.ch')
            #parser.add_argument('-s', '--hash', help='File hash (sha256) to download', metavar="HASH", required=True, type=check_sha256)
            #parser.add_argument('-u', '--unzip', help='Unzip the downloaded file', required=False, default=False, action='store_true')

            #args = parser.parse_args()

            data = {
                'query' : 'get_file',
                'sha256_hash' : hash_num,
            }

            response = requests.post('https://mb-api.abuse.ch/api/v1', data=data, timeout=15, headers=headers, allow_redirects=True)

            if 'file_not_found' in response.text:
                print('Error: file not found')
                sys.exit()
            else:
                open(hash_num+'.zip','wb').write(response.content)

                with pyzipper.AESZipFile(hash_num+'.zip') as zipfile:
                    zipfile.pwd = ZIP_PASSWORD
                    secrects = zipfile.extractall('.')
                    print('Sample \"' + hash_num + "\" downloaded and unpacked.")

os.remove('/Users/bai/Desktop/Bazaar/index.html')

