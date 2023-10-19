#!/usr/bin/python3

import json
import os
import requests
import sys

if len(sys.argv) != 2:
    print('Usage: python upload.py <file>')
    print()
    print('  Upload <file> to file.io and retrieve a download key.')
    print()
    print('E.g.   python upload.py image.bin')
    sys.exit(0)

filepath = sys.argv[1]
filename = os.path.basename(filepath)

with open(filepath, 'rb') as file:
    res = requests.post('https://file.io/', files={ 'file': ( filename, file ) })
    key = json.loads(res.text)['key']
    print(f'{key = }')
