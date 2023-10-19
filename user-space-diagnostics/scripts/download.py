#!/usr/bin/python3

import requests
import sys

if len(sys.argv) != 3:
    print('Usage: ./download.sh <key> <file>')
    print()
    print('  Download from file.io the file referenced by <key> and save it to <file>.')
    print()
    print('E.g.   ./download.sh vLvD4TGDuyzB image.bin')
    sys.exit(0)

key      = sys.argv[1]
filepath = sys.argv[2]

res = requests.get(f'https://file.io/{key}')
with open(filepath, 'wb') as file:
    file.write(res.content)
