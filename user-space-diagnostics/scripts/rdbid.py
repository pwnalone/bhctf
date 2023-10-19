#!/usr/bin/python3

from common import *

if len(sys.argv) < 2:
    print('Usage: python rdbid.py <DID>')
    print('')
    print('  Read data by its hex-encoded identifier.')
    print('')
    print('E.g.   python rdbid.py 00 08')
    sys.exit(0)

did = int(''.join(sys.argv[1:]), 16)

# Read data by identifier.
reply = sendrecv(socket(), bytes([ 0x22 ]) + p16(did))
assert_not_nrc(reply)
data = getdata(reply).decode()
print(data)
