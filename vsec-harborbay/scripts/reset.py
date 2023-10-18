#!/usr/bin/python3

from common import *

if len(sys.argv) > 2:
    print('Usage: python reset.py [kind]')
    sys.exit(0)

if len(sys.argv) > 1:
    kind = int(sys.argv[1])
else:
    kind = 1   # hard reset

s = socket()
broadcasts = socket(rxid=0x7df, timeout=5)
reply = sendrecv(s, bytes([ 0x11, kind ]))
assert_not_nrc(reply)
print(broadcasts.recv().decode())
