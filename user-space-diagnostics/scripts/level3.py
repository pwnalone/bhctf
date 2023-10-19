#!/usr/bin/python3

from common import *

s = socket()

seed = getseed(s, 3)
if not seed:
    print('Already authenticated to security access level 3')
    sys.exit(0)

# The key is computed from the following set of bit manipulations.
# See lines 145-149 of the `UDSHandler` function in image.bin.gzf.
key = [ 0 ] * 4
key[1] = ((seed[1] + (seed[2] ^ seed[1]) ^ 0xed) - (seed[2] << 4)) & 0xff
key[0] = ((seed[0] + (seed[3] ^ seed[0]) ^ 0xfe) - (seed[3] << 4)) & 0xff
key[2] = ((seed[2] + (seed[1] ^ seed[3]) ^ 0xfa) - (seed[1] << 4)) & 0xff
key[3] = ((seed[3] + (seed[0] ^ seed[2]) ^ 0xce) - (seed[0] << 4)) & 0xff
data = sendkey(s, 3, bytes(key))

print(data.decode())
