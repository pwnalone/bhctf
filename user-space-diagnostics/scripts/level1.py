#!/usr/bin/python3

from common import *

def broadcast(x, n):
    '''Broadcast byte `x` to all bytes in an `n`-byte integer.'''
    k = 8
    while n > 1:
        x  |= (x << k)
        n >>= 1
        k <<= 1
    return x

s = socket()

for x in range(256):
    seed = getseed(s, 1)
    if not seed:
        print('Already authenticated to security access level 1')
        sys.exit(0)
    data = sendkey(s, 1, p32(u32(seed) ^ broadcast(x, 4)))
    if data:
        print(data.decode())
        break
