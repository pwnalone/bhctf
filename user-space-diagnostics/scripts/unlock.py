#!/usr/bin/python3

from mt19937predictor import MT19937Predictor
from common import *

def level1(s):
    seed = getseed(s, 1)
    if not seed:
        return
    # The key is the bitwise exclusive-or of the seed and 0x20202020.
    return sendkey(s, 1, p32(u32(seed) ^ 0x20202020))

def level3(s):
    seed = getseed(s, 3)
    if not seed:
        return
    # The key is computed via the following set of bit manipulations.
    key = [ 0 ] * 4
    key[1] = ((seed[1] + (seed[2] ^ seed[1]) ^ 0xed) - (seed[2] << 4)) & 0xff
    key[0] = ((seed[0] + (seed[3] ^ seed[0]) ^ 0xfe) - (seed[3] << 4)) & 0xff
    key[2] = ((seed[2] + (seed[1] ^ seed[3]) ^ 0xfa) - (seed[1] << 4)) & 0xff
    key[3] = ((seed[3] + (seed[0] ^ seed[2]) ^ 0xce) - (seed[0] << 4)) & 0xff
    return sendkey(s, 3, bytes(key))

def level5(s):
    seed = getseed(s, 5)
    if not seed:
        return
    N = 32
    # Seed the PRNG. Either 1 or 3 will work ...
    junk = getseed(s, 3)
    # Feed the predictor the first 624 outputs of the PRNG.
    predictor = MT19937Predictor()
    for _ in range(624):
        predictor.setrandbits(u32(getseed(s, 5)), N)
    # Get the next output, which should be used as the key.
    key = predictor.getrandbits(N)
    return sendkey(s, 5, p32(key))

def unlock(s):
    level1(s)
    level3(s)
    level5(s)

unlock(socket())
