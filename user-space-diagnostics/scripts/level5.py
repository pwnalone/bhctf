#!/usr/bin/python3

from mt19937predictor import MT19937Predictor
from common import *

N = 32

s = socket()

# Seed the PRNG. Either 1 or 3 will work ...
getseed(s, 3)

# Feed the predictor the first 624 outputs of the PRNG.
predictor = MT19937Predictor()
for _ in range(624):
    seed = getseed(s, 5)
    if not seed:
        print('Already authenticated to security access level 5')
        sys.exit(0)
    predictor.setrandbits(u32(seed), N)

# Get the next output, which should be used as the key.
key = predictor.getrandbits(N)
data = sendkey(s, 5, p32(key))

print(data.decode())
