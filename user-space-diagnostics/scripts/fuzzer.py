#!/usr/bin/python3

from common import *

HEX_DIGITS = '0123456789abcdef'

if len(sys.argv) < 2:
    print('Usage: python fuzzer.py <fmt...>')
    print('')
    print('  Fuzz the UDS protocol.')
    print('')
    print('E.g.   python fuzzer.py 22 ?? 0?')
    sys.exit(0)

fmt = ' '.join(sys.argv[1:])
cnt = fmt.count('?')
fmt = fmt.replace('?', '{}')

s = socket()

def spaced(s, n):
    return ' '.join(s[i:i+n] for i in range(0, len(s), n))

for nibs in itertools.product(HEX_DIGITS, repeat=cnt):
    request = bytes(map(lambda x: int(x, 16), fmt.format(*nibs).split()))
    reply = sendrecv(s, request)
    print(spaced(request.hex(), 2), ' -> ', spaced(reply.hex(), 2))
