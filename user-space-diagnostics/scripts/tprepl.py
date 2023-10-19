#!/usr/bin/python3

from common import *

END = b'\x7f\x8c\x25\xab\xb6\x16\x1e\x94'

try:
    s = socket()
    while True:
        s.send(input('> ').encode())
        res = b''
        while not res.endswith(END):
            data = s.recv()
            if data:
                res += data
        res = res[:-8]
        print(res.decode())
except KeyboardInterrupt:
    print()
