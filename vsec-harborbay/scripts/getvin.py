#!/usr/bin/python3

from common import *

# Read data by identifier (0xf190 = VIN).
reply = sendrecv(socket(), bytes([ 0x22, 0xf1, 0x90 ]))
assert_not_nrc(reply)
print(get_data(reply).decode())
