#!/usr/bin/python3

from common import *

# Report Diagnostics Trouble Codes (DTC) by status mask (0xff = full mask).
reply = sendrecv(socket(), bytes([ 0x19, 0x02, 0xff ]))
assert_not_nrc(reply)
print(get_data(reply).hex())
