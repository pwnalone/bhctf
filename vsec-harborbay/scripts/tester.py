#!/usr/bin/python3

from common import *

INTERVAL = 3

s = socket()
while True:
    # Send tester present service ID, periodically.
    assert_not_nrc(sendrecv(s, bytes([ 0x3e ])))
    time.sleep(INTERVAL)
