#!/usr/bin/python3

from common import *

def level3(s):
    # Request an extended diagnostic session.
    reply = sendrecv(s, bytes([ 0x10, 0x03 ]))
    assert_not_nrc(reply)
    # Send seed request for security access level 3.
    reply = sendrecv(s, bytes([ 0x27, 0x03 ]))
    assert_not_nrc(reply)
    val = get_data(reply)
    # The key is the bitwise complement of the seed.
    key = p16(~u16(val) & 0xffff)
    # Send the key.
    reply = sendrecv(s, bytes([ 0x27, 0x04 ]) + key)
    assert_not_nrc(reply)

def level1(s):
    # Request a programming session.
    reply = sendrecv(s, bytes([ 0x10, 0x02 ]))
    assert_not_nrc(reply)
    # Send seed request for security access level 1.
    reply = sendrecv(s, bytes([ 0x27, 0x01 ]))
    assert_not_nrc(reply)
    val = get_data(reply)
    # The key is the bitwise exclusive-or of the seed and 0x5539aa17.
    key = xorbytes(val, p32(0x5539aa17))
    # Send the key.
    reply = sendrecv(s, bytes([ 0x27, 0x02 ]) + key)
    assert_not_nrc(reply)

def unlock(s):
    level3(s)
    level1(s)

unlock(socket())
