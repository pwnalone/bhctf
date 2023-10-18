#!/usr/bin/python3

import isotp
import struct
import sys
import time

DEBUG = False

DATA_OFFS = {
    0x59 : 3,
    0x62 : 3,
    0x63 : 1,
    0x67 : 2,
    }

READ_MEMORY_MAX_SIZE = 0x800

p16, u16 = lambda x: struct.pack('>H', x), lambda x: struct.unpack('>H', x)[0]
p32, u32 = lambda x: struct.pack('>I', x), lambda x: struct.unpack('>I', x)[0]
p64, u64 = lambda x: struct.pack('>Q', x), lambda x: struct.unpack('>Q', x)[0]

def xorbytes(a, b):
    return bytes(map(lambda x, y: x ^ y, a, b))

def socket(iface='vcan0', **kwargs):
    timeout = kwargs.get('timeout', 0.1)
    s = isotp.socket(timeout)
    rxid = kwargs.get('rxid', 0x7e8)
    txid = kwargs.get('txid', 0x7e0)
    s.set_ll_opts(**kwargs.get('ll_opts', dict()))
    s.set_fc_opts(**kwargs.get('fc_opts', dict(stmin=5, bs=10)))
    s.bind(iface, isotp.Address(rxid=rxid, txid=txid))
    return s

def sendrecv(s, request):
    s.send(request)
    return s.recv()

def assert_not_nrc(reply):
    assert(reply and reply[0] != 0x7f)

def get_data(reply):
    return reply[DATA_OFFS[reply[0]]:]

def readmem(s, addr, size):
    dump = b''
    step = min(READ_MEMORY_MAX_SIZE, size)
    while step > 0:
        reply = sendrecv(s, bytes([ 0x23, 0x24 ]) + p32(addr) + p16(step))
        if reply and reply[0] != 0x7f:
            dump  += get_data(reply)
            addr  += step
            size  -= step
            step   = min(step, size)
        else:
            step //= 2
    return dump
