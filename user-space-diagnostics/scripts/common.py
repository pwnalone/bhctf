#!/usr/bin/python3

import isotp
import itertools
import struct
import sys
import time

DEBUG = False

DATA_OFFS = {
    0x62 : 3,
    0x63 : 1,
    0x67 : 2,
    0x71 : 4,
    0x74 : 2,
    0x76 : 2,
    0x7f : 0,
    }

RT_CTL_START  = 1
RT_CTL_STOP   = 2
RT_CTL_STATUS = 3

READ_MEMORY_MAX_SIZE = 0x800

p16, u16 = lambda x: struct.pack('>H', x), lambda x: struct.unpack('>H', x)[0]
p32, u32 = lambda x: struct.pack('>I', x), lambda x: struct.unpack('>I', x)[0]
p64, u64 = lambda x: struct.pack('>Q', x), lambda x: struct.unpack('>Q', x)[0]

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

def getdata(reply):
    return reply[DATA_OFFS[reply[0]]:]

def readmem(s, addr, size, f=None):
    dump = b''
    step = READ_MEMORY_MAX_SIZE
    while step > 0:
        step = min(step, size)
        reply = sendrecv(s, bytes([ 0x23, 0x44 ]) + p32(addr) + p32(step))
        # 0x22 = Conditions Not Correct (e.g. need to authenticate)
        # 0x31 = Request Out Of Range   (e.g. invalid memory)
        if reply and reply == b'\x7f\x23\x22':
            break
        if reply and reply != b'\x7f\x23\x31':
            if f:
                f.write(reply)
            else:
                dump += reply
            addr  += step
            size  -= step
        else:
            step //= 2
    return dump

def getseed(s, level):
    request  = bytes([ 0x27, level + 0 ])
    reply = sendrecv(s, request)
    assert_not_nrc(reply)
    data = getdata(reply)
    if data != b'\0\0':
        return data
    else:
        return None

def sendkey(s, level, key):
    request  = bytes([ 0x27, level + 1 ])
    request += key
    reply = sendrecv(s, request)
    data = getdata(reply)
    if data and data[0] != 0x7f:
        return data
    else:
        return None

def rtctl(s, rid, action, no_return=False):
    reply = sendrecv(s, bytes([ 0x31, action ]) + p16(rid))
    if no_return and not reply:
        return
    assert_not_nrc(reply)
    return getdata(reply)
