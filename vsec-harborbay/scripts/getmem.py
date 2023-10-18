#!/usr/bin/python3

from common import *

if len(sys.argv) != 3:
    print('Usage: python getmem.py <addr> <size>')
    print('')
    print('  Read <size> bytes from <addr> and dump them to stdout.')
    print('')
    print('E.g.   python getmem.py 0xC3F80000 16')
    sys.exit(0)

addr = int(sys.argv[1], 16)
size = int(sys.argv[2], 10)

sys.stdout.buffer.write(readmem(socket(), addr, size))
