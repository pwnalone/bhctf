#!/usr/bin/python3

from common import *

if len(sys.argv) != 3 and len(sys.argv) != 4:
    print('Usage: python getmem.py <addr> <size> [<file>]')
    print('')
    print('  Read <size> bytes from <addr> and dump them to <file> (or stdout).')
    print('')
    print('E.g.   python getmem.py 0x00400000 1048576 image.bin')
    print('E.g.   python getmem.py 0xC0FFE000 4096')
    sys.exit(0)

addr = int(sys.argv[1], 16)
size = int(sys.argv[2], 10)

s = socket(timeout=5)

if len(sys.argv) == 3:
    sys.stdout.buffer.write(readmem(s, addr, size))
else:
    with open(sys.argv[3], 'wb') as file:
        readmem(s, addr, size, file)
