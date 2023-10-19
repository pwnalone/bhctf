#!/usr/bin/python3

from common import *
import hashlib

if len(sys.argv) != 2:
    print('Usage: python flash.py <exe>')
    print('')
    print('  Flash the firmware image saved in <exe> to the ECU.')
    print('')
    print('E.g.   python flash.py shell')
    sys.exit(0)

data  = open(sys.argv[1], 'rb').read()
data += hashlib.md5(data).digest()
size  = len(data)

s = socket()

#
# Initiate a firmware download.
#
# 0x34 = SID (Request Download)
# 0x00 = Data Format ID (no encryption / no compression)
# 0x41 = Address & Length ID (1-byte address / 4-byte size)
# 0x00 = Junk address since it's not used anyways
#
reply = sendrecv(s, bytes([ 0x34, 0x00, 0x41, 0x00 ]) + p32(size))
assert_not_nrc(reply)

# Transfer the firmware block-by-block.
seqn = 1
block_size = READ_MEMORY_MAX_SIZE
while size > 0:
    reply = sendrecv(s, bytes([ 0x36, seqn ]) + data[:block_size])
    assert_not_nrc(reply)
    seqn = (seqn + 1) & 0xff
    data = data[block_size:]
    size = size - block_size

# Routine a5a5 flashes the new firmware and executes it.
rtctl(s, 0xa5a5, RT_CTL_START, no_return=True)

print('Ready!')
