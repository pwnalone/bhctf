# VSEC HarborBay

The [scripts](scripts) directory contains the scripts I used to solve all the challenges in the VSEC
HarborBay CTF category. Most of these challenges were simple enough to where you can understand the
solutions simply by reading the source code of these scripts.

Below, however, are writeups for _Security Access Level 3_ and _Security Access Level 1_.

## Security Access Level 3 Writeup

In this challenge, we are supposed to authenticate to security access level 3 _"using MAAATH"_.
While it's hard to know what kind of math the author(s) had in mind, the value we get when
requesting a seed for level 3 is only 16 bits, so, in the worst case scenario, we could probably
write a script to try many different things and see what produces valid keys. When I attempted this
challenge, I just tried a few things manually and quickly discovered that the key is computed as the
bitwise complement of the seed.

```py
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

def unlock(s):
    level3(s)
    level1(s)

unlock(socket())
```

The challenge description states that the flag is the key for seed 1337 in hex, so we just take the
bitwise complement and we have our solution.

**Flag:** `fac6`

## Security Access Level 1 Writeup

After authenticating to security access level 3, we have access to the programming diagnostic
session (0x02) and 8 KiB of memory starting at address `0x1a000`. Whenever we request a seed for
security access level 1, we'll notice that the seed is written to address `0x1ac00` and the key is
written to address `0x1ac08`. We could just read the key from memory every time we want to
authenticate to access level 1, but the challenge asks us for the key for a specific seed
(`7D0E1A5C`). Therefore, we need to figure out the relationship between the seeds and the keys. If
we generate several seeds and print their corresponding keys, there doesn't seem to be much of a
relation right away. However, if we xor each seed with its key, then we'll see that the result is
always `5539AA17`. Thus, the key for any seed is the seed xor-ed by this fixed "secret" value.

```py
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
```

**Flag:** `2837b04b`
