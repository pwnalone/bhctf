# sadcarnoises

In this challenge, we're given a [WAV file](sadcarnoises.wav), which appears to be a 15-minute audio
recording of a bunch of cars crashing over and over again. Often times CTF challenges like to hide
data in the higher frequencies of audio files, but examining the spectrograph in [Sonic
Visualiser](https://sonicvisualiser.org/) doesn't reveal anything interesting.

![Audio Spectrograph](spectrograph.png)

Another common method of steganographically encoding data in media files involves replacing the
least-significant bit (LSB) of each frame or pixel with the data you want to hide. Using Python's
`wave` module, we can easily extract the metadata and frames of the audio recording.

```py
#!/usr/bin/python

import wave

f = wave.open('sadcarnoises.wav', 'rb')
meta = f.getparams()
data = f.readframes(32)
f.close()

print(meta)
print(data)
```

In this case, the audio file has 2 channels, 16-bit samples, a frame rate of 48 kHz, and ~43 million
frames. Python gives us the frame data as a string of bytes. Naturally, it would make sense to
extract the LSB of each sample, but doing so just gives us junk; however, taking the LSB of each
_byte_ of each sample (i.e. bits 0 and 8) yields a LUKS-encrypted file system image.

```py
#!/usr/bin/python

import wave

SIZE = 4096

def decode(data):
    s = ''.join(str(int(b & 1)) for b in data)
    return int(s, 2).to_bytes((len(s) + 7) // 8, byteorder='big')

with wave.open('sadcarnoises.wav', 'rb') as f:
    with open('sad.luks', 'wb') as g:
        while True:
            try:
                data = f.readframes(SIZE)
                g.write(decode(data))
            except ValueError:
                break
```

The challenge description gives us a hint of where to go next from here.

> Are you cewl? Do you not even care, not even a little bit? Then this one is for you.

[CeWL](https://www.kali.org/tools/cewl/) is a wordlist generator that works by scraping a website
for words that might be used as passwords. You can then pass this wordlist into a program like
Hashcat or JohnTheRipper (JTR) to crack password hashes. Before running this program, I checked with
the CTF moderators to make sure it was okay to run CeWL against their website, and they said it
should be fine as long as I kept it under 5 requests per second. By default, CeWL doesn't provide an
option to specify the desired rate limit, but we can apply a simple [patch](cewl.patch) to make sure
it doesn't go too fast.

```sh
cp /usr/bin/cewl . && patch < cewl.patch && ./cewl -v -d 5 --with-numbers -w wordlist https://blockharbor.io
```

This will take a while and will generate a wordlist of about 3,500 words. Unfortunately, the
encrypted file system image is using LUKS version 2, which neither Hashcat nor JTR supports as of
writing this, so we have to use `bruteforce-luks`, which is slower. On my Intel Core i7-10875H CPU,
it took about 2-3 hours to find the correct password.

```sh
bruteforce-luks -t 8 -v 1 -f wordlist sad.luks
```

With the password in hand, we can now decrypt the file system and mount it locally.

```sh
echo CyberSecuritySolutions | sudo cryptsetup open sad.luks sad
mkdir -p /mnt/sad
sudo mount /dev/mapper/sad /mnt/sad
```

Examining the decrypted file system, we find only a single file, `note.txt`, which contains the
string _"what the hell, where's the flag?"_. The flag obviously needs to be somewhere, so we can
guess that it is probably still present on the file system image, contained within a deleted file,
in the free space, or within the journal (since it's an ext4 file system). We could probably use
some fancy tools from [SleuthKit](https://sleuthkit.org/) to analyze the image, but I just ran
`strings` on it and searched for `bh{`, which was good enough to find the flag.

```sh
sudo strings /dev/mapper/sad | grep 'bh{'
```

**Flag:** `bh{n0t_ev3n_4_li77le_b1t}`
