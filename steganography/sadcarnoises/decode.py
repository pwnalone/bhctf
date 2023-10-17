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
