#!/bin/sh

curl -s -H 'Cookie: signature=cac53476985c5d01a17feded0be21b923f057a36260dada19493aa4b70b68a1f' \
    http://celsius.blockharbor.io:5800/vin/info\?vin\=1GTHC83G64B2F5VU8%80%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%01%28%26vin\=1337 \
        | grep -oE 'bh{[^}]+}'
