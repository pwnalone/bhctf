#!/usr/bin/python

from urllib.parse import quote
import hlextend
import sys

if len(sys.argv) != 4:
    print('Usage: python extend.py old-sig old-vin new-vin')
else:
    old_sig = sys.argv[1]
    old_vin =  b'vin=' + sys.argv[2].encode()
    new_vin = b'&vin=' + sys.argv[3].encode()
    sha256 = hlextend.new('sha256')
    new_query = sha256.extend(new_vin, old_vin, 16, old_sig)
    print('New Query =', quote(new_query, safe='/='))
    print('Signature =', sha256.hexdigest())
