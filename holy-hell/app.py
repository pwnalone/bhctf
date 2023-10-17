#!/usr/local/bin/python3
from hashlib import sha256
from urllib.parse import urlparse
from os import urandom
from time import time
from urllib.parse import unquote_to_bytes, quote
from binascii import hexlify, unhexlify
from flask import Flask, render_template, request, make_response
from vinGen import getRandomVin
from vindecoder import VINDecoder, InvalidVINException

_SECURE_BYTES = urandom(16)

with open("./flag.txt",'r') as fd:
    flag = fd.read().strip()

_vins = {b'1337':
    {'region': 'North America', 'country': 'United States', 'manufacturer': 'blockharbor', 'model': flag, 'check': True, 'year': 1337, 'assembly plant': '', 'serial': ''}
}

def lookup_vin(vin):
    return str(_vins[vin])

def calc_sig(data):
    if type(data) != bytes:
        data = data.encode()
    md = sha256(_SECURE_BYTES + data)
    return md.hexdigest()

def to_dct(data):
    _dct = {}
    try:
        data = data.split(b'&')
        for line in data:
            k,v = line.split(b'=')
            _dct[k] = v
    except Exception as e:
        pass
    return _dct

app = Flask(__name__)

@app.route('/')
def home():
    with open('frontend.html','r') as fd:
        return fd.read()

# super realistic application source leak
@app.route('/app')
def leak_app():
    with open("./run",'r') as fd:
        return fd.read()

@app.route('/vin/info',methods=['GET'])
def get_vin_info():

    query_string = request.query_string
    query_string = unquote_to_bytes(query_string)
    _set_sig     = request.cookies.get('signature')
    query_sig    = calc_sig(query_string)

    if query_sig != _set_sig:
        return "Invalid signature..."

    query_dict = to_dct(query_string)
    data = lookup_vin(query_dict[b'vin'])

    return data
        
@app.route('/vin/register',methods=['GET'])
def reg_vin():
    #Classic
    while True:
        try:
            vin = getRandomVin()
            decoder = VINDecoder()
            vin_data = decoder.decode(vin)
            break
        except KeyError:
            continue
    _vins[vin.encode()] = vin_data
    vin = 'vin=' + vin
    vin_sig = calc_sig(vin)
    response = make_response(vin)
    response.set_cookie('signature', vin_sig)
    return response

if __name__ == '__main__':
    app.run(host='0.0.0.0')
