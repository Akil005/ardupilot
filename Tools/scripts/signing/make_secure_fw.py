#!/usr/bin/env python
import sys
import json, base64, zlib
from Crypto.Signature import DSS
from Crypto.PublicKey import ECC
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
import struct
import binascii

def to_unsigned(i):
    '''convert a possibly signed integer to unsigned'''
    if i < 0:
        i += 2**32
    return i
    
key_len = 32
#sig_len = 64
sig_len = 256
sig_version = 30437
descriptor = b'\x41\xa3\xe5\xf2\x65\x69\x92\x07'

#sign the image if key declared
if len(sys.argv) == 3:
    # open apj file
    apj = open(sys.argv[1],'r').read()
    # decode json in apj
    d = json.loads(apj)
    # get image data
    img = zlib.decompress(base64.b64decode(d['image']))
    img_len = len(img)
    #key = ECC.import_key(open(sys.argv[2], "r").read())
    key = RSA.import_key(open(sys.argv[2], "r").read())
    #descriptor = b'\x41\xa3\xe5\xf2\x65\x69\x92\x07'
    offset = img.find(descriptor)
    if offset == -1:
        print("No APP_DESCRIPTOR found")
        sys.exit(1)
    offset += 8
    desc_len = 92
    digest = SHA256.new(img[:offset] + img[offset+desc_len:])
    #signer = DSS.new(key, 'fips-186-3', encoding='der')
    signature = pkcs1_15.new(key).sign(digest)
    #signature = signer.sign(digest)

    siglen = to_unsigned(len(signature))
    print("MY RSA SIGNATURE LENGTH %d",len(signature))
    #signature += bytes(bytearray([0 for i in range(72 - len(signature))]))
    #signature += bytes(bytearray([0 for i in range(257 - len(signature))]))
    #pack signature in 4 bytes and length into 72 byte array
    #desc = struct.pack("<I72s", siglen, signature)
    desc = struct.pack("<IQ256s", sig_len+8, sig_version, signature)
    img = img[:(offset + 16)] + desc + img[(offset + desc_len):]
    print("offset",offset)
    print("desc",desc)
    print("desc_len",desc_len)
    print("sig_len",sig_len)
    print("img len",len(img))
    print("Applying APP_DESCRIPTOR Signature %d %s" % (siglen, binascii.hexlify(desc)))
    d["image"] = base64.b64encode(zlib.compress(img,9)).decode('utf-8')
    d["image_size"] = len(img)
    d["flash_free"] = d["flash_total"] - d["image_size"]
    d["signed_firmware"] = True
    f = open(sys.argv[1], "w")
    f.write(json.dumps(d, indent=4))
    f.close()
else:
    print("Usage: make_secure_fw.py <apj_file> <key_file>")
    sys.exit(1)