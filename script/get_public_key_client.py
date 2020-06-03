import os
import json
import urllib.request
import ssl
from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib
import getopt
import sys

ssl._create_default_https_context = ssl._create_unverified_context

def aesgcmDecrypt(code, tag, key, nonce):
    try:
        mac_len = 16
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=mac_len)
        plaintext = cipher.decrypt_and_verify(code, tag)
        return plaintext
    except ValueError:
        print("Incorrect decryption")

# ra_mock
ra_mock_url = 'https://133.3.250.176/remote_attestation_mock?auth_token=B0702B28101BFCAA36965C6338688530'
headers = {
    'Content-Type': 'application/json',
}
req = urllib.request.Request(ra_mock_url, headers=headers, method='GET')
with urllib.request.urlopen(req) as res:
    body = json.load(res)
    session_token = body["session_token"]
    shared_key = body["shared_key"]

print("session_token: ", session_token)
print("shared_key: ", shared_key)

nonce = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' # initial vector

## Encrypt SecretKey with SessionKey
session_key = bytes.fromhex(shared_key)

# get_public_key
get_public_key_url = 'https://133.3.250.176/get_public_key?auth_token=B0702B28101BFCAA36965C6338688530'
headers = {
    'Content-Type': 'application/json',
}
data = {
    'session_token': session_token
}
req = urllib.request.Request(get_public_key_url, json.dumps(data).encode(), headers, method='GET')
with urllib.request.urlopen(req) as res:
    body = json.load(res)
    print(body)
    result = aesgcmDecrypt(b64decode(body['public_key']), b64decode(body['gcm_tag']), session_key, nonce)
    print("public_key: %s" % result.hex())