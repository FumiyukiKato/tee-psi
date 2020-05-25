import os
import json
import urllib.request
import ssl
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib
import random
import datetime

ssl._create_default_https_context = ssl._create_unverified_context

def gen_rand_geohash(length):
    geohash = [''] * 32
    base32 = '0123456789bcdefghjkmnpqrstuvwxyz'
    for i in range(length):
        r = random.randint(0, 31)
        geohash[i] = base32[r]
        
    return ''.join(geohash)

def gen_rand_timestamp():
    start = datetime.datetime(2020, 3, 1)
    end = datetime.datetime(2020, 5, 30)
    dt = random.random() * (end - start) + start
    return str(int(dt.timestamp()))

def generateMergeByteData(timestamp, geohash):
    timestamp = timestamp.encode()
    geohash = geohash.encode()
    return timestamp + geohash

def aesgcmEncrypt(byte, key, nonce):
    mac_len = 16
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=mac_len)
    ciphertext, tag = cipher.encrypt_and_digest(byte)
    return ciphertext, tag

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

input_secret_key = input("input Secret key as hex string (16bytes): ")
secret_key = bytes.fromhex(input_secret_key)
print("iv is (12bytes) => 000000000000")
nonce = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' # initial vector
num = 10
print("generate %d data" % num)
data_list = []
for i in range(num):
    timestamp = gen_rand_timestamp()
    geohash = gen_rand_geohash(9)
    mergedData = generateMergeByteData(timestamp, geohash)
    data_list.append(mergedData)

print(data_list)

byte = b''.join(data_list)
print(byte)
ciphertext, tag = aesgcmEncrypt(byte, secret_key, nonce)
print("ciphertext hex: ", ciphertext.hex())
print("tag hex: ", tag.hex())

b_ciphertext = str(b64encode(ciphertext).decode('utf-8'))
b_tag = str(b64encode(tag).decode('utf-8'))
print("base64 ciphertext: ", b_ciphertext)
print("base64 tag: ", b_tag)


## Encrypt SecretKey with SessionKey
session_key = bytes.fromhex(shared_key)

byte = secret_key
cipher_secret_key, secret_key_gcm_tag = aesgcmEncrypt(byte, session_key, nonce)
print("encrypted secret key as hex: ", cipher_secret_key.hex())
print("secret key gcm tag as hex: ", secret_key_gcm_tag.hex())

b_secret_key = str(b64encode(cipher_secret_key).decode('utf-8'))
b_secret_key_tag = str(b64encode(secret_key_gcm_tag).decode('utf-8'))
print("base64 encrypted secret key: ", b_secret_key)
print("base64 secret key gcm tag: ", b_secret_key_tag)

# report_infection

report_infection_url = 'https://133.3.250.176/report_infection?auth_token=B0702B28101BFCAA36965C6338688530'
headers = {
    'Content-Type': 'application/json',
}
data = {
    'user_id': 'katokato',
    'secret_key': b_secret_key,
    'gcm_tag': b_secret_key_tag,
    'session_token': session_token
}
req = urllib.request.Request(report_infection_url, json.dumps(data).encode(), headers, method='GET')
with urllib.request.urlopen(req) as res:
    body = json.load(res)
    print(body)
