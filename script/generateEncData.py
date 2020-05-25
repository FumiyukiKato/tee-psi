import os
import json
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib
import random
import datetime

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


def main():
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

main()