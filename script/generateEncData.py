import os
import json
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib
import random

def gen_rand_geohash(length):
    geohash = [''] * 32
    base32 = '0123456789bcdefghjkmnpqrstuvwxyz'
    for i in range(length):
        r = random.randint(0, 31)
        geohash[i] = base32[r]
        
    return ''.join(geohash)

def gen_rand_timestamp():
    date = random.randint(1, 31)
    hour = random.randint(0, 24)
    minute = random.randint(0, 60)
    return "202005%sT%s%s00" % (str(date).zfill(2), str(hour).zfill(2), str(minute).zfill(2))

def generateMergeByteData(geohash, timestamp):
    geohash = geohash.encode()
    timestamp = timestamp.encode()
    return geohash + timestamp

def aesgcmEncrypt(byte, key, nonce):
    mac_len = 16
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=mac_len)
    ciphertext, tag = cipher.encrypt_and_digest(byte)
    return ciphertext, tag


def main():
    input_key = input("input key as hex string (16bytes): ")
    key = bytes.fromhex(input_key) # key
    print("key   is %s" % input_key)
    print("iv is (12bytes) => 000000000000")
    nonce = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' # initial vector
    num = 3
    print("generate %d data" % num)
    data_list = []
    for i in range(num):
        geohash = gen_rand_geohash(10)
        timestamp = gen_rand_timestamp()
        mergedData = generateMergeByteData(geohash, timestamp)
        data_list.append(mergedData)

    print(data_list)
    
    byte = b''.join(data_list)
    print(byte)
    ciphertext, tag = aesgcmEncrypt(byte, key, nonce)
    print("ciphertext hex: ", ciphertext.hex())
    print("tag hex: ", tag.hex())
    
    b_ciphertext = str(b64encode(ciphertext).decode('utf-8'))
    b_tag = str(b64encode(tag).decode('utf-8'))
    print("base64 ciphertext: ", b_ciphertext)
    print("base64 tag: ", b_tag)

#    tmpFileName = 'client-data.txt'
#    with open(tmpFileName, 'w') as f:
#        f.write(b_ciphertext)

main()