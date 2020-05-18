import os
import json
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib
import random

def gen_rand_str_hex(length):
    buf = ''
    while len(buf) < length:
        buf += hashlib.md5(os.urandom(100)).hexdigest()
    return buf[0:length]

def gen_rand_timestamp():
    date = random.randint(1, 31)
    hour = random.randint(0, 24)
    minute = random.randint(0, 60)
    return "202005%sT%s%s00" % (date, str(hour).zfill(2), str(minute).zfill(2))

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
    key = bytes.fromhex('1234567890abcdef1234567890abcdef') # key
    nonce = bytes.fromhex('00000000000000000000000000000000') # initial vector
    num = 3
    data_list = []
    for i in range(num):
        geohash = gen_rand_str_hex(1000)
        timestamp = gen_rand_timestamp()
        mergedData = generateMergeByteData(geohash, timestamp)
        data_list.append(mergedData)
    
    byte = b''.join(data_list)
    ciphertext, tag = aesgcmEncrypt(byte, key, nonce)
    print("cipher text: ", ciphertext.hex())
    print("tag: ", tag.hex())

    b_key = str(b64encode(key).decode('utf-8'))
    b_ciphertext = str(b64encode(ciphertext).decode('utf-8'))
    b_tag = str(b64encode(tag).decode('utf-8'))
    print("base64 key: ", b_key)
    print("base64 ciphertext: ", b_ciphertext)
    print("base64 tag: ", b_tag)

    tmpFileName = 'client-data.txt'
    with open(tmpFileName, 'w') as f:
        f.write(b_ciphertext)

main()