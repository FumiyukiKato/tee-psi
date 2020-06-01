import os
import json
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib
import random
import datetime
import collections as cl

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
    nonce = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' # initial vector
    list_num = 450
    data_num = 100
    json_data = cl.OrderedDict()
    total_data_list = []
    for i in range(list_num):
        data_list = []
        for j in range(data_num):
            timestamp = gen_rand_timestamp()
            geohash = gen_rand_geohash(9)
            mergedData = generateMergeByteData(timestamp, geohash)
            data_list.append(mergedData)
        
        byte = b''.join(data_list)
        ciphertext, tag = aesgcmEncrypt(byte, secret_key, nonce)
        b_ciphertext = str(b64encode(ciphertext).decode('utf-8'))
        b_tag = str(b64encode(tag).decode('utf-8'))
        value = { "gps": b_ciphertext, "gcm_tag": b_tag }
        total_data_list.append(value)

    json_data["response"] = total_data_list

    filename = './data/client-data-%d.json' % (list_num*data_num)
    with open(filename, 'w') as f:
        json.dump(json_data, f, indent=4)

main()