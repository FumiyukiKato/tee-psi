import os
import json
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib
import random


def aesgcmEncrypt(byte, key, nonce):
    mac_len = 16
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=mac_len)
    ciphertext, tag = cipher.encrypt_and_digest(byte)
    return ciphertext, tag    

def main():
    ## SessionKey
    input_secret_key = input("input Secret  key as hex string (16bytes): ")
    secret_key = bytes.fromhex(input_secret_key)

    ## Encrypt SecretKey with SessionKey
    input_key = input("input Session key as hex string (16bytes): ")
    session_key = bytes.fromhex(input_key)

    byte = secret_key
    nonce = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' # initial vector
    cipher_secret_key, secret_key_gcm_tag = aesgcmEncrypt(byte, session_key, nonce)
    print("encrypted secret key as hex: ", cipher_secret_key.hex())
    print("secret key gcm tag as hex: ", secret_key_gcm_tag.hex())
    
    b_secret_key = str(b64encode(cipher_secret_key).decode('utf-8'))
    b_secret_key_tag = str(b64encode(secret_key_gcm_tag).decode('utf-8'))
    print("base64 encrypted secret key: ", b_secret_key)
    print("base64 secret key gcm tag: ", b_secret_key_tag)

main()