import random
from locust import HttpUser, task, between
import os
import json
import ssl
from base64 import b64encode
from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib
import datetime


class QuickstartUser(HttpUser):
    wait_time = between(1, 2)

    def ra_mock(self):
        self.client.headers['Content-Type'] = "application/json"
        with self.client.get("/remote_attestation_mock", catch_response = True, verify=False) as response:
            body = response.json()
            session_token = body["session_token"]
            shared_key = body["shared_key"]
            print("session_token: ", session_token)
            print("shared_key: ", shared_key)
            return session_token, shared_key

    @task
    def judge_contact(self):
        session_token, shared_key = self.ra_mock()
        nonce = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' # initial vector
        session_key = bytes.fromhex(shared_key)
        self.client.headers['Content-Type'] = "application/json"
        b_secret_key, b_secret_key_tag = encrypt('B0702B28101BFCAA36965C6338688530', shared_key, nonce, session_key)
        data = {
            'user_id': 'katokato',
            'secret_key': b_secret_key,
            'gcm_tag': b_secret_key_tag,
            'session_token': session_token,
            'mock_file': '../data/client-data-4000.json'
        }
        with self.client.get("/judge_contact", catch_response = True, verify=False, json=data) as response:
            if response.status_code != 200:
                response.failure("failed")
            body = response.json()
            print(body)
            session_key = bytes.fromhex(shared_key)
            result = aesgcmDecrypt(b64decode(body['risk_level']), b64decode(body['gcm_tag']), session_key, nonce)
            print("decrypted result: %s" % result.hex())

def encrypt(secret_key, shared_key, nonce, session_key):
    input_secret_key = secret_key
    secret_key = bytes.fromhex(input_secret_key)
    byte = secret_key
    cipher_secret_key, secret_key_gcm_tag = aesgcmEncrypt(byte, session_key, nonce)
    b_secret_key = str(b64encode(cipher_secret_key).decode('utf-8'))
    b_secret_key_tag = str(b64encode(secret_key_gcm_tag).decode('utf-8'))
    return b_secret_key, b_secret_key_tag

def aesgcmEncrypt(byte, key, nonce):
    mac_len = 16
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=mac_len)
    ciphertext, tag = cipher.encrypt_and_digest(byte)
    return ciphertext, tag

def aesgcmDecrypt(code, tag, key, nonce):
    try:
        mac_len = 16
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=mac_len)
        plaintext = cipher.decrypt_and_verify(code, tag)
        return plaintext
    except ValueError:
        print("Incorrect decryption")