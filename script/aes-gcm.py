import json
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


def test(geohash):
    print("#############################")
    key = bytes.fromhex('1234567890abcdef1234567890abcdef')
    nonce = bytes.fromhex('00000000000000000000000000000000')
    mac_len = 16
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=mac_len)
    ciphertext, tag = cipher.encrypt_and_digest(geohash)
    
    print("plain", str(geohash))
    print("key: ", str(key.hex()))
    print("ciphertext: ", str(ciphertext.hex()))
    print("tag: ", str(tag.hex()))

    print("base64 key: ", str(b64encode(key).decode('utf-8')))
    print("base64 ciphertext: ", str(b64encode(ciphertext).decode('utf-8')))
    print("base64 tag: ", str(b64encode(tag).decode('utf-8')))


    dec_cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=mac_len)
    plaintext = dec_cipher.decrypt_and_verify(ciphertext, tag)
    print("The message was: " + str(plaintext))
    print("#############################\n")


def main():
    while True:
        val = input("input raw value: ")
        test(val.encode())

main()
