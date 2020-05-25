from base64 import b64decode
from Crypto.Cipher import AES

def aesgcmDecrypt(code, tag, key, nonce):
    try:
        mac_len = 16
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=mac_len)
        plaintext = cipher.decrypt_and_verify(code, tag)
        return plaintext
    except ValueError:
        print("Incorrect decryption")

def main():
    input_key = input("input key: ")
    key = bytes.fromhex(input_key)
    tag = input("input tag: ")
    code = input("input base64 code: ")
    nonce = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    result = aesgcmDecrypt(b64decode(code), b64decode(tag), key, nonce)
    print("result: %s" % result.hex())

main()