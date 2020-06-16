import ecdsa
from hashlib import sha256

user_id = input("input user_id: ")
# user_id = '936da01f9abd4d9d80c702af85c822a8'
timestamp = input("input timestamp: ")
# timestamp = '1591208843'
risk_level = input("input risk_level ('00' or '01'): ")
# risk_level = '00'

b_user_id = bytes.fromhex(user_id)
b_timestamp = timestamp.encode()
b_risk_level = bytes.fromhex(risk_level)

message = b_user_id + b_timestamp + b_risk_level

signature = input("input signature: ")
# signature = '6586320e7785bfd780b15e15b23cbd09a153147c6390052ca34d49a5a17e128b423e16b866874d86ead8ecf0d1bebc6ef193e3b20d6f14070b5a295fce35555e'

public_key = input("public key: ")
# public_key = '3dffed5a98360323042f14484f887999cf7f86971d7bc6b8e1d670e56377f3c91d42eb4ff3563d7bb8b8d4524b7867788fe989cc0761dbed4a068f9fb4e79833'

vk = ecdsa.VerifyingKey.from_string(bytes.fromhex(public_key), curve=ecdsa.NIST256p, hashfunc=sha256)

try:
    result = vk.verify(bytes.fromhex(signature), message)
    if result:
        print("[+] VERIFICATION SUCCES!!")
except ecdsa.keys.BadSignatureError as e:
    print("[-] VERIFICATION FAILED!!")

