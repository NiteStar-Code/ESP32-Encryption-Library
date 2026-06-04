import base64
from Crypto.Cipher import AES

key = bytes.fromhex("df1784356d60546b1c649bb9d40e3ffae7e1c6ab700ded629d314bbd1d617773")

payload = input("Paste payload: ")
iv, tag, ct = [base64.b64decode(x) for x in payload.split(":")]

print(AES.new(key, AES.MODE_GCM, nonce=iv).decrypt_and_verify(ct, tag).decode())