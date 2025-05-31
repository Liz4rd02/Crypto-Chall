from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import os
os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'
from pwn import *
import json
import base64



HOST = "130.192.5.212"
PORT = 6551

server = remote(HOST, PORT)

# JUST FOR DEBUG 
key = get_random_bytes(32)

# {"username": "aa |                \ | "yoloo           |                 \| ":               |                , |             true | aaaa", "admin":  | false}pppppppppp

# {"username": "aa | aaaa", "admin":  |             true |                , | "yoloo           | ":               | false}pppppppppp                

name = b"a"*2 + b" "*11 + b"true}" + b"a"*4

name = b"a"*2 + b" "*15 + b'"' + b"yoloo" + b" "*10 + b" "*15 + b'":' + b" "*(14+15) + b"," + b" "*12 + b"true" + b"aaaa"

token = json.dumps({
        "username": name.decode(),
        "admin": False
    })

print(token.encode())
print(len(token))

for i in range(0, len(token), AES.block_size):
        block = token[i:i+AES.block_size]
        print(f"Block {i // AES.block_size:02}: {block}")

token2 = token[:16] + token[112:128] + token[96:112] + token[80:96] + token[32:48] + token[64:80] + token[128:134]
print(len(token2))

print("------------")
for i in range(0, len(token2), AES.block_size):
        block = token2[i:i+AES.block_size]
        print(f"Block {i // AES.block_size:02}: {block}")

cipher = AES.new(key=key, mode=AES.MODE_ECB)
enc_token2 = cipher.encrypt(pad(token.encode(), AES.block_size))
print(len(enc_token2))
#enc_token2 = enc_token2[:16] + enc_token2[128:144] + enc_token2[16:32] + enc_token2[32:128]
new_enc_token = enc_token2[:16] + enc_token2[112:128] + enc_token2[96:112] + enc_token2[80:96] + enc_token2[32:48] + enc_token2[64:80] + enc_token2[128:144]
print(len(new_enc_token))

cipher = AES.new(key=key, mode=AES.MODE_ECB)
dec_token = unpad(cipher.decrypt(new_enc_token), AES.block_size)

print(dec_token)
user = json.loads(dec_token)
print(user)

#------------------------------------------------------------------
#attack is here

name = b"a"*2 + b" "*15 + b'"' + b"yoloo" + b" "*10 + b" "*15 + b'":' + b" "*(14+15) + b"," + b" "*12 + b"true" + b"aaaa"
server.sendlineafter(b"> ", name)

server.recvuntil(b"This is your token: ")
cookie1_b64 = server.recvline().strip()
cookie1_b = base64.b64decode(cookie1_b64)
print(f"Cookie1: {cookie1_b}, {len(cookie1_b)} bytes long")

message = server.recvuntil(b"> ")
print(message.decode())

server.sendline(b"flag")
question = server.recvuntil(b'> ')
print(question.decode())

adminCookie = cookie1_b[:16] + cookie1_b[112:128] + cookie1_b[96:112] + cookie1_b[80:96] + cookie1_b[32:48] + cookie1_b[64:80] + cookie1_b[128:144]

print(f"My cookie is: {adminCookie}, Len: {len(adminCookie)}")
adminCookie_b64 = base64.b64encode(adminCookie)
print(adminCookie_b64)
server.sendline(adminCookie_b64)

result = server.recv(4096)
print(result.decode())

server.close()


