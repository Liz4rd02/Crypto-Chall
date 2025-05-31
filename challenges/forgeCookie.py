import os
os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'
from pwn import *
import json
import base64

HOST = "130.192.5.212" 
PORT = 6521

server = remote(HOST, PORT)
message = server.recvline()
print(message.decode())

name = "matteo"
server.sendline(name.encode())

tokenJson = server.recvline()
print(tokenJson.decode())

response_token = server.recvline()
print(response_token.decode())
originalToken = response_token.decode().split(":")[1].strip()
print(originalToken)

nonce_b64, enc_token_b64 = originalToken.split(".")
nonce = base64.b64decode(nonce_b64)
enc_token = base64.b64decode(enc_token_b64)
print(f"nonce: {nonce}")
print(f"Encrypted token: {enc_token}")

#can reuse nonce -> same keystream will be used and xored with {"username": "matteo"}
#{"username": "matteo"} -> 
#{"admin": true}
#enc(m) xor m xor a = m xor k xor m xor a 

myTokenJson_byte = json.dumps({"admin": True}).encode()
originalTokenJson_byte = json.dumps({"username": "matteo"}).encode()

edt_enc_token = bytearray(enc_token)
start_index = 2
end_index = 15

for i in range(start_index, end_index):
    edt_enc_token[i] ^= myTokenJson_byte[i] ^ originalTokenJson_byte[i]



new_token = f"{nonce_b64}.{base64.b64encode(edt_enc_token[:end_index]).decode()}"
print(f"\nNew token: {new_token}\n")

menu_data = server.recvuntil(b'> ')
print(menu_data.decode())

server.sendline(b"flag")
server.recvuntil(b'> ')
server.sendline(new_token.encode())

final = server.recvuntil(b"}").decode()
print(final)
server.close()
#print(message.decode().splitlines()[0])