import os
os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'
from pwn import *
import json
import base64

HOST = "130.192.5.212" 
PORT = 6523

server = remote(HOST, PORT)
menu = server.recvuntil(b">")
print(menu.decode())

zeros = b"\00"*16
zeros_hex = zeros.hex()
server.sendline(b"enc")
msg = server.recvline()
print(msg.decode())

server.sendline(zeros_hex.encode())

iv_hex = server.recvline().decode()
iv_hex = iv_hex.split(":")[1].strip()
print(iv_hex)
iv = bytes.fromhex(iv_hex)

encrypted_hex = server.recvline().decode()
encrypted_hex = encrypted_hex.split(":")[1].strip()
print(encrypted_hex)
#encrypted = bytes(encrypted_hex)

#enc(iv xor 0) = enc(iv) = c
#dec(c) xor iv2 = iv xor iv xor leak
#iv2 = iv xor leak

iv2 = bytearray(iv)
leak = b"mynamesuperadmin"
print(len(iv2))
print(len(leak))

for i in range(16):
    print(i)
    iv2[i] = iv[i] ^ leak[i]

print(len(iv2))
iv2_hex = iv2.hex()

menu = server.recvuntil(b">")
print(menu.decode())

server.sendline(b"dec")

msg = server.recvline()
print(msg.decode())
server.sendline(encrypted_hex.encode())

msg = server.recvline()
print(msg.decode())
server.sendline(iv2_hex.encode())

res = server.recvline()
print(res.decode())
