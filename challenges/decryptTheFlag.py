import os
os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'
from pwn import *
from Crypto.Cipher import AES

HOST = "130.192.5.212" 
PORT = 6561

# in Python, variables passed as function arguments are treated as local inside the function unless you explicitly declare them global

server = remote(HOST, PORT)
#server.interactive()
server.recvuntil(b">")
server.sendline(b"0")
server.recvline()
flag_enc_hex = server.recvline().decode()
flag_enc_b = bytes.fromhex(flag_enc_hex)
print(f"Encrypted flag (hex): {flag_enc_hex}")
print(f"Encrypted flag (bytes): {flag_enc_b}")
print(len(flag_enc_b))

msg = b'A'*46
res = server.recvuntil(b"Do you want to encrypt something else? (y/n)")
print(res)
server.sendline(b"y")
server.recvuntil(b"What is the message? ")
server.sendline(msg)
enc_msg_hex = server.recvline().decode()
enc_msg_b = bytes.fromhex(enc_msg_hex)

keystream = bytearray(msg)
for i in range(46):
    keystream[i] = enc_msg_b[i] ^ msg[i]

print(f"Keystream: {keystream}")

flag = bytearray(msg)

for i in range(46):
    flag[i] = flag_enc_b[i] ^ keystream[i]

print(flag.decode())

server.close()