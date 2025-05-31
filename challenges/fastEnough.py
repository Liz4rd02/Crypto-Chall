import os
os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'
from pwn import *
from Crypto.Cipher import AES

HOST = "130.192.5.212" 
PORT = 6562

# in Python, variables passed as function arguments are treated as local inside the function unless you explicitly declare them global

server = remote(HOST, PORT)
#server.interactive()
server.recvuntil(b"f)")
server.sendline(b"y")
server.recvuntil(b">")
msg = b"A"*46
server.sendline(msg)
msg_enc_hex = server.recvline().decode()
server.recvuntil(b"f)")
server.sendline(b"f")
flag_enc_hex = server.recvline().decode()
flag_enc_b = bytes.fromhex(flag_enc_hex)
msg_enc_b = bytes.fromhex(msg_enc_hex)

print(f"Encrypted msg (hex): {msg_enc_hex}")
print(f"Encrypted msg (bytes): {msg_enc_b}")

print(f"Encrypted msg (hex): {flag_enc_hex}")
print(f"Encrypted msg (bytes): {flag_enc_b}")


keystream = bytearray(msg)
for i in range(46):
    keystream[i] = msg_enc_b[i] ^ msg[i]

print(f"Keystream: {keystream}")

flag = bytearray(msg)

for i in range(46):
    flag[i] = flag_enc_b[i] ^ keystream[i]

print(flag.decode())

server.close()