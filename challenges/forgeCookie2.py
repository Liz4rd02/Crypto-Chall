# username=aaaaaaa | truepppppppppppp | aaaaaaaaa&admin= | falseppppppppppp





from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'
from pwn import *
import json
import base64

HOST = "130.192.5.212"
PORT = 6552

server = remote(HOST, PORT)
server2 = remote(HOST, PORT)

name = b"a"*7 + pad( b'true', AES.block_size) + b"a"*9
server.sendlineafter(b"Username: ", name)

cookie1_b = server.recvline().strip()
cookie_int1 = int(cookie1_b)
cookie_bytes1 = long_to_bytes(cookie_int1)
print(f"Cookie1: {cookie_bytes1}, {len(cookie_bytes1)} bytes long")

message = server.recvuntil(b"> ")
print(message.decode())

server.sendline(b"flag")
question = server.recvuntil(b'Cookie: ')
print(question.decode())

adminCookie = cookie_bytes1[:16] + cookie_bytes1[32:48] + cookie_bytes1[16:32]

print(f"My cookie is: {adminCookie}, Len: {len(adminCookie)}")
adminCookie_long = bytes_to_long(adminCookie)
adminCookie_b = str(adminCookie_long).encode()
print(f"Admin Cookie long (as integer): {adminCookie_b}")
server.sendline(adminCookie_b)

result = server.recvline()
print(result.decode())

server.close()


