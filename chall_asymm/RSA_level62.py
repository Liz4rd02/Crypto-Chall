from Crypto.Util.number import long_to_bytes, bytes_to_long
from math import gcd
from random import randint

import os
os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'
from pwn import *


HOST = "130.192.5.212"
PORT = 6646

server = remote(HOST, PORT)

e = 65537

#server sends number as str(num).encode()
c = int(server.recvline().strip())
#print(c)



s = 3
server.sendline(b'e' + str(s).encode())
s_enc = int(server.recvline().strip()) #2^e mod n
print(f"2^e (mod n): {s_enc}")

s2 = 2
server.sendline(b'e' + str(s2).encode())
s2_enc = int(server.recvline().strip()) #2^e mod n
print(f"3^e (mod n): {s_enc}")

x = s**e - s_enc #s^e - (s^e - k1*n) = k1*n 
y = s2**e - s2_enc #s2^e - (s2^e - k2*n) = k2*n 
n = gcd(x, y) #gcd(k1*n, k2*n) = n
print(n)

c2 = (s_enc * c) % n
server.sendline(b'd' + str(c2).encode())
sm = int(server.recvline().strip())

gcd = gcd(s, n)
print(gcd) #1
inv_s = pow(s, -1, n) 
m = (sm * inv_s) % n
m = long_to_bytes(m)
print(m) 