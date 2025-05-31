from Crypto.Util.number import long_to_bytes, bytes_to_long
from math import gcd
from random import randint

import os
os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'
from pwn import *


HOST = "130.192.5.212"
PORT = 6645

server = remote(HOST, PORT)

e = 65537

#server sends number as str(num).encode()
n = int(server.recvline().strip())
#print(n)
c = int(server.recvline().strip())
#print(c)

#Chosen Ciphertext Attack
#c=m^e (mod n)
#send r^e C (mod n)
#receive (r^e C)^d mod n = r C^d = r m
#get m = rm * r^-1 (mod n)

while True:
    r = randint(2, n-1)
    if gcd(r, n) == 1:
        break
#modular inverse exists iff gcd(r, n) = 1.

c2 = (pow(r, e, n) * c) % n
server.sendline(b'd' + str(c2).encode())
rm = int(server.recvline().strip())
inv_r = pow(r, -1, n) 
m = (rm * inv_r) % n
m = long_to_bytes(m)
print(m) 