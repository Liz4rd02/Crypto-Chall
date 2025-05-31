from Crypto.Util.number import long_to_bytes, bytes_to_long
from math import gcd
from random import randint

import os
os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'
from pwn import *

def print_bounds(low, up):
    print("[" + str(low) + "," + str(up) + "]")

HOST = "130.192.5.212"
PORT = 6647

server = remote(HOST, PORT)

e = 65537

#server sends number as str(num).encode()
n = int(server.recvline().strip())
#print(n)
c = int(server.recvline().strip())
#print(c)

#LSB oracle attack
upper_bound = n
lower_bound = 0
print_bounds(lower_bound,upper_bound)


# loop
m = c
for i in range(n.bit_length()):
    m = (pow(2, e, n) * m) % n

    # interact with the server
    server.sendline(str(m).encode())
    bit = server.recv(1024).strip()
    print(bit)
    # update bounds based on the leaked LSB
    if  int(bit) == 1:
        lower_bound = (upper_bound + lower_bound) // 2
    else:
        upper_bound = (upper_bound + lower_bound) // 2
    print_bounds(lower_bound, upper_bound)


#print decoded message
msg = long_to_bytes(lower_bound)
print(msg)