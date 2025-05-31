#ACPA ECB

import os
os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'
from pwn import *
from Crypto.Cipher import AES

HOST = "130.192.5.212" 
PORT = 6541
len_flag = len("CRYPTO25{}") + 36

# AAAAAAAAAAAAAAAA  aaaaaaaaaaaggg  aaaaaaaaaagggg
# AAAAAAAAAAAAAAAA  gggggggggggggg  gggggggggggggg
# AAAAAAAAAAAAAAAg  gggggggggggggg  gggggggggggggg          3 - 6
# AAAAAAAAAAAAAAAA  aaaaaaaaaaafff  aaaaaaaaaaffff
# AAAAAAAAAAAAAAAA  ffffffffffffff  ffffffffffffff  
# AAAAAAAAAAAAAAAf  ffffffffffffff  ffffffffffffff  
# ffffffffffffffff  fppppppppppppp
# ffffffffffffffff
# fffppppppppppppp

postfix = b"A"*47
secret = b''
for i in range(len_flag):
    a=3
    b=6

    pad = (3*AES.block_size - i - 1 ) * b'A'
    for guess in string.printable:
        message = postfix + secret + guess.encode() + pad
        #print(message)

        server = remote(HOST, PORT)
        menu = server.recvuntil(b">")
        #print(menu.decode())
        server.sendline("enc")
        server.recvuntil(b">")
        server.sendline(message.hex().encode())
        ciphertext_hex = server.recvline().strip().decode()
        ciphertext = bytes.fromhex(ciphertext_hex)
        #print(message)
        #print(ciphertext)
        #print(len(ciphertext))
        server.close()
        #print((a,b))
        print(guess)
        #print(f"{(a-1)*AES.block_size} : {a*AES.block_size}")

        if ciphertext[(a-1)*AES.block_size:a*AES.block_size] == ciphertext[(b-1)*AES.block_size:b*AES.block_size]:
            print("Found=" + guess)
            secret+= guess.encode()
            postfix = postfix[1:]
            break

print(secret)
'CRYPTO25{96ce8a9000000000000000000000000000000'