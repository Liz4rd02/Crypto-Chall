#ACPA ECB

import os
os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'
from pwn import *
from Crypto.Cipher import AES

HOST = "130.192.5.212" 
PORT = 6542
len_flag = len("CRYPTO25{}") + 36
                                                                                #43
# PPPPPAAAAAAAAAAA  PPPPPaaaaaaggg  PPPPPaaaaagggg                      PPPPPggggggggggg    PPPPP(cut 3)gggg
# AAAAAAAAAAAAAAAA  gggggggggggggg  gggggggggggggg                      gggggggggggggggg    gggggggggggggggg
# AAAAAAAAAAAAAAAg  gggggggggggggg  gggggggggggggg          3 - 6       gggggggggggggggg    gggggggggggggggg
# AAAAAAAAAAAAAAAA  aaaaaaaaaaafff  aaaaaaaaaaffff                      aaaaafffffffffff    aaffffffffffffff
# AAAAAAAAAAAAAAAA  ffffffffffffff  ffffffffffffff                      ffffffffffffffff    ffffffffffffffff
# AAAAAAAAAAAAAAAf  ffffffffffffff  ffffffffffffff                      ffffffffffffffff    ffffffffffffffff
# ffffffffffffffff  fppppppppppppp                                      fffppppppppppppp
# ffffffffffffffff                                                     
# fffppppppppppppp

#PPPPPdataffffffffffffffffffffffffffffffffffffffffffffff

# All printable characters
printable = string.printable

# Uppercase letters
uppercase = string.ascii_uppercase

# Filter out uppercase letters
filtered = ''.join(ch for ch in printable if ch not in uppercase)
print("Looking in this set: " + filtered)

postfix = b"A"*33 + b"CRYPTO25{"
secret = b''

for i in range(len_flag-9-1): #i know it ends with '}'
    a=3
    b=6
    pad = (3*AES.block_size - i - 1 -9) * b'A'
    for guess in filtered:
        
        message = postfix + secret + guess.encode() + pad
        #print(message)

        server = remote(HOST, PORT)
        menu = server.recvuntil(b">")
        #print(menu.decode())
        server.sendline(b"enc")
        server.recvuntil(b">")
        server.sendline(message.hex().encode())
        ciphertext_hex = server.recvline().strip().decode()
        ciphertext = bytes.fromhex(ciphertext_hex)
        #print(message)
        #print(ciphertext)
        #print(len(ciphertext))
        server.close()
        #print((a,b))
        #print(guess)
        #print(f"{(a-1)*AES.block_size} : {a*AES.block_size}")

        if ciphertext[(a-1)*AES.block_size:a*AES.block_size] == ciphertext[(b-1)*AES.block_size:b*AES.block_size]:
            print("Found=" + guess)
            secret+= guess.encode()
            print(secret)
            postfix = postfix[1:]
            break

print("CRYPTO25{" + secret + "")
