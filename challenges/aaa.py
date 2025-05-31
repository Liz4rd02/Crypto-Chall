#ACPA ECB

import os
os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'
from pwn import *
from Crypto.Cipher import AES#ACPA ECB


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

# Afffffffffffffff
# ffffffffffffffff
# fffffffffffffff
server = remote(HOST, PORT)

server.interactive()