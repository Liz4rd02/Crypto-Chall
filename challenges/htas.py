import os
os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'
from Crypto.Cipher import AES
from pwn import *
import string

HOST = "130.192.5.212"
PORT = 6542
BLOCK_SIZE = AES.block_size
flag_known_prefix = b"CRYPTO25{"
len_flag = len(flag_known_prefix) + 36

filtered = ''.join(ch for ch in string.printable if ch in (string.digits + string.ascii_lowercase + "-"))

def get_ciphertext(data: bytes):
    s = remote(HOST, PORT)
    s.recvuntil(b">")
    s.sendline(b"enc")
    s.recvuntil(b">")
    s.sendline(data.hex().encode())
    ciphertext = bytes.fromhex(s.recvline().strip().decode())
    s.close()
    return ciphertext

# Step 1: Find padding offset
def find_offset():
    for i in range(32):  # Try up to 32 bytes of padding
        test = b"A" * i + b"B" * BLOCK_SIZE * 2
        ct = get_ciphertext(test)
        blocks = [ct[j:j+BLOCK_SIZE] for j in range(0, len(ct), BLOCK_SIZE)]
        for k in range(len(blocks)-1):
            if blocks[k] == blocks[k+1]:
                print(f"[+] Found repeating blocks at offset={i}, block={k}")
                return i, k
    raise Exception("[-] Couldn't find alignment")

offset, target_block = find_offset()
print(f"[*] Using offset: {offset}, target block: {target_block}")

# Step 2: Byte-by-byte decryption
known = b""
for i in range(len_flag - len(flag_known_prefix) - 1):
    pad_len = (BLOCK_SIZE - (len(known) + 1 + offset) % BLOCK_SIZE)
    payload = b"A" * (offset + pad_len)
    block_index = (len(payload) + len(known)) // BLOCK_SIZE

    ref_block = get_ciphertext(payload)[block_index*BLOCK_SIZE:(block_index+1)*BLOCK_SIZE]

    for c in filtered:
        guess = payload + known + c.encode()
        ct = get_ciphertext(guess)
        test_block = ct[block_index*BLOCK_SIZE:(block_index+1)*BLOCK_SIZE]
        if test_block == ref_block:
            known += c.encode()
            print(f"[+] Found: {known}")
            break

print(f"\n[!] Final flag: {flag_known_prefix.decode()}{known.decode()}}}")
