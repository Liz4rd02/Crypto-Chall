# length extension attack 
#Original (signed): username=mat&value=10
#New one:           username=mat&value=10<PADDING>&value=1000
import hashlib
import os
os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'
from pwn import *

def sha256_pad(message: bytes) -> bytes:
    original_length = len(message) * 8  + 16*8# length in bits (count also secret of 16 bytes)

    padded = message + b'\x80'
    while (len(padded) % 64) != 56:
        padded += b'\x00'

    padded += original_length.to_bytes(8, byteorder='big')

    return padded

def run_hash_extender(orig_mac, orig_msg, extra_data, key_len):
    result = subprocess.run([
        "hash_extender",
        "-s", orig_mac,
        "-d", orig_msg,
        "-a", extra_data,
        "-l", str(key_len),
        "-f", "sha256",
        "--data-format", "raw",
        "--append-format", "raw",
        "--out-data-format", "hex",
        "--out-signature-format", "hex"
    ], capture_output=True, text=True)

    new_sig, new_msg = None, None
    for line in result.stdout.splitlines():
        if line.startswith("New string:"):
            new_msg = line.split(":", 1)[1].strip()
        elif line.startswith("New signature:"):
            new_sig = line.split(":", 1)[1].strip()

    if not new_sig or not new_msg:
        raise ValueError("Hash extension failed. Output:\n" + result.stdout)

    return new_sig, new_msg

HOST = "130.192.5.212"
PORT = 6630

server = remote(HOST, PORT)
#server.interactive()

server.sendlineafter(b"Choose an option (1-3): ", b'1')
server.sendlineafter(b"Enter your name: ", b'mat')
server.recvuntil(b"Coupon: ")
msg_hex_bytes = server.recvline().strip()
server.recvuntil(b"MAC: ")
mac_bytes = server.recvline().strip()

print(msg_hex_bytes)
print(mac_bytes)

msg_bytes = bytes.fromhex(msg_hex_bytes.decode())
extra_data = b"&value=1000"

#Python’s hashlib always starts from an internal state initialized as if nothing has been hashed yet. 
#so doesn't work this way, when i initialize it with mac_bytes it doesn't actually start from that state
#padded_msg_bytes = sha256_pad(msg_bytes)

#h = hashlib.sha256(mac_bytes)
#h.update(extra_data)
#mac2=h.hexdigest()
#msg2_bytes = padded_msg_bytes + extra_data
#msg2_hex_bytes = msg2_bytes.hex().encode()

key_len = 16
mac2_hex, msg2_hex = run_hash_extender(mac_bytes.decode(), msg_bytes.decode(), extra_data.decode(), key_len)

server.sendlineafter(b"Choose an option (1-3): ", b'2')
server.sendlineafter(b"Enter your coupon: ", msg2_hex.encode())
server.sendlineafter(b"Enter your MAC: ", mac2_hex.encode())

server.recvuntil(b"Result: ")
result = server.recvline()
print(result)