import os
os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'
from pwn import *

HOST = "130.192.5.212" 
PORT = 6532

def extractCiphertext(output):
    lines = output.splitlines()

    for line in lines:
        if line.startswith("Output"):
            ciphertext = line.split(":")[1].strip()
            break

    return ciphertext


def guess_mode(otp_hex1, otp_hex2):
    if bytes.fromhex(otp_hex1) == bytes.fromhex(otp_hex2):
        return "ECB"
    return "CBC"

    

server = remote(HOST, PORT)

for i in range(128):
    message = server.recvuntil(b"Input: ")
    print(message.decode())

    zeros = b"\00"*32
    zeros_hex = zeros.hex()
    server.sendline(zeros_hex.encode())

    output = server.recvline()
    print(output.decode())

    otp_hex = extractCiphertext(output.decode())
    print(otp_hex)

    message = server.recvuntil(b"Input: ")
    print(message.decode())

    server.sendline(zeros_hex.encode())

    output2 = server.recvline()
    print(output2.decode())

    otp_hex2 = extractCiphertext(output2.decode())
    print(otp_hex2)

    output = server.recvuntil(b"What mode did I use? (ECB, CBC)\n")
    print(output.decode())

    guess = guess_mode(otp_hex, otp_hex2)

    print(guess)
    server.sendline(guess.encode())

    result = server.recv(1024)
    print(f"Round {i+1}/128: {result.decode().strip()}")

final = server.recvall().decode()
print(final)
