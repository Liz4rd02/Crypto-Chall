import os
os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'
from pwn import *

HOST = "130.192.5.212" 
PORT = 6531

def extractOTPhex(message):
    # Split the text into lines
    lines = message.splitlines()

    # Look for the line that starts with "The otp I'm using:"
    for line in lines:
        if line.startswith("The otp I'm using:"):
            # Split on the colon and strip any extra whitespace
            otp_hex = line.split(":")[1].strip()
            break
    return otp_hex

def extractCiphertext(output):
    lines = output.splitlines()

    for line in lines:
        if line.startswith("Output"):
            ciphertext = line.split(":")[1].strip()
            break

    return ciphertext


def guess_mode(ciphertext):
    if ciphertext[:16] == ciphertext[16:]:
        return "ECB"
    return "CBC"

    

server = remote(HOST, PORT)

for i in range(128):
    message = server.recv(1024)
    print(message.decode().splitlines()[0])

    otp_hex = extractOTPhex(message.decode())

    plaintext = otp_hex
    #print(plaintext)
    server.sendline(plaintext.encode())

    output = server.recvuntil(b"What mode did I use? (ECB, CBC)\n")
    #print(output.decode())

    ciphertext_hex = extractCiphertext(output.decode())
    guess = guess_mode(bytes.fromhex(ciphertext_hex))

    #print(guess)
    server.sendline(guess.encode())

    result = server.recv(1024)
    print(f"Round {i+1}/128: {result.decode().strip()}")

final = server.recvall().decode()
print(final)
