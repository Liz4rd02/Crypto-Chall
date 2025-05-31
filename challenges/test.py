from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes
import json
import base64

# Define the key and nonce
key = get_random_bytes(32)  # Generate a random 32-byte key
nonce = get_random_bytes(12)  # Generate a random 12-byte nonce

# Encrypt the original JSON token
def encrypt_token(data, key, nonce):
    cipher = ChaCha20.new(key=key, nonce=nonce)
    encrypted_data = cipher.encrypt(data.encode())  # Encrypt the JSON string
    return encrypted_data

# Decrypt the encrypted token
def decrypt_token(encrypted_data, key, nonce):
    cipher = ChaCha20.new(key=key, nonce=nonce)
    decrypted_data = cipher.decrypt(encrypted_data)  # Decrypt the encrypted data
    return decrypted_data

# Original data (the token)
original_json = {"username": "matteo"}

# Convert the dictionary to a JSON string
original_data = json.dumps(original_json)

# Encrypt the original JSON token
encrypted_token = encrypt_token(original_data, key, nonce)

# Print the original token and encrypted token (for debugging)
print(f"Original JSON: {original_json}")
print(f"Encrypted token (in bytes): {encrypted_token}")

# Now, simulate what happens on the server: decrypt the token
decrypted_token = decrypt_token(encrypted_token, key, nonce)

# Print the decrypted token (this should match the original data)
print(f"Decrypted token (before modification): {decrypted_token.decode()}")

# Now, let's modify the encrypted token to change "username" to "admin"
# Example modification: Replace the bytes for 'username' with 'admin'
originalTokenJson_byte = original_data.encode()
myTokenJson_byte = json.dumps({"admin": True}).encode()

modified_encrypted_token = bytearray(encrypted_token)

start_index = 2
end_index = 15

for i in range(start_index, end_index):
    modified_encrypted_token[i] ^= myTokenJson_byte[i] ^ originalTokenJson_byte[i]

# Decrypt the modified token
decrypted_modified_token = decrypt_token(modified_encrypted_token[:end_index], key, nonce)

# Try to decode it as UTF-8. If it fails, print the raw bytes for inspection.
try:
    print(f"Decrypted token (after modification): {decrypted_modified_token.decode()}")
except UnicodeDecodeError:
    print(f"Decrypted token (after modification) is not valid UTF-8. Raw bytes:")
    print(decrypted_modified_token)
    # Optionally, print it in hexadecimal format for inspection
    print(decrypted_modified_token.hex())
