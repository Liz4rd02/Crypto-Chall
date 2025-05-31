from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.Random import get_random_bytes
import binascii

# Simulate the server's behavior

key = get_random_bytes(32)  # Server key (same as in the original server)

def sanitize_field(field: str):
    return field \
        .replace("/", "_") \
        .replace("&", "") \
        .replace(":", "") \
        .replace(";", "") \
        .replace("<", "") \
        .replace(">", "") \
        .replace('"', "") \
        .replace("'", "") \
        .replace("(", "") \
        .replace(")", "") \
        .replace("[", "") \
        .replace("]", "") \
        .replace("{", "") \
        .replace("}", "") \
        .replace("=", "")

def build_cookie(username: str):
    cookie = f"username={username}&admin=false"
    return pad(cookie.encode(), AES.block_size)

def encrypt_cookie(cookie):
    cipher = AES.new(key, AES.MODE_ECB)
    return bytes_to_long(cipher.encrypt(cookie))

# Step 1: Build and encrypt the cookie with a normal username
username1 = "aaaaaaaaaaaaaaaa"  # 16-byte username
cookie1 = build_cookie(username1)
cookie_encrypted1 = encrypt_cookie(cookie1)
print(f"Encrypted Cookie1 (int): {cookie_encrypted1}")

c = str(cookie_encrypted1).encode()
c2 = c.strip()
c3 = int(c2)
print(c)
print(c2)
print(c3)



# Step 2: Build and encrypt the cookie with 'admin=true' in place of 'admin=false'
username2 = b"aaaaaaa" + pad( b'true', AES.block_size)  # Craft the second cookie to include 'true' after padding

#aaaaaaatrue\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c'
cookie2 = build_cookie(username2.decode())

cookie_encrypted2 = encrypt_cookie(cookie2)
print(f"Encrypted Cookie2 (int): {cookie_encrypted2}")

c4 = str(cookie_encrypted2).encode()
c5= c4.strip()
c6 = int(c5)


# Step 3: Now perform the attack (copy-paste attack) to combine parts of both cookies
print(long_to_bytes(c3))
print(long_to_bytes(cookie_encrypted1))
cookie1_bytes = long_to_bytes(c3)
cookie2_bytes = long_to_bytes(c6)

# Use the first part of cookie1 and the 'admin=true' part of cookie2
admin_cookie = cookie1_bytes[:32] + cookie2_bytes[16:32]  # Modify as per the attack
print(f"My cookie is: {admin_cookie}, Len: {len(admin_cookie)}")
adminCookie_long = bytes_to_long(admin_cookie)
adminCookie_b = str(adminCookie_long).encode()
print(f"Admin Cookie long (as integer): {adminCookie_b}")

cx= adminCookie_b.strip()
cx2 = int(cx)
print(cx2)
c_b = long_to_bytes(cx2)

# Step 4: Decrypt the admin cookie to see if it worked
cipher = AES.new(key, AES.MODE_ECB)
print(cipher.decrypt(c_b))
#username=aaaaaaa|aaaaaaaaa&admin=|aaatrue\\x0c\\x0c\\'
decrypted_admin_cookie = unpad(cipher.decrypt(c_b), AES.block_size).decode()
print(f"Decrypted Admin Cookie: {decrypted_admin_cookie}")

# Now, check what happens after you parse the cookie (simulating the server's behavior)
def parse_cookie(cookie_str: str):
    parsed = {}
    for field in cookie_str.split("&"):
        key, value = field.split("=")
        parsed[key.strip()] = value.strip()
    return parsed

token = parse_cookie(decrypted_admin_cookie)
print(f"Parsed Cookie: {token}")
