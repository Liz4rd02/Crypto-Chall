import requests
from Crypto.Util.number import long_to_bytes, bytes_to_long
import time

session = requests.Session()

url = 'http://130.192.5.212:6522'  

login_url = f'{url}/login'

params = {
    'username': 'testuser',
    'admin': 1
}

while(1):
    response = session.get(login_url, params=params)


    if response.status_code == 200:
        print("Login successful!")

        flag_url = f'{url}/flag'
        nonce = response.json()['nonce']
        cookie = response.json()['cookie']

        #print(f"Nonce: {nonce}")
        #print(f"Cookie: {cookie}")

        cookie_ciphertext = long_to_bytes(cookie)    #b"username=testuser&expires=expire_date&admin=1" xor keystream

        expires = int(time.time()) + 30 * 24 * 60 * 60
        cookie_plaintext = f"username=testuser&expires={expires}&admin=1".encode()

        #guess most of keystream except bytes in expires that are different (don't care)
        keystream = bytes([c ^ p for c, p in zip(cookie_ciphertext, cookie_plaintext)])

        modified_expires = expires + 140 * 24 * 60 * 60  #guess middle value around 125, sum 140 so that 30+125+140=290
        modified_cookie_pt = f"username=testuser&expires={modified_expires}&admin=1".encode()

        modified_ct = bytes([k ^ p for k, p in zip(keystream, modified_cookie_pt)])
        modified_cookie = bytes_to_long(modified_ct)
        
        flag_response = session.get(flag_url, params={'nonce': nonce, 'cookie': modified_cookie})

        print("Flag Response:", flag_response.text)
        if("OK" in  flag_response.text):
            break
    else:
        print("Login failed with status:", response.status_code)

    session.close()
    #keep trying until i get the right expires so that the diff is in (291,299)