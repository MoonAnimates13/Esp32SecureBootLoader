from Crypto.Cipher import AES
import os

key = b'ThisIsASecretKey'  # 16-byte AES key
iv = os.urandom(16)

with open('whitelist.txt', 'rb') as f:
    data = f.read()
padded = data + b' ' * (16 - len(data) % 16)
cipher = AES.new(key, AES.MODE_CBC, iv)
enc = iv + cipher.encrypt(padded)

with open('whitelist.enc.bin', 'wb') as f:
    f.write(enc)
