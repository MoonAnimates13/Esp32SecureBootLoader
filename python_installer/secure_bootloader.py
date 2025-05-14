import hashlib, base64, os, subprocess
import serial.tools.list_ports
from Crypto.Cipher import AES

AES_KEY = b'ThisIsASecretKey'
BIN_FILE = '../whitelist/whitelist.enc.bin'

def decrypt_whitelist(enc):
    iv, data = enc[:16], enc[16:]
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    return cipher.decrypt(data).decode().strip()

def hash_password(pw):
    return hashlib.md5(pw.encode()).hexdigest()

def get_whitelist():
    with open(BIN_FILE, 'rb') as f:
        content = f.read()
    raw = decrypt_whitelist(content)
    return dict(line.split(":") for line in raw.splitlines())

def authenticate(user, pw):
    wl = get_whitelist()
    return user in wl and wl[user] == hash_password(pw)

def find_port():
    for p in serial.tools.list_ports.comports():
        if "USB" in p.description or "UART" in p.description:
            return p.device
    return None

def get_mac():
    result = os.popen("esptool.py chip_id").read()
    return result.strip().split()[-1][-17:]

def write_auth_blob(user, mac):
    data = base64.b64encode(f"AUTH::{user}::{mac}".encode())
    with open("auth_blob.bin", "wb") as f:
        f.write(data)

def flash_blob(port):
    subprocess.run(f"esptool.py --chip esp32 --port {port} --baud 460800 write_flash 0x10000 auth_blob.bin", shell=True)

if __name__ == "__main__":
    user = input("Username: ")
    pw = input("Password: ")
    if authenticate(user, pw):
        port = find_port()
        if not port:
            print("ESP32 not detected")
            exit(1)
        mac = get_mac()
        write_auth_blob(user, mac)
        flash_blob(port)
        print("✅ Secure bootloader flashed.")
    else:
        print("❌ Authentication failed.")
