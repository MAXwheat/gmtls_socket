import socket
import time
from gmssl import sm2, func
from gmssl.sm4 import CryptSM4, SM4_ENCRYPT
import hashlib

def create_key(data):
    md5 = hashlib.md5()
    md5.update(data.encode("utf-8"))
    return md5.hexdigest()[:16]

MAX_BUFFER_SIZE = 1024 * 1024
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.settimeout(30)
client.connect(('127.0.0.1', 11223))

public_key = client.recv(MAX_BUFFER_SIZE).decode()
sm2_crypt = sm2.CryptSM2(public_key=public_key, private_key='')

while True:
    inputData = input("Enter message (or 'quit' to stop): ")
    if inputData.lower() == "quit":
        break
    if not inputData:
        print("Please enter a message.")
        continue

    key = create_key(inputData).encode()
    crypt_sm4 = CryptSM4()
    crypt_sm4.set_key(key, SM4_ENCRYPT)
    encrypted_data = crypt_sm4.crypt_ecb(inputData.encode())
    encrypted_key = sm2_crypt.encrypt(key)
    client.send(encrypted_data)
    client.send(encrypted_key)

    response = client.recv(MAX_BUFFER_SIZE)
    if not response:
        print('Connection error')
        break

    print(f"Server response: {response.decode()}")

client.close()
print("Client connection closed")