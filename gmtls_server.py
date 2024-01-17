import socket
import time
from gmssl import sm2, func
from gmssl.sm4 import CryptSM4, SM4_DECRYPT

def generate_sm2_public_key(private_key):
    sm2_crypt = sm2.CryptSM2(public_key='', private_key=private_key)
    g = sm2.default_ecc_table["g"]
    public_key = sm2_crypt._kg(int(private_key, 16), g)
    return public_key

def decrypt_data(encrypted_data, encrypted_key, sm2_crypt):
    dec_key = sm2_crypt.decrypt(encrypted_key)
    crypt_sm4 = CryptSM4()
    crypt_sm4.set_key(dec_key, SM4_DECRYPT)
    return crypt_sm4.crypt_ecb(encrypted_data)

MAX_BUFFER_SIZE = 1024 * 1024
private_key = func.random_hex(64)
public_key = generate_sm2_public_key(private_key)
sm2_crypt = sm2.CryptSM2(public_key=public_key, private_key=private_key)

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.settimeout(60)
server.bind(('127.0.0.1', 11223))
server.listen(1)

try:
    client, addr = server.accept()
    print(f"{addr} Client connected")
    client.send(public_key.encode())

    while True:
        encrypted_data = client.recv(MAX_BUFFER_SIZE)
        encrypted_key = client.recv(MAX_BUFFER_SIZE)
        if not encrypted_data:
            print('Connection error')
            break

        dec_data = decrypt_data(encrypted_data, encrypted_key, sm2_crypt)
        print(f"Decrypted data: {dec_data.decode()}")
        client.send(f"Received: {dec_data.decode()}".encode())

except Exception as e:
    print(f"Exception: {e}")
finally:
    server.close()
    print("Server connection closed")