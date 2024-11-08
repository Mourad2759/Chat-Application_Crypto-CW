import socket
import threading
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import hashlib
import base64

# Server configuration
HOST = '127.0.0.1'
PORT = 12345

# AES Encryption
aes_key = get_random_bytes(16)

# SHA-256 hash function for password hashing
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Utility functions for encryption/decryption
def encrypt_message(message, aes_key):
    cipher = AES.new(aes_key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(message.encode('utf-8'))
    return base64.b64encode(nonce + tag + ciphertext).decode('utf-8')

def decrypt_message(encrypted_message, aes_key):
    data = base64.b64decode(encrypted_message)
    nonce = data[:16]
    tag = data[16:32]
    ciphertext = data[32:]
    cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')

def receive_messages(client_socket):
    while True:
        try:
            encrypted_message = client_socket.recv(1024).decode('utf-8')
            message = decrypt_message(encrypted_message, aes_key)
            print(message)
        except:
            print("[ERROR] Connection closed by server.")
            break

def main():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((HOST, PORT))

    # Send username and password for authentication
    username = input("Enter your username: ")
    password = input("Enter your password: ")

    client_socket.send(username.encode())
    client_socket.send(password.encode())

    # Receive server response
    response = client_socket.recv(1024).decode('utf-8')
    print(response)
    if response == "Invalid credentials.":
        client_socket.close()
        return

    # Receive RSA public key
    public_key_data = client_socket.recv(1024)
    try:
        rsa_public_key = RSA.import_key(public_key_data)
    except ValueError as e:
        print("Failed to load RSA public key:", e)
        client_socket.close()
        return

    rsa_cipher = PKCS1_OAEP.new(rsa_public_key)

    # Encrypt AES key and send to server
    encrypted_aes_key = rsa_cipher.encrypt(aes_key)
    client_socket.send(encrypted_aes_key)

    # Start receiving messages
    threading.Thread(target=receive_messages, args=(client_socket,)).start()

    while True:
        message = input("You: ")
        encrypted_message = encrypt_message(message, aes_key)
        client_socket.send(encrypted_message.encode('utf-8'))

if __name__ == "__main__":
    main()
