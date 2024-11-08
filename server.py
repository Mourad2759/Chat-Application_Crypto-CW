import socket
import threading
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
import base64
import hashlib
import os

# Server configuration
HOST = '127.0.0.1'
PORT = 12345
connected_clients = {}
credentials_file = "credentials.txt"

# Generate RSA key pair
rsa_key = RSA.generate(2048)
public_key = rsa_key.publickey().export_key()
private_cipher = PKCS1_OAEP.new(rsa_key)

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

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def load_credentials():
    credentials = {}
    if os.path.exists(credentials_file):
        with open(credentials_file, 'r') as file:
            for line in file:
                username, hashed_password = line.strip().split(':')
                credentials[username] = hashed_password
    return credentials

def save_credentials(username, hashed_password):
    with open(credentials_file, 'a') as file:
        file.write(f"{username}:{hashed_password}\n")

def authenticate_client(client_socket):
    client_socket.send("Username: ".encode())
    username = client_socket.recv(1024).decode('utf-8')
    client_socket.send("Password: ".encode())
    password = client_socket.recv(1024).decode('utf-8')
    
    hashed_password = hash_password(password)
    credentials = load_credentials()
    
    if username in credentials and credentials[username] == hashed_password:
        client_socket.send("Login successful.".encode())
        return username
    elif username not in credentials:
        save_credentials(username, hashed_password)
        client_socket.send("Account created successfully.".encode())
        return username
    else:
        client_socket.send("Invalid credentials.".encode())
        return None

def client_handler(client_socket, addr):
    try:
        username = authenticate_client(client_socket)
        if not username:
            client_socket.close()
            return

        # Send RSA public key for AES key exchange
        client_socket.send(public_key)
        
        # Receive AES key encrypted with public key
        encrypted_aes_key = client_socket.recv(256)
        aes_key = private_cipher.decrypt(encrypted_aes_key)
        
        connected_clients[username] = client_socket
        print(f"[NEW CONNECTION] {username} connected from {addr}")
        
        while True:
            encrypted_message = client_socket.recv(1024).decode('utf-8')
            message = decrypt_message(encrypted_message, aes_key)
            print(f"[{username}] {message}")
            
            # Broadcast the message to other clients with username
            for user, client in connected_clients.items():
                if client != client_socket:
                    full_message = f"{username}: {message}"
                    client.send(encrypt_message(full_message, aes_key).encode('utf-8'))
    except:
        print(f"[{addr}] Connection closed")
    finally:
        client_socket.close()
        del connected_clients[username]

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen()
    print(f"[SERVER] Server started on {HOST}:{PORT}")

    while True:
        client_socket, addr = server_socket.accept()
        threading.Thread(target=client_handler, args=(client_socket, addr)).start()

if __name__ == "__main__":
    start_server()
