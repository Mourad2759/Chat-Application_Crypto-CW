import socket
import threading
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import os
import base64

# Server setup
HOST = '127.0.0.1'
PORT = 65432

# Global variables
clients = []
nicknames = []

# Key file paths
PUBLIC_KEY_PATH = "public_key.pem"
PRIVATE_KEY_PATH = "private_key.pem"

def generate_keys():
    """Generates RSA public and private keys if they don't exist."""
    if not os.path.exists(PUBLIC_KEY_PATH) or not os.path.exists(PRIVATE_KEY_PATH):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()

        with open(PRIVATE_KEY_PATH, "wb") as private_file:
            private_file.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )

        with open(PUBLIC_KEY_PATH, "wb") as public_file:
            public_file.write(
                public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )
        print("RSA key pair generated.")

def load_public_key():
    """Loads the public key from the file."""
    with open(PUBLIC_KEY_PATH, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())
    return public_key

def encrypt_message(message, public_key):
    """Encrypts a message using the provided RSA public key and returns a base64 encoded string."""
    encrypted_message = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted_message).decode()

def broadcast(message):
    """Sends a message to all connected clients and stores it encrypted in a file."""
    public_key = load_public_key()
    encrypted_message = encrypt_message(message, public_key)
    
    with open("chat_history.txt", "a") as f:
        f.write(encrypted_message + "\n")
    
    for client in clients:
        try:
            client.send(message.encode())
        except:
            remove_client(client)

def remove_client(client):
    """Removes client from clients and nicknames lists and closes the connection."""
    if client in clients:
        index = clients.index(client)
        clients.remove(client)
        client.close()
        nickname = nicknames[index]
        nicknames.remove(nickname)
        broadcast(f"{nickname} has left the chat.")
        print(f"{nickname} has disconnected.")

def handle_client(client):
    """Handles incoming messages from clients."""
    while True:
        try:
            message = client.recv(1024).decode()
            if message:
                print(message)
                broadcast(message)
        except:
            remove_client(client)
            break

def receive_connections():
    """Accepts new client connections."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()
    print(f"Server is listening on {HOST}:{PORT}")

    try:
        while True:
            client, address = server.accept()
            print(f"Connected with {str(address)}")

            client.send("NICK".encode())
            nickname = client.recv(1024).decode()
            
            if nickname in nicknames:
                client.send("Nickname already taken. Disconnecting.".encode())
                client.close()
                continue

            nicknames.append(nickname)
            clients.append(client)

            print(f"Nickname is {nickname}")
            broadcast(f"{nickname} joined the chat!")
            client.send("Connected to the server.".encode())

            thread = threading.Thread(target=handle_client, args=(client,))
            thread.start()

    except KeyboardInterrupt:
        print("Shutting down server.")
        server.close()

if __name__ == "__main__":
    generate_keys()  # Ensure keys are generated before starting the server
    receive_connections()
