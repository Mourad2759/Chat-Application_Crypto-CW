import socket
import threading
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
import base64

# Server setup
HOST = '127.0.0.1'
PORT = 65432

# Global variables
clients = []
nicknames = []
CHAT_HISTORY_PATH = "Chat_history.txt"

# RSA Keys for Server
key = RSA.generate(2048)
private_key = key
public_key = key.publickey()

# RSA encryption and decryption functions
def encrypt_message_rsa(message, public_key):
    cipher = PKCS1_OAEP.new(public_key)
    encrypted_message = cipher.encrypt(message.encode())
    return base64.b64encode(encrypted_message).decode('utf-8')

def decrypt_message_rsa(encrypted_message, private_key):
    cipher = PKCS1_OAEP.new(private_key)
    decrypted_message = cipher.decrypt(base64.b64decode(encrypted_message))
    return decrypted_message.decode('utf-8')

# AES Encryption key (make sure to use a securely generated key)
SECRET_KEY = b'Sixteen byte key'  # 16-byte key for AES-128

# Encryption and decryption functions
def encrypt_message(message):
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return iv, ct

def decrypt_message(iv, ct):
    iv = base64.b64decode(iv)
    ct = base64.b64decode(ct)
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size).decode('utf-8')
    return pt

def broadcast(message):
    """Sends a message to all connected clients and stores it in chat history."""
    # Encrypt the message with AES
    if message.startswith('/'):
        # This is a plain text message (e.g., "/exit", "/join", etc.)
        for client in clients:
            try:
                client.send(message.encode())  # Send plain text message to clients
            except:
                remove_client(client)

        # Store plain text messages in chat history (Optional if you want to keep the history)
        with open(CHAT_HISTORY_PATH, "a", encoding="utf-8") as f:
            f.write(message + "\n")

    else:
        # Encrypt the message with AES
        iv, encrypted_message = encrypt_message(message)
        for client in clients:
            try:
                client.send(f"{iv}:{encrypted_message}".encode())  # Send AES-encrypted message to clients
            except:
                remove_client(client)

        # Store the AES-encrypted message in chat history (Optional)
        with open(CHAT_HISTORY_PATH, "a", encoding="utf-8") as f:
            f.write(f"{iv}:{encrypted_message}\n")

        # Log only the encrypted message in RSA format
        encrypted_message_for_server = encrypt_message_rsa(message, public_key)
        print(f"Encrypted message (RSA) on server: {encrypted_message_for_server}")



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
                iv, encrypted_message = message.split(":")
                decrypted_message = decrypt_message(iv, encrypted_message)
                broadcast(decrypted_message)
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

            # Receive the nickname immediately
            nickname = client.recv(1024).decode()

            # Check if nickname is already in use
            if nickname in nicknames:
                client.send("Nickname already taken. Disconnecting.".encode())
                client.close()
                continue

            nicknames.append(nickname)
            clients.append(client)

            print(f"{nickname} has joined the chat.")
            broadcast(f"{nickname} joined the chat!")  # Broadcast join message
            client.send("Connected to the server.".encode())

            thread = threading.Thread(target=handle_client, args=(client,))
            thread.start()

    except KeyboardInterrupt:
        print("Shutting down server.")
        server.close()

if __name__ == "__main__":
    receive_connections()