import socket
import threading
import re
import os
import hashlib
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

HOST = '127.0.0.1'
PORT = 65432

# File paths for keys and chat history
PUBLIC_KEY_PATH = "public_key.pem"
PRIVATE_KEY_PATH = "private_key.pem"
CHAT_HISTORY_PATH = "chat_history.txt"

# Complex password check
def is_complex_password(password):
    return (len(password) >= 8 and re.search(r'[A-Z]', password) and re.search(r'[a-z]', password) 
            and re.search(r'[0-9]', password) and re.search(r'[!@#$%^&*()_+]', password))

# Hashing password
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Signup or Login
def signup_or_login():
    choice = input("Choose an option:\n1. Login\n2. Signup\n> ")
    if choice == '1':
        return login()
    elif choice == '2':
        return signup()
    else:
        print("Invalid choice. Try again.")
        return signup_or_login()

def login():
    username = input("Username: ")
    password = input("Password: ")
    password_hash = hash_password(password)

    try:
        with open("credentials.txt", "r") as f:
            lines = f.readlines()
            for line in lines:
                stored_username, stored_password = line.strip().split(":")
                if username == stored_username and password_hash == stored_password:
                    print("Login successful!")
                    return username
            print("Invalid username or password.")
            return login()
    except FileNotFoundError:
        print("No credentials found. Please sign up.")
        return signup()

def signup():
    username = input("Choose a username: ")
    password = input("Choose a complex password: ")

    if not is_complex_password(password):
        print("Password must be at least 8 characters long and contain uppercase, lowercase, digit, and special character.")
        return signup()

    password_hash = hash_password(password)

    with open("credentials.txt", "a") as f:
        f.write(f"{username}:{password_hash}\n")

    print("Signup successful! Please log in now.")
    return login()

def load_private_key():
    """Loads the private key from a file."""
    with open(PRIVATE_KEY_PATH, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )
    return private_key

def decrypt_message(encrypted_message, private_key):
    """Decrypts a base64 encoded encrypted message using the provided RSA private key."""
    encrypted_message_bytes = base64.b64decode(encrypted_message)
    decrypted_message = private_key.decrypt(
        encrypted_message_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_message.decode()

def view_chat_history():
    """Decrypts and displays the chat history."""
    try:
        private_key = load_private_key()
        
        # Open the file with explicit UTF-8 encoding
        with open(CHAT_HISTORY_PATH, "r", encoding="utf-8") as f:
            lines = f.readlines()

        print("\n--- Chat History ---")
        for encrypted_message in lines:
            try:
                decrypted_message = decrypt_message(encrypted_message.strip(), private_key)
                print(decrypted_message)
            except Exception as e:
                print("Error decrypting a message:", e)
        print("--- End of Chat History ---\n")
    except FileNotFoundError:
        print("Chat history file not found.")


def receive_messages(client_socket):
    """Handles receiving messages from the server."""
    while True:
        try:
            message = client_socket.recv(1024).decode()
            if message == 'NICK':
                client_socket.send(nickname.encode())
            else:
                print(message)
        except:
            print("An error occurred. Disconnecting from server.")
            client_socket.close()
            break

def send_messages(client_socket):
    """Handles sending messages to the server."""
    while True:
        message = input('')
        if message == "/exit":
            client_socket.close()
            print("Disconnected from chat.")
            break
        client_socket.send(f"{nickname}: {message}".encode())

def main():
    global nickname
    nickname = signup_or_login()

    # Provide the user with options after login
    choice = input("\nChoose an option:\n1. Join Chat Room\n2. View Chat History\n> ")

    if choice == '1':
        # Join the chat room
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((HOST, PORT))
        client.send(nickname.encode())

        receive_thread = threading.Thread(target=receive_messages, args=(client,))
        receive_thread.start()

        send_thread = threading.Thread(target=send_messages, args=(client,))
        send_thread.start()

    elif choice == '2':
        # View the chat history
        view_chat_history()

    else:
        print("Invalid choice. Exiting.")

if __name__ == "__main__":
    main()
