import socket
import threading
import re
import os
import hashlib

HOST = '127.0.0.1'
PORT = 65432

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

# Main client function
nickname = signup_or_login()

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((HOST, PORT))
client.send(nickname.encode())

receive_thread = threading.Thread(target=receive_messages, args=(client,))
receive_thread.start()

send_thread = threading.Thread(target=send_messages, args=(client,))
send_thread.start()
