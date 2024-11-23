import socket
import threading
import re
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

HOST = '127.0.0.1'
PORT = 65432

CHAT_HISTORY_PATH = "Chat_history.txt"

# AES Encryption key (same as the server's)
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

def post_exit_menu(client_socket):
    """Displays a menu after the user exits the chat room."""
    while True:
        choice = input("\nChoose an option:\n1. View Chat History\n2. Enter Chat Room Again\n3. Exit the App\n> ")

        if choice == '1':
            view_chat_history()
        elif choice == '2':
            # Close the previous socket before starting a new one
            client_socket.close()
            print("Reconnecting to the chat...")
            main()  # Start the main function to rejoin the chat room
            break
        elif choice == '3':
            print("Exiting the application.")
            client_socket.close()
            break
        else:
            print("Invalid choice. Please try again.")


def view_chat_history():
    secret_code = input("Enter the secret code to access the chat history: ")

    if secret_code == "25-8-2024":
        try:
            with open(CHAT_HISTORY_PATH, "r", encoding="utf-8") as f:
                lines = f.readlines()

            print("\n--- Chat History ---")
            for message in lines:
                message = message.strip()  # Remove any surrounding whitespace

                # Check if the message contains a colon, indicating it's encrypted
                if ':' in message:
                    try:
                        iv, encrypted_message = message.split(":", 1)
                        decrypted_message = decrypt_message(iv, encrypted_message)
                        print(decrypted_message)  # Print the decrypted message
                    except Exception as e:
                        print(f"Error decrypting message: {e}")
                else:
                    # If it's a plain text message, print it as is
                    print(message)

            print("--- End of Chat History ---\n")
        except FileNotFoundError:
            print("Chat history file not found.")
    else:
        print("Incorrect secret code. You are not authorized to view the chat history.")


def receive_messages(client_socket):
    """Handles receiving messages from the server."""
    while True:
        try:
            message = client_socket.recv(1024).decode()

            # Check if the message contains a colon to indicate it's encrypted
            if ':' in message:
                iv, encrypted_message = message.split(":", 1)
                decrypted_message = decrypt_message(iv, encrypted_message)
                print(decrypted_message)
            else:
                # If the message is not in the encrypted format, print it as is
                print(message)

        except (OSError, ConnectionResetError) as e:
            print(f"Connection lost: {e}. Closing connection.")
            client_socket.close()
            break
        except Exception as e:
            print(f"Unexpected error: {e}. Closing connection.")
            client_socket.close()
            break


def send_messages(client_socket):
    """Handles sending messages to the server."""
    while True:
        try:
            message = input('')
            if message == "/exit":
                print("Exiting the chat room.")
                client_socket.send(f"{nickname} has left the chat.".encode())
                # Close the socket and exit the chat
                client_socket.close()
                post_exit_menu(client_socket)
                break  # Exit the while loop

            # Encrypt the message and send it
            iv, encrypted_message = encrypt_message(f"{nickname}: {message}")
            client_socket.send(f"{iv}:{encrypted_message}".encode())

        except OSError as e:
            print(f"Socket error: {e}. Exiting.")
            break
        except Exception as e:
            print(f"Unexpected error: {e}. Exiting.")
            break


def main():
    global nickname
    nickname = signup_or_login()

    choice = input("\nChoose an option:\n1. Join Chat Room\n2. View Chat History\n> ")

    if choice == '1':
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((HOST, PORT))
        client.send(nickname.encode())

        receive_thread = threading.Thread(target=receive_messages, args=(client,))
        receive_thread.start()

        send_thread = threading.Thread(target=send_messages, args=(client,))
        send_thread.start()

    elif choice == '2':
        view_chat_history()

    else:
        print("Invalid choice. Exiting.")

if __name__ == "__main__":
    main()