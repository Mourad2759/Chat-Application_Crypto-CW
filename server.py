import socket
import threading

# Function to load credentials from a file
def load_credentials():
    credentials = {}
    try:
        with open("credentials.txt", "r") as file:
            for line in file:
                username, password = line.strip().split(":")
                credentials[username] = password
    except FileNotFoundError:
        print("Credentials file not found. No users are registered.")
    return credentials

# Function to handle client connections
def handle_client(client_socket, address, credentials):
    print(f"Connection from {address} has been established.")
    
    # Login process
    while True:
        client_socket.send("Enter username: ".encode())
        username = client_socket.recv(1024).decode()
        client_socket.send("Enter password: ".encode())
        password = client_socket.recv(1024).decode()

        if username in credentials and credentials[username] == password:
            client_socket.send("Login successful! Welcome to the chat room.\n".encode())
            break
        else:
            client_socket.send("Invalid credentials. Please try again.\n".encode())

    # Chat functionality can be added here
    # ...

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 10000))
    server.listen(5)
    print("Server is listening...")

    credentials = load_credentials()

    while True:
        client_socket, address = server.accept()
        threading.Thread(target=handle_client, args=(client_socket, address, credentials)).start()

if __name__ == "__main__":
    main()