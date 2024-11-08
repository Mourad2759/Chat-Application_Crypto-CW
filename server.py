import socket
import threading
import sys

# Server setup
HOST = '127.0.0.1'
PORT = 65432

# Global variables
clients = []
nicknames = []

def broadcast(message):
    """Sends a message to all connected clients and logs it to a file."""
    with open("chat_history.txt", "a") as f:
        f.write(message + "\n")
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
        sys.exit(0)

if __name__ == "__main__":
    receive_connections()
