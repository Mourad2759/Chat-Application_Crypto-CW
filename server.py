import socket
import threading

clients = []
usernames = {}

def handle_client(client_socket, client_address):
    print(f"{client_address} connected.")
    
    # Get username
    client_socket.send("Enter your username: ".encode())
    username = client_socket.recv(1024).decode()
    usernames[client_socket] = username
    clients.append(client_socket)

    broadcast(f"{username} has joined the chat!", client_socket)

    while True:
        try:
            message = client_socket.recv(1024).decode()
            if message == "#exit":
                broadcast(f"{username} has left the chat.", client_socket)
                clients.remove(client_socket)
                del usernames[client_socket]
                client_socket.close()
                break
            else:
                broadcast(f"{username}: {message}", client_socket)
        except:
            break

def broadcast(message, sender_socket):
    for client in clients:
        if client != sender_socket:
            client.send(message.encode())

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", 10000))
    server.listen(5)
    print("Server started. Waiting for connections...")

    while True:
        client_socket, client_address = server.accept()
        thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
        thread.start()

if __name__ == "__main__":
    main()