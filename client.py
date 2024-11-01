import socket
import threading

def receive_messages(client_socket):
    while True:
        try:
            message = client_socket.recv(1024).decode()
            if message:
                print(message)
            else:
                break
        except:
            break

def save_credentials(username, password):
    with open("credentials.txt", "a") as file:
        file.write(f"{username}:{password}\n")

def main():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("127.0.0.1", 10000))

    while True:
        username = input("Enter your username: ")
        password = input("Enter your password: ")

        # Send credentials to the server
        client.send(username.encode())
        client.send(password.encode())

        # Receive login response
        response = client.recv(1024).decode()
        print(response)

        if "successful" in response:
            break  # Exit the loop if login is successful


    client.send(username.encode())

    # Start a thread to receive messages
    thread = threading.Thread(target=receive_messages, args=(client,))
    thread.start()

    while True:
        message = input()
        if message == "#exit":
            client.send(message.encode())
            break
        client.send(message.encode())

    client.close()

if __name__ == "__main__":
    main()