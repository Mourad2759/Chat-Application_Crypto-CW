Introduction
This project is a secure chat application implemented in Python that ensures confidentiality and data integrity using advanced cryptographic techniques. The application provides real-time messaging functionality between clients with end-to-end encryption and secure password management.

Code Structure
The project comprises the following main files:

server.py: Implements server-side functionality, including communication management and message encryption.
client.py: Handles client-side operations such as user authentication, message encryption, and chat interface.
test_crypto_functions.py: Provides unit tests to validate the reliability of the cryptographic functions used in server.py and client.py.
File Breakdown
server.py
The server is responsible for managing client connections, broadcasting messages, and securely storing chat history. Key features include:

Message Broadcasting: Encrypts messages using AES before broadcasting them to connected clients.
Chat History Encryption: Stores chat history in encrypted format using AES to ensure security in case of unauthorized access.
RSA Terminal Encryption: Messages displayed on the server’s terminal are encrypted using RSA, preventing plaintext exposure.
Key Functions:

encrypt_message_aes(message): Encrypts messages using AES before broadcasting.
encrypt_terminal_message_rsa(message): Encrypts server-displayed messages using RSA.
decrypt_message_rsa(encrypted_message): Decrypts terminal messages using the private key.
client.py
The client manages user authentication, secure messaging, and chat history access.

User Authentication: Uses SHA-256 to hash and securely store user passwords.
Message Encryption: Encrypts messages with AES before sending to the server; decrypts received messages for display.
Chat History Access: Enables authorized users to access encrypted chat history securely.
Key Functions:

hash_password_sha256(password): Hashes passwords using SHA-256.
encrypt_message_aes(message): Encrypts messages using AES before sending to the server.
decrypt_message_aes(encrypted_message): Decrypts AES-encrypted messages received from the server.
test_crypto_functions.py
This file contains unit tests to verify the functionality and correctness of cryptographic operations in the application.

Test Coverage:

AES Encryption/Decryption:
Validates encryption and decryption correctness.
Ensures the same key is used across operations.
RSA Key Pair Integrity:
Confirms valid key pair generation.
Verifies encryption and decryption using RSA.
SHA-256 Hashing:
Ensures passwords are hashed consistently.
Confirms that hashed passwords cannot be reversed.
Cryptographic Techniques
AES (Advanced Encryption Standard):

Use: Message encryption during transit and chat history storage.
Mode: CBC (Cipher Block Chaining) to enhance security by linking message blocks.
Advantages: High speed and efficiency for real-time communication.
RSA (Rivest-Shamir-Adleman):

Use: Server-side terminal encryption.
Implementation: Asymmetric encryption with public/private key pair.
Advantages: Provides robust protection for sensitive server-side data.
SHA-256:

Use: Password hashing for secure storage.
Advantages: Irreversible hashing prevents unauthorized access to plaintext passwords.
How to Run
Clone the repository:
bash
Copy code
git clone https://github.com/Mourad2759/Chat-Application_Crypto-CW.git
Install dependencies:
bash
Copy code
pip install -r requirements.txt
Run the server:
bash
Copy code
python server.py
Run clients:
bash
Copy code
python client.py
Testing the Application
Run the tests using the unittest module:

bash
Copy code
python -m unittest test_crypto_functions.py
