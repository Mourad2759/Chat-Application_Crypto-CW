# Secure Chat Application

---

## **Introduction**

This project is a secure chat application implemented in Python that ensures confidentiality and data integrity using advanced cryptographic techniques. The application provides real-time messaging functionality between clients with end-to-end encryption and secure password management.

---

## **Code Structure**

The project comprises the following main files:

1. **`server.py`**: Implements server-side functionality, including communication management and message encryption.
2. **`client.py`**: Handles client-side operations such as user authentication, message encryption, and chat interface.
3. **`test_crypto_functions.py`**: Provides unit tests to validate the reliability of the cryptographic functions used in `server.py` and `client.py`.

---

## **File Breakdown**

### **`server.py`**
The server is responsible for managing client connections, broadcasting messages, and securely storing chat history.

**Key Features**:
- **Message Broadcasting**: Encrypts messages using AES before broadcasting them to connected clients.
- **Chat History Encryption**: Stores chat history in encrypted format using AES to ensure security in case of unauthorized access.
- **RSA Terminal Encryption**: Messages displayed on the server’s terminal are encrypted using RSA, preventing plaintext exposure.

**Key Functions**:
- `encrypt_message_aes(message)`: Encrypts messages using AES before broadcasting.
- `encrypt_terminal_message_rsa(message)`: Encrypts server-displayed messages using RSA.
- `decrypt_message_rsa(encrypted_message)`: Decrypts terminal messages using the private key.

---

### **`client.py`**
The client manages user authentication, secure messaging, and chat history access.

**Key Features**:
- **User Authentication**: Uses SHA-256 to hash and securely store user passwords.
- **Message Encryption**: Encrypts messages with AES before sending to the server; decrypts received messages for display.
- **Chat History Access**: Enables authorized users to access encrypted chat history securely.

**Key Functions**:
- `hash_password_sha256(password)`: Hashes passwords using SHA-256.
- `encrypt_message_aes(message)`: Encrypts messages using AES before sending to the server.
- `decrypt_message_aes(encrypted_message)`: Decrypts AES-encrypted messages received from the server.

---

### **`test_crypto_functions.py`**
This file contains unit tests to verify the functionality and correctness of cryptographic operations in the application.

**Test Coverage**:
1. **AES Encryption/Decryption**:
   - Validates encryption and decryption correctness.
   - Ensures the same key is used across operations.
2. **RSA Key Pair Integrity**:
   - Confirms valid key pair generation.
   - Verifies encryption and decryption using RSA.
3. **SHA-256 Hashing**:
   - Ensures passwords are hashed consistently.
   - Confirms that hashed passwords cannot be reversed.

---

## **Cryptographic Techniques**

1. **AES (Advanced Encryption Standard)**:
   - **Use**: Message encryption during transit and chat history storage.
   - **Mode**: CBC (Cipher Block Chaining) to enhance security by linking message blocks.
   - **Advantages**: High speed and efficiency for real-time communication.

2. **RSA (Rivest-Shamir-Adleman)**:
   - **Use**: Server-side terminal encryption.
   - **Implementation**: Asymmetric encryption with public/private key pair.
   - **Advantages**: Provides robust protection for sensitive server-side data.

3. **SHA-256**:
   - **Use**: Password hashing for secure storage.
   - **Advantages**: Irreversible hashing prevents unauthorized access to plaintext passwords.

---

## **How to Run**

1. Clone the repository:
   ```bash
   git clone https://github.com/Mourad2759/Chat-Application_Crypto-CW.git
