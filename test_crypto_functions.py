import unittest
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64
from server import (
    encrypt_message_rsa as server_encrypt_message_rsa,
    decrypt_message_rsa as server_decrypt_message_rsa,
    encrypt_message as server_encrypt_message,
    decrypt_message as server_decrypt_message,
    SECRET_KEY as SERVER_SECRET_KEY,
    public_key as server_public_key,
    private_key as server_private_key,
)
from client import (
    encrypt_message as client_encrypt_message,
    decrypt_message as client_decrypt_message,
    SECRET_KEY as CLIENT_SECRET_KEY,
)

class TestCryptoFunctions(unittest.TestCase):
    def test_aes_encryption_decryption_shared(self):
        """Test shared AES encryption/decryption between server and client."""
        print("\nTesting AES encryption and decryption (Server -> Client)...")
        plaintext = "Test message for shared AES encryption."
        iv, encrypted_message = server_encrypt_message(plaintext)
        decrypted_message = client_decrypt_message(iv, encrypted_message)
        print(f"Original: {plaintext}, Encrypted: {encrypted_message}, Decrypted: {decrypted_message}")
        self.assertEqual(plaintext, decrypted_message, "Server->Client AES encryption/decryption failed")

        print("\nTesting AES encryption and decryption (Client -> Server)...")
        iv, encrypted_message = client_encrypt_message(plaintext)
        decrypted_message = server_decrypt_message(iv, encrypted_message)
        print(f"Original: {plaintext}, Encrypted: {encrypted_message}, Decrypted: {decrypted_message}")
        self.assertEqual(plaintext, decrypted_message, "Client->Server AES encryption/decryption failed")

    def test_aes_key_mismatch(self):
        """Test that AES decryption fails with a mismatched key."""
        plaintext = "This message tests AES key mismatch."
        iv, encrypted_message = server_encrypt_message(plaintext)
        AES_MISMATCH_KEY = b"Different 16ByteK"
        print("\nTesting AES decryption with mismatched key...")
        with self.assertRaises(ValueError, msg="AES decryption did not fail with mismatched keys"):
            cipher = AES.new(AES_MISMATCH_KEY, AES.MODE_CBC, base64.b64decode(iv))
            unpad(cipher.decrypt(base64.b64decode(encrypted_message)), AES.block_size)

    def test_rsa_encryption_decryption_shared(self):
        """Test shared RSA encryption/decryption using server's keys."""
        plaintext = "Test message for shared RSA encryption."
        print("\nTesting RSA encryption and decryption (Server -> Server)...")
        encrypted_message = server_encrypt_message_rsa(plaintext, server_public_key)
        decrypted_message = server_decrypt_message_rsa(encrypted_message, server_private_key)
        print(f"Original: {plaintext}, Encrypted: {encrypted_message}, Decrypted: {decrypted_message}")
        self.assertEqual(plaintext, decrypted_message, "Server->Server RSA encryption/decryption failed")

    def test_aes_key_length(self):
        """Verify the length and consistency of AES keys."""
        print("\nTesting AES key length and consistency...")
        self.assertEqual(len(SERVER_SECRET_KEY), 16, "Server AES key length is not 16 bytes")
        self.assertEqual(len(CLIENT_SECRET_KEY), 16, "Client AES key length is not 16 bytes")
        self.assertEqual(SERVER_SECRET_KEY, CLIENT_SECRET_KEY, "Server and client AES keys do not match")

    def test_rsa_key_pair(self):
        """Ensure the RSA keys used by the server are valid."""
        print("\nTesting RSA key pair validity...")
        self.assertIsInstance(server_public_key, RSA.RsaKey, "Server public key is not an instance of RsaKey")
        self.assertIsInstance(server_private_key, RSA.RsaKey, "Server private key is not an instance of RsaKey")
        self.assertTrue(server_public_key.can_encrypt(), "Server public key cannot encrypt")
        self.assertTrue(server_private_key.can_sign(), "Server private key cannot sign")

if __name__ == "__main__":
    unittest.main(verbosity=2)
