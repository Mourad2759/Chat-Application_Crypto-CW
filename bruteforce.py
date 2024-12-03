import hashlib
import itertools
import string

CREDENTIALS_FILE = "credentials.txt"

def hash_password(password):
    """Hashes a password using SHA-256."""
    return hashlib.sha256(password.encode()).hexdigest()

def load_hashes(file_path):
    """Loads hashed passwords from the credentials file."""
    hashes = {}
    with open(file_path, "r") as f:
        for line in f:
            username, hashed_password = line.strip().split(":")
            hashes[username] = hashed_password
    return hashes

def brute_force(hashes, max_length=6):
    """Brute-forces hashes by trying all possible combinations of characters."""
    chars = string.ascii_letters + string.digits + string.punctuation
    cracked = {}

    print("[*] Starting brute-force attack...")
    for length in range(1, max_length + 1):
        print(f"[*] Trying passwords of length {length}...")
        for candidate in itertools.product(chars, repeat=length):
            candidate = ''.join(candidate)
            candidate_hash = hash_password(candidate)

            # Check against stored hashes
            for username, hashed_password in hashes.items():
                if candidate_hash == hashed_password:
                    cracked[username] = candidate
                    print(f"[+] Found password for {username}: {candidate}")

                    # Remove cracked hash to save time
                    del hashes[username]
                    if not hashes:
                        return cracked

    return cracked

def main():
    hashes = load_hashes(CREDENTIALS_FILE)
    cracked_hashes = brute_force(hashes, max_length=6)

    if cracked_hashes:
        print("\n[*] Cracked hashes:")
        for username, password in cracked_hashes.items():
            print(f"    {username}: {password}")
    else:
        print("\n[-] No hashes were cracked.")

if __name__ == "__main__":
    main()
