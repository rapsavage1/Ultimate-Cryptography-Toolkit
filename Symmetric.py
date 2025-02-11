import math
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

#############################
# Symmetric Encryption Functions
#############################
def generate_key():
    """Generate a symmetric key and save it to 'secret.key'."""
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)
    print("Symmetric key generated and saved as 'secret.key'.")

def load_key():
    """Load the symmetric key from 'secret.key'."""
    try:
        with open("secret.key", "rb") as key_file:
            return key_file.read()
    except FileNotFoundError:
        print("Key file not found. Please generate a key first.")
        return None

def encrypt_message(message):
    """Encrypt a message using the loaded symmetric key."""
    key = load_key()
    if key is None:
        return None
    cipher_suite = Fernet(key)
    return cipher_suite.encrypt(message.encode())

def decrypt_message(encrypted_message):
    """Decrypt an encrypted message using the loaded symmetric key."""
    key = load_key()
    if key is None:
        return None
    cipher_suite = Fernet(key)
    try:
        return cipher_suite.decrypt(encrypted_message).decode()
    except Exception as e:
        print("Decryption failed:", e)
        return None

#############################
# RSA Key Pair Generation (Asymmetric Keys)
#############################
def generate_rsa_keys():
    """
    Generate an RSA key pair and save them to files.
    You will be prompted for the key size and the filenames.
    """
    try:
        key_size = int(input("Enter the RSA key size (e.g., 2048): "))
    except ValueError:
        print("Invalid key size. Please enter an integer.")
        return

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # Serialize private key in PEM format
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    # Serialize public key in PEM format
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    private_filename = input("Enter filename to save the private key (e.g., private.pem): ").strip()
    public_filename = input("Enter filename to save the public key (e.g., public.pem): ").strip()

    with open(private_filename, 'wb') as f:
        f.write(pem_private)
    with open(public_filename, 'wb') as f:
        f.write(pem_public)

    print("RSA key pair generated and saved as:")
    print("  Private key:", private_filename)
    print("  Public key: ", public_filename)

#############################
# Symmetric Keys Calculation Functions
#############################
def symmetric_keys(users):
    """Calculate the number of keys required for symmetric encryption."""
    return (users * (users - 1)) // 2

def asymmetric_keys(users):
    """Calculate the number of keys required for asymmetric encryption."""
    return users * 2

def users_from_asymmetric_keys(keys):
    """Determine the number of users from the given number of asymmetric keys."""
    return math.ceil(keys / 2)

def users_from_symmetric_keys(keys):
    """Determine the number of users from the given number of symmetric keys."""
    return math.ceil((1 + math.sqrt(1 + 8 * keys)) / 2)

#############################
# Symmetric Module Menu
#############################
def symmetric_module_menu():
    print("\n--- Symmetric Module ---")
    print("1. Symmetric Encryption/Decryption")
    print("2. Symmetric Keys Calculation")
    print("3. Generate RSA Key Pair (Public/Private)")
    choice = input("Enter your choice (1, 2, or 3): ").strip()

    if choice == '1':
        # Symmetric Encryption/Decryption
        action = input("Enter 'G' to generate a symmetric key, 'E' to encrypt, or 'D' to decrypt: ").strip().upper()
        if action == 'G':
            generate_key()
        elif action == 'E':
            message = input("Enter the message to encrypt: ")
            encrypted = encrypt_message(message)
            if encrypted:
                print("Encrypted message:", encrypted.decode())
        elif action == 'D':
            enc_text = input("Enter the encrypted message: ")
            decrypted = decrypt_message(enc_text.encode())
            if decrypted:
                print("Decrypted message:", decrypted)
        else:
            print("Invalid choice in symmetric encryption.")
    elif choice == '2':
        # Symmetric Keys Calculation
        key_choice = input("Do you have the number of 'users' or 'keys'? ").strip().lower()
        if key_choice == 'users':
            try:
                users = int(input("Enter the number of users: "))
                print(f"Symmetric encryption requires {symmetric_keys(users)} keys.")
                print(f"Asymmetric encryption requires {asymmetric_keys(users)} keys.")
            except ValueError:
                print("Invalid input. Please enter an integer.")
        elif key_choice == 'keys':
            try:
                given_keys = int(input("Enter the number of keys: "))
                print(f"With {given_keys} asymmetric keys, you can handle {users_from_asymmetric_keys(given_keys)} users.")
                print(f"With {given_keys} symmetric keys, you can handle {users_from_symmetric_keys(given_keys)} users.")
            except ValueError:
                print("Invalid input. Please enter an integer.")
        else:
            print("Invalid choice. Please enter 'users' or 'keys'.")
    elif choice == '3':
        # RSA Key Pair Generation
        generate_rsa_keys()
    else:
        print("Invalid choice in symmetric module.")

#############################
# Main for Testing the Symmetric Module
#############################
def main():
    symmetric_module_menu()

if __name__ == "__main__":
    main()
