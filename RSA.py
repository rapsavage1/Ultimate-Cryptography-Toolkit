import sympy

def compute_private_exponent():
    """Compute the private exponent d given p, q, and e."""
    p = int(input("Enter prime number p: "))
    q = int(input("Enter prime number q: "))
    e = int(input("Enter public key exponent e: "))
    
    N = p * q
    phi_n = (p - 1) * (q - 1)
    
    try:
        d = sympy.mod_inverse(e, phi_n)
        print(f"\nComputed Private Key Exponent (d): {d}")
    except ValueError:
        print("No modular inverse found. Ensure e is coprime with φ(N).")

def encrypt_message():
    """Encrypt a message using RSA."""
    print("\n--- RSA Encryption ---")
    print("First, enter the given RSA primes (p and q) to compute N.")
    
    p = int(input("Enter the given prime number p: "))
    q = int(input("Enter the given prime number q: "))
    N = p * q  # Compute modulus N
    print(f"Computed Modulus (N): {N}")

    print("\nNow enter the plaintext value P (this is the message to encrypt).")
    P = int(input("Enter the plaintext number P: "))
    e = int(input("Enter public key exponent (e): "))

    C = pow(P, e, N)
    print(f"\nEncrypted Message (Ciphertext C): {C}")

def decrypt_message():
    """Decrypt a message using RSA."""
    print("\n--- RSA Decryption ---")
    print("First, enter the given RSA primes (p and q) to compute N.")

    p = int(input("Enter the given prime number p: "))
    q = int(input("Enter the given prime number q: "))
    N = p * q  # Compute modulus N
    print(f"Computed Modulus (N): {N}")

    print("\nNow enter the ciphertext value C to decrypt.")
    C = int(input("Enter the ciphertext C: "))
    d = int(input("Enter private key exponent (d): "))

    P = pow(C, d, N)
    print(f"\nDecrypted Message (Plaintext P): {P}")

def rsa_menu():
    """Main menu for RSA cryptosystem functions"""
    while True:
        print("\n=== RSA Cryptosystem ===")
        print("1. Compute Private Exponent (d)")
        print("2. Encrypt a Message (Compute C from P)")
        print("3. Decrypt a Message (Compute P from C)")
        print("4. Exit")

        choice = input("Enter your choice (1-4): ").strip()
        
        if choice == '1':
            compute_private_exponent()
        elif choice == '2':
            encrypt_message()
        elif choice == '3':
            decrypt_message()
        elif choice == '4':
            print("Exiting RSA Cryptosystem. Goodbye!")
            break
        else:
            print("Invalid choice. Please enter 1-4.")