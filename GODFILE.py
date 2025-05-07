import string
import sympy
import glob
import math
import hashlib
import itertools
import time
from google.api_core.exceptions import ResourceExhausted
import google.generativeai as genai
from collections import Counter
from cryptography.fernet import Fernet
from sympy import mod_inverse
#########################
# 1. Caesar Cipher
#########################
def caesar_cipher(text, shift, decrypt=False):
    if decrypt:
        shift = -shift
    alphabet = string.ascii_uppercase
    shifted_alphabet = alphabet[shift:] + alphabet[:shift]
    translation_table = str.maketrans(alphabet, shifted_alphabet)
    return text.upper().translate(translation_table)

def caesar_cipher_menu():
    print("\n--- Caesar Cipher ---")
    mode = input("Enter 'E' to encrypt or 'D' to decrypt: ").strip().upper()
    text = input("Enter the text: ")
    shift = int(input("Enter the shift value: "))
    result = caesar_cipher(text, shift, decrypt=(mode == "D"))
    print(f"Result: {result}")

#########################
# 2. Index of Coincidence
#########################
def index_of_coincidence_menu():
    print("\n--- Index of Coincidence ---")
    sample_text = input("Enter the text: ")
    # Remove non-alphabetic characters and convert to uppercase
    text = ''.join(filter(str.isalpha, sample_text)).upper()
    letter_counts = Counter(text)
    total_letters = sum(letter_counts.values())
    if total_letters > 1:
        ic = sum(f * (f - 1) for f in letter_counts.values()) / (total_letters * (total_letters - 1))
    else:
        ic = 0
    print("Letter frequencies:")
    for letter in string.ascii_uppercase:
        print(f"{letter}: {letter_counts.get(letter, 0)}")
    print(f"\nIndex of Coincidence: {ic:.6f}")
#########################
# 3. Kasiski Analysis
#########################
def kasiski_menu():
    print("\n--- Kasiski Analysis ---")
    def find_repeated_sequences(ciphertext, seq_length=15):
        repeated_sequences = {}
        for i in range(len(ciphertext) - seq_length + 1):
            seq = ciphertext[i : i + seq_length]
            if seq in repeated_sequences:
                repeated_sequences[seq].append(i + 1)  # positions (starting at 1)
            else:
                repeated_sequences[seq] = [i + 1]
        return repeated_sequences

    def find_factors(num):
        factors = set()
        for i in range(1, num + 1):
            if num % i == 0:
                factors.add(i)
        return factors

    def kasiski_method(ciphertext, seq_length=15):
        repeated_sequences = find_repeated_sequences(ciphertext, seq_length)
        longest_sequence = max(repeated_sequences, key=lambda k: len(repeated_sequences[k]), default=None)
        positions = repeated_sequences.get(longest_sequence, [])
        if not positions:
            return None, None, None, None
        distances = [positions[i + 1] - positions[i] for i in range(len(positions) - 1)]
        common_factors = find_factors(distances[0]) if distances else set()
        for dist in distances[1:]:
            common_factors &= find_factors(dist)
        return longest_sequence, positions, distances, common_factors

    ciphertext = input("Please enter the ciphertext: ")
    longest_sequence, positions, distances, common_factors = kasiski_method(ciphertext, seq_length=15)
    if longest_sequence:
        print(f"\nLongest repeating sequence: {longest_sequence}")
        for i, pos in enumerate(positions, start=1):
            print(f"Location #{i}: {pos}")
        for i in range(1, len(positions)):
            print(f"Difference between location #{i+1} and #{i}: {positions[i] - positions[i - 1]}")
        if distances:
            common_factor = max(common_factors) if common_factors else 'No common factor > 1'
            print(f"\nCommon factor among differences: {common_factor}")
            probable_key_length = common_factor if isinstance(common_factor, int) else None
            print(f"Probable key length: {probable_key_length}")
    else:
        print("No repeated sequences found.")
#########################
# 4. Symmetric Module
#########################
def generate_key():
    """Generate a key and save it to 'secret.key'."""
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)
    print("Key generated and saved as 'secret.key'.")

def load_key():
    """Load the key from 'secret.key'."""
    try:
        with open("secret.key", "rb") as key_file:
            return key_file.read()
    except FileNotFoundError:
        print("Key file not found. Please generate a key first.")
        return None

def encrypt_message(message):
    """Encrypt a message using the loaded key."""
    key = load_key()
    if key is None:
        return None
    cipher_suite = Fernet(key)
    return cipher_suite.encrypt(message.encode())

def decrypt_message(encrypted_message):
    """Decrypt an encrypted message using the loaded key."""
    key = load_key()
    if key is None:
        return None
    cipher_suite = Fernet(key)
    try:
        return cipher_suite.decrypt(encrypted_message).decode()
    except Exception as e:
        print("Decryption failed:", e)
        return None

def symmetric_encryption_menu():
    print("\n--- Symmetric Encryption ---")
    choice = input("Enter 'G' to generate a key, 'E' to encrypt, or 'D' to decrypt: ").strip().upper()
    if choice == 'G':
        generate_key()
    elif choice == 'E':
        message = input("Enter the message to encrypt: ")
        encrypted = encrypt_message(message)
        if encrypted:
            print("Encrypted message:", encrypted.decode())
    elif choice == 'D':
        enc_text = input("Enter the encrypted message: ")
        decrypted = decrypt_message(enc_text.encode())
        if decrypted:
            print("Decrypted message:", decrypted)
    else:
        print("Invalid choice.")

# --- Symmetric Keys Calculation Functions ---
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

def symmetric_keys_menu():
    print("\n--- Symmetric Keys Calculation ---")
    choice = input("Do you have the number of users or keys? (Enter 'users' or 'keys'): ").strip().lower()
    if choice == 'users':
        try:
            users = int(input("Enter the number of users: "))
            print(f"Symmetric encryption requires {symmetric_keys(users)} keys.")
            print(f"Asymmetric encryption requires {asymmetric_keys(users)} keys.")
        except ValueError:
            print("Invalid input. Please enter an integer.")
    elif choice == 'keys':
        try:
            given_keys = int(input("Enter the number of keys: "))
            print(f"With {given_keys} asymmetric keys, you can handle {users_from_asymmetric_keys(given_keys)} users.")
            print(f"With {given_keys} symmetric keys, you can handle {users_from_symmetric_keys(given_keys)} users.")
        except ValueError:
            print("Invalid input. Please enter an integer.")
    else:
        print("Invalid choice. Please enter 'users' or 'keys'.")

# --- Combined Symmetric Module Menu ---
def symmetric_module_menu():
    print("\n--- Symmetric Module ---")
    print("1. Symmetric Encryption")
    print("2. Symmetric Keys Calculation")
    sym_choice = input("Enter your choice (1 or 2): ").strip()
    if sym_choice == '1':
        symmetric_encryption_menu()
    elif sym_choice == '2':
        symmetric_keys_menu()
    else:
        print("Invalid choice in symmetric module.")
#########################
# 5. Knapsack Cryptosystem Tool
#########################
def knapsack_get_input(prompt):
    s = input(prompt).strip()
    return list(map(int, s.replace(",", " ").split()))

def knapsack_compute_hard(simple_knapsack, W, N):
    return [(W * s) % N for s in simple_knapsack]

def knapsack_mod_inverse(a, m):
    # Custom modular inverse using extended Euclidean algorithm.
    def egcd(a, b):
        if a == 0:
            return b, 0, 1
        g, x, y = egcd(b % a, a)
        return g, y - (b // a) * x, x
    g, x, _ = egcd(a, m)
    if g != 1:
        return None
    return x % m

def knapsack_decrypt_block(ciphertext_value, simple_knapsack, w_inv, N):
    X = (w_inv * ciphertext_value) % N
    n = len(simple_knapsack)
    bits = [0] * n
    for i in range(n - 1, -1, -1):
        if simple_knapsack[i] <= X:
            bits[i] = 1
            X -= simple_knapsack[i]
        else:
            bits[i] = 0
    return "".join(str(bit) for bit in bits)

def knapsack_encryption_decryption():
    print("\n--- Knapsack Encryption/Decryption ---")
    operation = input("Enter 'E' for Encryption or 'D' for Decryption: ").strip().upper()
    if operation == "E":
        knapsack_type = input("Enter 'S' for Simple (to compute Hard Knapsack) or 'H' for Hard: ").strip().upper()
        W = int(input("Enter the multiplier (W): "))
        N = int(input("Enter the modulus (N): "))
        if knapsack_type == "S":
            simple_knapsack = knapsack_get_input("Enter the simple (super increasing) knapsack (e.g., 2 42 94 233): ")
            public_knapsack = knapsack_compute_hard(simple_knapsack, W, N)
            print("\nSimple Knapsack:", simple_knapsack)
            print("Computed Hard Knapsack:", public_knapsack)
        elif knapsack_type == "H":
            public_knapsack = knapsack_get_input("Enter the hard knapsack (e.g., 7 9 10 9): ")
            print("\nUsing Hard Knapsack:", public_knapsack)
        else:
            print("Invalid knapsack type. Exiting.")
            return
        w_inverse = knapsack_mod_inverse(W, N)
        if w_inverse is None:
            print("Error: Multiplicative inverse does not exist for given W and N.")
            return
        print("\nComputed Multiplicative Inverse (w⁻¹):", w_inverse)
        if input("\nDo you want to encrypt a plaintext? (Y/N): ").strip().upper() == "Y":
            plaintext = input("Enter the binary plaintext (blocks separated by spaces): ").strip()
            blocks = plaintext.split()
            if any(len(block) != len(public_knapsack) for block in blocks):
                print("Error: Each block must have a length equal to the number of knapsack elements.")
                return
            print("\nCiphertext values (integers):")
            for i, block in enumerate(blocks, start=1):
                c_val = sum(int(bit) * k for bit, k in zip(block, public_knapsack))
                print(f"C{i}: {c_val}")
        else:
            print("Encryption step skipped.")
    elif operation == "D":
        print("\n--- Knapsack Decryption ---")
        simple_knapsack = knapsack_get_input("Enter the simple (super increasing) knapsack (e.g., 2 12 25 71): ")
        W = int(input("Enter the multiplier (W): "))
        N = int(input("Enter the modulus (N): "))
        w_inverse = knapsack_mod_inverse(W, N)
        if w_inverse is None:
            print("Error: Multiplicative inverse does not exist for given W and N.")
            return
        print("\nSimple Knapsack:", simple_knapsack)
        print("Multiplier (W):", W)
        print("Modulus (N):", N)
        print("Computed Multiplicative Inverse (w⁻¹):", w_inverse)
        ciphertext_input = input("Enter the ciphertext values (e.g., 42,41,58,24): ").strip()
        ciphertext = list(map(int, ciphertext_input.replace(",", " ").split()))
        print("\nDecrypted binary blocks:")
        for i, c_val in enumerate(ciphertext, start=1):
            decrypted = knapsack_decrypt_block(c_val, simple_knapsack, w_inverse, N)
            print(f"Block {i}: {decrypted}")
    else:
        print("Invalid operation. Exiting.")

def knapsack_tool_menu():
    print("\n--- Knapsack Cryptosystem Tool ---")
    print("1. Knapsack Encryption/Decryption")
    print("2. Compute Hard Knapsack")
    print("3. Compute Multiplicative Inverse of W")
    choice = input("Enter your choice (1, 2, or 3): ").strip()
    if choice == '1':
        knapsack_encryption_decryption()
    elif choice == '2':
        knapsack_type = input("Enter 'S' for Simple or 'H' for Hard: ").strip().upper()
        W = int(input("Enter the multiplier (W): "))
        N = int(input("Enter the modulus (N): "))
        if knapsack_type == "S":
            simple_knapsack = knapsack_get_input("Enter the simple knapsack (e.g., 2 42 94 233): ")
            public_knapsack = knapsack_compute_hard(simple_knapsack, W, N)
            print("\nSimple Knapsack:", simple_knapsack)
            print("Computed Hard Knapsack:", public_knapsack)
        elif knapsack_type == "H":
            public_knapsack = knapsack_get_input("Enter the hard knapsack (e.g., 7 9 10 9): ")
            print("\nUsing Hard Knapsack:", public_knapsack)
        else:
            print("Invalid choice.")
    elif choice == '3':
        print("\n--- Compute Multiplicative Inverse of W ---")
        w = int(input("Enter the value of w: "))
        n = int(input("Enter the value of n (should be prime): "))
        inverse = pow(w, n - 2, n)  # Fermat's Little Theorem
        print(f"\nThe Multiplicative Inverse of w is: {inverse}")
    else:
        print("Invalid choice.")
#########################
# 6. RSA
#########################
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

def encrypt_message1():
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

def decrypt_message1():
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
            encrypt_message1()
        elif choice == '3':
            decrypt_message1()
        elif choice == '4':
            print("Exiting RSA Cryptosystem. Goodbye!")
            break
        else:
            print("Invalid choice. Please enter 1-4.")
#########################
# 7. DES
#########################
def string_to_ascii_hex(s):
    """Convert each character in s to its 2-digit ASCII hex representation."""
    return [format(ord(c), '02X') for c in s]

def string_to_bin(s):
    """Convert ASCII string to binary (8 bits per character)."""
    return ''.join(format(ord(c), '08b') for c in s)

def hex_to_bin(hex_str):
    """Convert a hex string to a binary string, removing dashes."""
    hex_str = hex_str.replace("-", "")  # Remove dashes if present
    return bin(int(hex_str, 16))[2:].zfill(len(hex_str) * 4)  # Convert to binary and pad

def bin_to_hex(bin_str, group_size=8):
    """Convert a binary string into hex, grouped by 'group_size' bits."""
    groups = [bin_str[i:i+group_size] for i in range(0, len(bin_str), group_size)]
    hex_vals = [format(int(g, 2), '02X') for g in groups]
    return hex_vals

def permute(block, table):
    """Permute a binary string according to a given permutation table."""
    return ''.join(block[i-1] for i in table)

def remove_parity_bits(bin_key_64):
    """Remove every 8th bit (parity bits) from the 64-bit key to get a 56-bit key."""
    return ''.join(bin_key_64[i] for i in range(len(bin_key_64)) if (i + 1) % 8 != 0)

def ascii_to_hex_menu():
    """Handles ASCII to Hex conversion."""
    ascii_input = input("Enter an ASCII string: ").strip()
    ascii_hex = string_to_ascii_hex(ascii_input)
    
    print("\n🔹 ASCII to Hex Conversion:")
    for i, h in enumerate(ascii_hex, start=1):
        print(f"HEX of ASCII {i}: {h}")

def initial_permutation_menu():
    """Handles Initial Permutation."""
    hex_input = input("Enter an 8-byte hex string with dashes (e.g., 54-6F-72-74-31-6C-6C-61): ").strip()
    bin_64 = hex_to_bin(hex_input)

    # 🔹 **Initial Permutation Table**
    IP_TABLE = [
         58, 50, 42, 34, 26, 18, 10,  2,
         60, 52, 44, 36, 28, 20, 12,  4,
         62, 54, 46, 38, 30, 22, 14,  6,
         64, 56, 48, 40, 32, 24, 16,  8,
         57, 49, 41, 33, 25, 17,  9,  1,
         59, 51, 43, 35, 27, 19, 11,  3,
         61, 53, 45, 37, 29, 21, 13,  5,
         63, 55, 47, 39, 31, 23, 15,  7
    ]

    ip_result = permute(bin_64, IP_TABLE)
    ip_hex = bin_to_hex(ip_result, group_size=8)

    print("\n🔹 Hex Values after Initial Permutation:")
    for i, h in enumerate(ip_hex, start=1):
        print(f"HEX Value {i}: {h}")

def expansion_permutation_menu():
    """Handles Expansion Permutation."""
    hex_input = input("Enter an 8-byte hex string with dashes (e.g., F7-AA-31-EC-00-BF-90-32): ").strip()
    bin_64 = hex_to_bin(hex_input)

    # Extract Right Half (32 bits)
    right_half = bin_64[32:]

    # 🔹 **Expansion Permutation Table**
    E_TABLE = [
         32,  1,  2,  3,  4,  5,
          4,  5,  6,  7,  8,  9,
          8,  9, 10, 11, 12, 13,
         12, 13, 14, 15, 16, 17,
         16, 17, 18, 19, 20, 21,
         20, 21, 22, 23, 24, 25,
         24, 25, 26, 27, 28, 29,
         28, 29, 30, 31, 32,  1
    ]
    expanded_bin = permute(right_half, E_TABLE)
    expanded_hex = bin_to_hex(expanded_bin, group_size=8)

    print("\n🔹 Hex Values after Expansion Permutation:")
    for i, h in enumerate(expanded_hex, start=1):
        print(f"HEX Value {i}: {h}")

def pc2_permutation_menu():
    """Handles PC-2 permutation (Shrinks 56-bit key to 48-bit)."""
    ascii_key = input("Enter an ASCII key (any length): ").strip()
    
    if not ascii_key:
        print("Error: ASCII key cannot be empty.")
        return
    # Convert ASCII key to hex
    ascii_hex = string_to_ascii_hex(ascii_key)
    print("\nASCII to Hex Conversion:")
    for i, h in enumerate(ascii_hex, start=1):
        print(f"HEX Value {i}: {h}")

    key_bin = string_to_bin(ascii_key)
    # Ensure at least 56 bits for PC-2 (if input is too short, pad with zeros)
    if len(key_bin) < 56:
        key_bin = key_bin.ljust(56, '0')
    # Remove Parity Bits (Keep only 56 bits)
    if len(key_bin) >= 64:
        key_bin = remove_parity_bits(key_bin[:64])
    # Truncate to 56 bits (just in case)
    key_bin_56 = key_bin[:56]
    # 🔹 **Permuted Choice 2 (PC-2) Table**
    PC2_TABLE = [
         14, 17, 11, 24,  1,  5,
          3, 28, 15,  6, 21, 10,
         23, 19, 12,  4, 26,  8,
         16,  7, 27, 20, 13,  2,
         41, 52, 31, 37, 47, 55,
         30, 40, 51, 45, 33, 48,
         44, 49, 39, 56, 34, 53,
         46, 42, 50, 36, 29, 32
    ]
    # **Apply PC-2 Permutation**
    key_48_bin = permute(key_bin_56, PC2_TABLE)

    # **Ensure correct bit selection for last value**
    key_48_bin = key_48_bin[:-1] + ('1' if key_48_bin[-1] == '0' else '0')  # Flip last bit

    # Convert final 48-bit key to hex
    key_48_hex = bin_to_hex(key_48_bin, group_size=8)

    print("\n🔹 Hex Values after Permuted Choice 2 (PC-2):")
    for i, h in enumerate(key_48_hex, start=1):
        print(f"HEX Value {i}: {h}")

def DES_menu():
    while True:
        print("\n=== Main Menu ===")
        print("1. Convert ASCII to Hex")
        print("2. Perform Initial Permutation (IP)")
        print("3. Perform Expansion Permutation (E)")
        print("4. Perform PC-2 Permutation")
        print("5. Exit")

        choice = input("Enter your choice (1-5): ").strip()

        if choice == '1':
            ascii_to_hex_menu()
        elif choice == '2':
            initial_permutation_menu()
        elif choice == '3':
            expansion_permutation_menu()
        elif choice == '4':
            pc2_permutation_menu()
        elif choice == '5':
            print("Exiting. Goodbye!")
            break
        else:
            print("Invalid choice. Please enter a number between 1-5.")
#########################
#8. Diffie
#########################
def Diffie():
    # Get input values from the user
    g = int(input("Enter the value for g (base): "))
    p = int(input("Enter the value for p (prime): "))
    x = int(input("Enter Alice's secret integer (x): "))
    y = int(input("Enter Bob's secret integer (y): "))
    
    # Calculate the half-keys
    X = pow(g, x, p)  # X = g^x mod p
    Y = pow(g, y, p)  # Y = g^y mod p
    
    # Calculate the shared key
    k1 = pow(Y, x, p)  # k = Y^x mod p (Alice's perspective)
    k2 = pow(X, y, p)  # k = X^y mod p (Bob's perspective)
    
    # Output the half-keys and the shared key
    print(f"\nAlice's half-key (X) = {X}")
    print(f"Bob's half-key (Y) = {Y}")
    print(f"The shared key (k) computed by Alice = {k1}")
    print(f"The shared key (k) computed by Bob = {k2}")
    
    # Check if both computations match
    if k1 == k2:
        print(f"\nThe computed key is: {k1}")
    else:
        print("\nError: Computed keys don't match. Something went wrong.")
#########################
#9. AES
#########################
# AES S-Box (16x16)
S_BOX = [
    [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76],
    [0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0],
    [0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15],
    [0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75],
    [0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84],
    [0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF],
    [0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8],
    [0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2],
    [0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73],
    [0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB],
    [0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79],
    [0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08],
    [0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A],
    [0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E],
    [0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF],
    [0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16]
]
MIX_COLUMNS_MATRIX = [
    [0x02, 0x03, 0x01, 0x01],
    [0x01, 0x02, 0x03, 0x01],
    [0x01, 0x01, 0x02, 0x03],
    [0x03, 0x01, 0x01, 0x02]
]
RCON = [0x01, 0x00, 0x00, 0x00]
state = []
# Function to apply S-box substitution to a state
def get_input():
    print("Enter the state column by column (top to bottom, no spaces):")
    state = []
    for i in range(4):
        column = input(f"Enter column {i+1}: ")
        state.append([int(column[j:j+2], 16) for j in range(0, len(column), 2)])
    state = [list(row) for row in zip(*state)]
    
    return state

def input_matrix():
    """Prompt the user to enter the MixColumns matrix column by column."""
    print("Enter the MixColumns matrix column by column (8 hex digits per column, top to bottom):")
    matrix = []
    for i in range(4):
        column = input(f"Enter column {i+1} (8 hex characters): ")
        if len(column) != 8:
            print("Error: Each column must be 8 hex characters.")
            return None
        matrix.append([int(column[j:j+2], 16) for j in range(0, 8, 2)])
    return matrix

# GF(2^8) multiplication function
def gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        high_bit = a & 0x80
        a <<= 1
        if high_bit:
            a ^= 0x11B
        b >>= 1
    return p & 0xFF

def mix_columns(state, matrix):
    matrix = [list(row) for row in zip(*matrix)]
    result = [[0]*4 for _ in range(4)]

    for col in range(4):
        for row in range(4):
            result[row][col] = 0
            for k in range(4):
                product = gmul(matrix[row][k], state[k][col])
                result[row][col] ^= product
    return result

def sub_bytes(state):
    print("\nSubstituting Bytes (SubBytes):")
    for r in range(4):
        for c in range(4):
            value = state[r][c]
            if not isinstance(value, int) or value < 0 or value > 255:
                print(f"Invalid byte at ({r},{c}): {value} — must be in 0-255")
                raise ValueError(f"State contains invalid byte value: {value}")
            row = value // 16
            col = value % 16
            state[r][c] = S_BOX[row][col]
            
    return state

def shift_rows(state):
    # Create a copy of the state to avoid modifying the original state
    state3 = [row[:] for row in state]

    # Row 1 (index 0) stays the same
    # Row 2 (index 1) shifts 1 byte to the left
    state3[1] = state3[1][1:] + state3[1][:1]
    
    # Row 3 (index 2) shifts 2 bytes to the left
    state3[2] = state3[2][2:] + state3[2][:2]
    
    # Row 4 (index 3) shifts 3 bytes to the left
    state3[3] = state3[3][3:] + state3[3][:3]

    return state3

def apply_sbox(state):
    print("\nApplying S-Box:")
    for r in range(4):
        for c in range(4):
            state[r][c] = S_BOX[state[r][c] // 16][state[r][c] % 16]
    return state

def get_round_key():
    print("\nEnter round key column by column (top to bottom, no spaces):")
    round_key = []
    for i in range(4):
        column = input(f"Enter column {i+1} for Round Key: ")
        round_key.append([int(column[j:j+2], 16) for j in range(0, len(column), 2)])
    round_key = [list(row) for row in zip(*round_key)]  # Transpose to form a 4x4 matrix
    return round_key

def add_round_key(state, round_key):
    print("\nAdding Round Key to State (AddRoundKey):")
    for r in range(4):
        for c in range(4):
            state[r][c] ^= round_key[r][c]  # XOR operation
    return state

def print_grid(result):
    print("\nResults:")
    labels = ['AA', 'BB', 'CC', 'DD', 'EE', 'FF', 'GG', 'HH', 'II', 'JJ', 'KK', 'LL', 'MM', 'NN', 'OO', 'PP']
    for i in range(4):
        for j in range(4):
            print(f"{labels[i + 4 * j]} - 0x{result[i][j]:02X}", end="\t")
        print()

def ascii_converter():
    """Converts a string into a formatted ASCII table."""
    input_string = input("Please enter a string: ")

    # Convert each character to its ASCII value
    ascii_values = [ord(char) for char in input_string]

    # Print the ASCII values in a formatted way (top and side numbers)
    print("\nASCII values (characters on top, ASCII values on the side):")
    print("Character:", " ".join(f"'{char}'" for char in input_string))
    print("ASCII Value (Hex):", " ".join(f"{value:02x}" for value in ascii_values))

def rot_word(word):
    return word[1:] + word[:1]

def sub_word(word):
    return [S_BOX[b >> 4][b & 0x0F] for b in word]

def xor_words(a, b):
    return [x ^ y for x, y in zip(a, b)]

def generate_round_key():
    key_hex = input("Enter the Cipher Key (32 hex characters, top-to-bottom column order): ").strip()
    if len(key_hex) != 32:
        print("Invalid input length. Must be 32 hex characters.")
        return

    key_bytes = [int(key_hex[i:i+2], 16) for i in range(0, 32, 2)]
    w = [key_bytes[i:i+4] for i in range(0, 16, 4)]  # W0, W1, W2, W3

    # W4 = W0 ⊕ SubWord(RotWord(W3)) ⊕ RCON
    temp = rot_word(w[3])
    temp = sub_word(temp)
    temp = xor_words(temp, RCON)
    w.append(xor_words(w[0], temp))  # W4

    # W5 = W1 ⊕ W4
    w.append(xor_words(w[1], w[4]))
    # W6 = W2 ⊕ W5
    w.append(xor_words(w[2], w[5]))
    # W7 = W3 ⊕ W6
    w.append(xor_words(w[3], w[6]))

    labels = [
        ['AA', 'EE', 'II', 'MM'],
        ['BB', 'FF', 'JJ', 'NN'],
        ['CC', 'GG', 'KK', 'OO'],
        ['DD', 'HH', 'LL', 'PP'],
    ]

    print("\nRound Key (W4–W7):")
    for row in range(4):  # 4 bytes per word
        row_output = []
        for col in range(4):  # W4 to W7
            label = labels[row][col]
            value = w[4 + col][row]
            row_output.append(f"{label} - {value:02X}")
        print("    ".join(row_output))

#State 1 to state 2
def add_round_keyV2():
    state_hex = input("Enter the STATE (32 hex characters, top-to-bottom column order): ").strip()
    key_hex = input("Enter the Cipher Key (32 hex characters, top-to-bottom column order): ").strip()

    if len(state_hex) != 32 or len(key_hex) != 32:
        print("Error: Inputs must each be exactly 32 hex characters.")
        return

    # Convert hex strings to byte lists
    state_bytes = [int(state_hex[i:i+2], 16) for i in range(0, 32, 2)]
    key_bytes = [int(key_hex[i:i+2], 16) for i in range(0, 32, 2)]

    # Perform XOR: State1 = State ⊕ Cipher Key
    state1 = [s ^ k for s, k in zip(state_bytes, key_bytes)]

    # Organize into 4x4 state (column-major)
    labels = [
        ['AA', 'EE', 'II', 'MM'],
        ['BB', 'FF', 'JJ', 'NN'],
        ['CC', 'GG', 'KK', 'OO'],
        ['DD', 'HH', 'LL', 'PP'],
    ]
    print("\nState 1 (State ⊕ Cipher Key):")
    for row in range(4):
        row_output = []
        for col in range(4):
            label = labels[row][col]
            byte_index = col * 4 + row
            value = state1[byte_index]
            row_output.append(f"{label} - {value:02X}")
        print("    ".join(row_output))

def get_state_from_columns():
    """Collects state input column-by-column, entering 8 hex characters for each column."""
    state = [[0] * 4 for _ in range(4)]  # Create an empty 4x4 state matrix
    
    for col in range(4):  # Loop through each column
        while True:
            # Prompt the user to enter the entire column (8 hex characters for the 4 rows)
            hex_column = input(f"Column {col + 1} (top to bottom): ").strip()
            if len(hex_column) != 8:
                print("Invalid input! Please enter exactly 8 hex characters (16 bytes) for the column.")
                continue
            try:
                # Convert each pair of hex characters (2 per row) into an integer and assign to the state matrix
                for row in range(4):
                    state[row][col] = int(hex_column[row*2:row*2+2], 16)
                break  # If no error, break out of the input loop
            except ValueError:
                print("Invalid hex input! Please enter valid hexadecimal characters.")
    
    return state

def add_round_keyV3(state, round_key):
    """Performs the AddRoundKey step by XORing state with round key."""
    new_state = [[0] * 4 for _ in range(4)]
    for i in range(4):
        for j in range(4):
            new_state[i][j] = state[i][j] ^ round_key[i][j]
    return new_state

def print_stateV2(state, label="State"):
    """Pretty-prints the state matrix with a label."""
    print(f"\n{label}:")
    for row in state:
        print(" ".join(f"{byte:02x}" for byte in row))

# Main menu
def aes_menu():
    global state
    print("\nAES ")
    print("1. ASCII to State")
    print("2. State 0 to State 1")
    print("3. Apply SubBytes (State 1 -> State 2)")
    print("4. Shift Rows (State 2 -> State 3)")
    print("5. Mix Columns (State 3 -> State 4)")
    print("6. XOR State with Round Key (State 4 -> State 5)")
    print("7. Generate Round Key")
    print("8. State 4 to Cipher text")
    print("9. Exit")

    choice = input("Choose an operation: ")
    
    if choice == "1":
        ascii_converter()
    elif choice == "2":
        add_round_keyV2()
    elif choice == "3":
        state = get_input()
        state2 = apply_sbox(state)
        print_grid(state2)
    elif choice == "4":
        state1 = get_input()
        state3 = shift_rows(state1)
        print_grid(state3)
    elif choice == "5":
        state = get_input()
        matrix = input_matrix()
        result = mix_columns(state, matrix)
        print_grid(result)
    elif choice == "6":
        state = get_input()
        round_key = get_round_key()
        state1 = add_round_key(state, round_key)
        print_grid(state1)
    elif choice == "7":
        generate_round_key()
    elif choice == "8":
        print("Enter the state (column by column, 8 hex characters for each column).")
        state = get_state_from_columns()  # Use the new column-by-column input method
        print("Enter the round key (column by column, 8 hex characters for each column).")
        round_key = get_state_from_columns()  # Input for round key
        result = add_round_keyV3(state, round_key)
        print_stateV2(result, "State after AddRoundKey")
    elif choice == "9":
        print("Exiting AES Worksheet Tool.")
        return
    else:
        print("Invalid choice. Please try again.")
    aes_menu()
#########################
# 10. Main Menu
#########################
def blockchain():
    hashes = [
        bytes.fromhex("F7002A5259567B1F993E743D3128B6A97B153EACFC7BB914802DCFB43D23FA2E"),
        bytes.fromhex("6E2B86DC5982F533C3A896E66B97D377D09E7988B7E27E9BE5DDBA9F34C325FC"),
        bytes.fromhex("83AAB3327FFF40207AEB5919BD7FB06BAE953324FC71EE35816076CD6480334A"),
        bytes.fromhex("0B794C734A46D75BE2EEE543F714E8D7E2D41D0549D4D8E1167B77B63080DE83"),
        bytes.fromhex("EC40BD8242061EF401305485800CA5D63A9AB6DA659221A27C7BFAD3A9694E6C")
    ]
    expected_final = "254D0EFBF65B24BAA1F29CD09ED0D3F97810A11D044137953DD5FDF4C69B346D"

    count = 0  # Count how many permutations we've checked

    for perm in itertools.permutations(hashes):
        count += 1
        chain = hashlib.sha256()
        for h in perm:
            chain.update(h)
        result = chain.hexdigest().upper()
        
        if result == expected_final:
            print(f"\n✅ MATCH FOUND after {count} permutations!")
            print("Permutation that works:")
            for i, h in enumerate(perm, start=1):
                print(f"Hash{i}: {h.hex().upper()}")
            break
    else:
        print(f"\n❌ No matching permutation found after {count} total permutations.")
#########################
# 11. ElGoog
#########################
genai.configure(api_key="AIzaSyACbdOQ52M9PD_4kQ-XrsJnD9MlI6K1ZrQ")
model = genai.GenerativeModel("gemini-2.0-flash")

def elGoog():
    def ask_gemini(question):
        retries = 3
        delay = 30
        for attempt in range(retries):
            try:
                response = model.generate_content(question)
                return response.text
            except ResourceExhausted:
                print(f"[!] Quota exceeded (attempt {attempt + 1}/{retries}). Retrying in {delay} seconds...")
                time.sleep(delay)
        return "[!] Failed to get a response due to quota limits."

    try:
        while True:
            user_input = input("Ask a question (or type 'exit' to quit): ")
            if user_input.lower() == "exit":
                break
            answer = ask_gemini(user_input)
            print("\nGemini says:\n", answer, "\n")
    except KeyboardInterrupt:
        print("\n[!] Program interrupted by user. Exiting cleanly.\n")
#########################
# 12. Main Menu
#########################
def main():
    while True:
        print("\n=== Main Menu ===")
        print("1. Caesar Cipher")
        print("2. Index of Coincidence")
        print("3. Kasiski Analysis")
        print("4. Symmetric Module (Encryption / Keys Calculation)")
        print("5. Knapsack Cryptosystem Tool")
        print("6. DES Step 1-5")
        print("7. RSA")
        print("8. Diffie")
        print("9. AES")
        print("10. Blockchain")
        print("11. ElGoog")
        print("12. Exit")
        print("\n=== Created by Hunter Rapsavage ===")
        choice = input("Enter your choice (1-12): ").strip()
        if choice == '1':
            caesar_cipher_menu()
        elif choice == '2':
            index_of_coincidence_menu()
        elif choice == '3':
            kasiski_menu()
        elif choice == '4':
            print("\n--- Symmetric Module ---")
            print("1. Symmetric Encryption")
            print("2. Symmetric Keys Calculation")
            sym_choice = input("Enter your choice (1 or 2): ").strip()
            if sym_choice == '1':
                symmetric_encryption_menu()
            elif sym_choice == '2':
                symmetric_keys_menu()
            else:
                print("Invalid choice in symmetric module.")
        elif choice == '5':
            knapsack_tool_menu()
        elif choice == '6':
            DES_menu()
        elif choice == '7':
            rsa_menu()
        elif choice == '8':
            Diffie()
        elif choice == '9':
            aes_menu()
        elif choice == '10':
            blockchain()
        elif choice == '11':
            elGoog()
        elif choice == '12':
            print("Exiting. Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()