import string
import glob
import math
from collections import Counter
from cryptography.fernet import Fernet
from sympy import mod_inverse  # Used in some parts

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
# --- Symmetric Encryption Functions ---
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
# 6. DES Step 1-5
#########################
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
#########################
# 7. RSA
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
# 8. Main Menu
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
        print("8. Exit")
        choice = input("Enter your choice (1-7): ").strip()
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
            print("Exiting. Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()