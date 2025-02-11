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

def main():
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

if __name__ == "__main__":
    main()
