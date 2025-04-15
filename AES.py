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

    # print("Enter the matrix column by column (top to bottom, no spaces):")
    # matrix = []
    # for i in range(4):
    #     column = input(f"Enter matrix column {i+1}: ")
    #     matrix.append([int(column[j:j+2], 16) for j in range(0, len(column), 2)])
    
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
    return matrix  # No need to transpose; matrix is used as-is in mix_columns

def print_state(state, label):
    """Print the state matrix in 2-digit hex format."""
    print(label)
    for i in range(4):
        for j in range(4):
            print(f"{chr(65+i)}{chr(65+j)} - {state[i][j]:02X}")

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

def xor_state_with_key(state, key):
    print("\nXORing State with Key (AddRoundKey):")
    for r in range(4):
        for c in range(4):
            state[r][c] ^= key[r][c]  # XOR operation
    return state

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

def parse_state(state_input):
    """Parses a 32-character hexadecimal string into a 4x4 state matrix."""
    state = []
    for i in range(4):
        column = state_input[i*8:(i+1)*8]
        state.append([int(column[j:j+2], 16) for j in range(0, len(column), 2)])
    return [list(row) for row in zip(*state)]  # Transpose to form a 4x4 matrix

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

if __name__ == "__main__":
    aes_menu()
