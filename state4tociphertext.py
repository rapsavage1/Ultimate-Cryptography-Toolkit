def get_state_from_columns():
    """Collects state input column-by-column, entering 8 hex characters for each column."""
    state = [[0] * 4 for _ in range(4)]  # Create an empty 4x4 state matrix
    
    for col in range(4):  # Loop through each column
        while True:
            # Prompt the user to enter the entire column (8 hex characters for the 4 rows)
            hex_column = input(f"Enter the 8 hex characters for column {col + 1} (top to bottom): ").strip()
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

def add_round_key(state, round_key):
    """Performs the AddRoundKey step by XORing state with round key."""
    new_state = [[0] * 4 for _ in range(4)]
    for i in range(4):
        for j in range(4):
            new_state[i][j] = state[i][j] ^ round_key[i][j]
    return new_state

def print_state(state, label="State"):
    """Pretty-prints the state matrix with a label."""
    print(f"\n{label}:")
    for row in state:
        print(" ".join(f"{byte:02x}" for byte in row))

def main():
    print("Enter the state (column by column, 8 hex characters for each column).")
    state = get_state_from_columns()  # Use the new column-by-column input method

    print("Enter the round key (column by column, 8 hex characters for each column).")
    round_key = get_state_from_columns()  # Input for round key

    # print_state(state, "Initial State")
    # print_state(round_key, "Round Key")

    result = add_round_key(state, round_key)
    print_state(result, "State after AddRoundKey")

if __name__ == "__main__":
    main()
