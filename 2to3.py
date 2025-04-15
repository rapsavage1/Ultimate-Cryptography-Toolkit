# Function to apply the Shift Rows operation
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

# Function to take user input for STATE 2 (4 rows, 8 hexadecimal digits per row)
def get_state2_input():
    state2 = []
    print("Enter the values for STATE 2 (4 rows, 8 hexadecimal digits per row):")
    
    for row in range(4):
        row_input = input(f"Enter row {row + 1} (8 digits in hexadecimal, e.g., '964c0f41'): ").strip()
        if len(row_input) != 8 or not all(c in '0123456789abcdefABCDEF' for c in row_input):
            print(f"Invalid input. Please enter exactly 8 hexadecimal digits for row {row + 1}.")
            return None
        
        # Convert the input into a list of 4-byte integers
        row_values = [int(row_input[i:i+2], 16) for i in range(0, 8, 2)]
        state2.append(row_values)
    
    return state2

# Get STATE 2 from user input
state2 = get_state2_input()
if state2 is None:
    print("Exiting program due to invalid input.")
else:
    # Perform the Shift Rows operation to get STATE 3
    state3 = shift_rows(state2)

    # Printing the STATE 3 result in the same format
    print("\nSTATE 3 after Shift Rows operation:")
    labels = ['AA', 'BB', 'CC', 'DD', 'EE', 'FF', 'GG', 'HH', 'II', 'JJ', 'KK', 'LL', 'MM', 'NN', 'OO', 'PP']
    counter = 0

    # For each row, print out the shifted state in the required format
    for r in range(4):
        for c in range(4):
            print(f"{labels[counter]} - 0x{state3[r][c]:02x}")
            counter += 1
