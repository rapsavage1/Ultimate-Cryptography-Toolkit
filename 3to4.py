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

def get_input():
    print("Enter the state column by column (top to bottom, no spaces):")
    state = []
    for i in range(4):
        column = input(f"Enter column {i+1}: ")
        state.append([int(column[j:j+2], 16) for j in range(0, len(column), 2)])
    state = [list(row) for row in zip(*state)]

    print("Enter the matrix column by column (top to bottom, no spaces):")
    matrix = []
    for i in range(4):
        column = input(f"Enter matrix column {i+1}: ")
        matrix.append([int(column[j:j+2], 16) for j in range(0, len(column), 2)])
    
    return state, matrix

def print_grid(result):
    print("\nResulting State 4:")
    labels = ['AA', 'BB', 'CC', 'DD', 'EE', 'FF', 'GG', 'HH', 'II', 'JJ', 'KK', 'LL', 'MM', 'NN', 'OO', 'PP']
    for i in range(4):
        for j in range(4):
            print(f"{labels[i + 4 * j]} - 0x{result[i][j]:02X}", end="\t")
        print()

def main():
    state, matrix = get_input()
    result = mix_columns(state, matrix)
    print_grid(result)

if __name__ == "__main__":
    main()
