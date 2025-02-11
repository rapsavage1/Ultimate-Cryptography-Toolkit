def encrypt_block(binary_block, knapsack):
    """
    Encrypt a single binary block using the provided knapsack.
    binary_block: A string of 0's and 1's (e.g., "1001").
    knapsack: A list of integers (e.g., [7, 9, 10, 9]).
    Returns the dot product as an integer.
    """
    return sum(int(bit) * k for bit, k in zip(binary_block, knapsack))


def get_knapsack_input(prompt):
    """
    Reads a knapsack input from the user.
    Accepts comma-separated or space-separated integers.
    Returns a list of integers.
    """
    s = input(prompt).strip()
    return list(map(int, s.replace(",", " ").split()))


def compute_hard_knapsack(simple_knapsack, W, N):
    """
    Given a simple (super increasing) knapsack, multiplier W, and modulus N,
    compute the Hard (public) knapsack:
         H = [ (W * s) mod N  for each s in simple_knapsack ].
    """
    return [(W * s) % N for s in simple_knapsack]


def mod_inverse(a, m):
    """
    Compute the modular inverse of a modulo m using the extended Euclidean algorithm.
    Returns x such that (a * x) mod m == 1, or None if no inverse exists.
    """

    def egcd(a, b):
        if a == 0:
            return b, 0, 1
        g, x, y = egcd(b % a, a)
        return g, y - (b // a) * x, x

    g, x, _ = egcd(a, m)
    if g != 1:
        return None
    return x % m


def decrypt_block(ciphertext_value, simple_knapsack, w_inv, N):
    """
    Decrypt a single ciphertext integer.
    Computes X = (w_inv * ciphertext_value) mod N and then uses the simple
    knapsack (which is super increasing) to solve the subset sum and recover the plaintext block (in binary).
    """
    X = (w_inv * ciphertext_value) % N
    n = len(simple_knapsack)
    bits = [0] * n
    # Process the simple knapsack in reverse order (greedy algorithm)
    for i in range(n - 1, -1, -1):
        if simple_knapsack[i] <= X:
            bits[i] = 1
            X -= simple_knapsack[i]
        else:
            bits[i] = 0
    return "".join(str(bit) for bit in bits)


def compute_values(w, n):
    """
    Compute the multiplicative inverse of w modulo n using Fermat's Little Theorem.
    Assumes n is prime.
    Returns the inverse.
    """
    return pow(w, n - 2, n)


def knapsack_encryption_decryption():
    print("\n--- Knapsack Encryption/Decryption ---")
    operation = (
        input("Choose operation - Enter 'E' for Encryption or 'D' for Decryption: ")
        .strip()
        .upper()
    )

    if operation == "E":
        knapsack_type = (
            input("Choose knapsack type - Enter 'S' for Simple or 'H' for Hard: ")
            .strip()
            .upper()
        )
        W = int(input("Enter the multiplier (W): "))
        N = int(input("Enter the modulus (N): "))

        if knapsack_type == "S":
            simple_knapsack = get_knapsack_input(
                "Enter the simple (super increasing) knapsack as integers (e.g., 2 42 94 233): "
            )
            public_knapsack = compute_hard_knapsack(simple_knapsack, W, N)
            print("\nSimple Knapsack (S):", simple_knapsack)
            print("Computed Hard Knapsack (H):", public_knapsack)
        elif knapsack_type == "H":
            public_knapsack = get_knapsack_input(
                "Enter the hard knapsack as integers (e.g., 7 9 10 9): "
            )
            print("\nUsing Hard Knapsack (H):", public_knapsack)
        else:
            print("Invalid knapsack type. Exiting.")
            return

        # (Optional) Compute and display the multiplicative inverse.
        w_inverse = mod_inverse(W, N)
        if w_inverse is None:
            print("Error: Multiplicative inverse does not exist for given W and N.")
            return
        print("\nComputed Multiplicative Inverse (w⁻¹):", w_inverse)

        encrypt_option = (
            input("\nDo you want to encrypt a plaintext? (Y/N): ").strip().upper()
        )
        if encrypt_option == "Y":
            plaintext = input(
                "Enter the binary plaintext to encrypt (blocks separated by spaces): "
            ).strip()
            blocks = plaintext.split()
            knapsack_length = len(public_knapsack)
            # Verify each block's length matches the knapsack length.
            for i, block in enumerate(blocks):
                if len(block) != knapsack_length:
                    print(
                        f"Error: Block {i+1} has length {len(block)} but knapsack length is {knapsack_length}."
                    )
                    return
            ciphertext = []
            print("\nCiphertext values (in integer format):")
            for i, block in enumerate(blocks):
                c_val = encrypt_block(block, public_knapsack)
                ciphertext.append(c_val)
                print(f"C{i+1}: {c_val}")
            if len(ciphertext) != 4:
                print(
                    f"\nNote: Expected 4 ciphertext values (C1, C2, C3, C4), but got {len(ciphertext)}."
                )
        else:
            print("\nEncryption step skipped.")

    elif operation == "D":
        print("\n--- Decryption Process ---")
        simple_knapsack = get_knapsack_input(
            "Enter the simple (super increasing) knapsack as integers (e.g., 2 12 25 71): "
        )
        W = int(input("Enter the multiplier (W): "))
        N = int(input("Enter the modulus (N): "))
        w_inverse = mod_inverse(W, N)
        if w_inverse is None:
            print("Error: Multiplicative inverse does not exist for given W and N.")
            return
        print("\nSimple Knapsack (S):", simple_knapsack)
        print("Multiplier (W):", W)
        print("Modulus (N):", N)
        print("Computed Multiplicative Inverse (w⁻¹):", w_inverse)
        ciphertext_input = input(
            "Enter the ciphertext values as integers (e.g., 42,41,58,24): "
        ).strip()
        ciphertext = list(map(int, ciphertext_input.replace(",", " ").split()))
        print("\nDecrypted binary blocks (each block with appropriate digits):")
        for i, c_val in enumerate(ciphertext):
            decrypted = decrypt_block(c_val, simple_knapsack, w_inverse, N)
            print(f"Block {i+1}: {decrypted}")
    else:
        print("Invalid operation selected. Exiting.")


def compute_hard_knapsack_menu():
    print("\n--- Compute Hard Knapsack ---")
    knapsack_type = (
        input("Choose knapsack type - Enter 'S' for Simple or 'H' for Hard: ")
        .strip()
        .upper()
    )
    W = int(input("Enter the multiplier (W): "))
    N = int(input("Enter the modulus (N): "))

    if knapsack_type == "S":
        simple_knapsack = get_knapsack_input(
            "Enter the simple (super increasing) knapsack as integers (e.g., 2 42 94 233): "
        )
        public_knapsack = compute_hard_knapsack(simple_knapsack, W, N)
        print("\nSimple Knapsack (S):", simple_knapsack)
        print("Computed Hard Knapsack (H):", public_knapsack)
    elif knapsack_type == "H":
        public_knapsack = get_knapsack_input(
            "Enter the hard knapsack as integers (e.g., 7 9 10 9): "
        )
        print("\nUsing Hard Knapsack (H):", public_knapsack)
    else:
        print("Invalid knapsack type. Exiting.")


def compute_inverse_menu():
    print("\n--- Compute Multiplicative Inverse of W ---")
    w = int(input("Enter the value of w: "))
    n = int(input("Enter the value of n (n should be prime): "))
    inverse = compute_values(w, n)
    print(f"\nThe Multiplicative Inverse of W is: {inverse}")


def main():
    print("Merkle-Hellman Cryptosystem Tool")
    print("--------------------------------")
    print("Choose an option:")
    print("1. Knapsack Encryption/Decryption")
    print("2. Compute Hard Knapsack")
    print("3. Compute Multiplicative Inverse of W")
    choice = input("Enter your choice (1, 2, or 3): ").strip()

    if choice == "1":
        knapsack_encryption_decryption()
    elif choice == "2":
        compute_hard_knapsack_menu()
    elif choice == "3":
        compute_inverse_menu()
    else:
        print("Invalid choice. Exiting.")


if __name__ == "__main__":
    main()