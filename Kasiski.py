from collections import Counter
import math


# Function to find repeated sequences and calculate their distances
def find_repeated_sequences(ciphertext, seq_length=15):
    repeated_sequences = {}

    # Iterate through the ciphertext to find all sequences of length seq_length
    for i in range(len(ciphertext) - seq_length + 1):
        seq = ciphertext[i : i + seq_length]
        if seq in repeated_sequences:
            repeated_sequences[seq].append(i + 1)  # Count positions from 1
        else:
            repeated_sequences[seq] = [i + 1]  # Count positions from 1

    return repeated_sequences


# Function to calculate the factors of a number
def find_factors(num):
    factors = set()
    for i in range(1, num + 1):
        if num % i == 0:
            factors.add(i)
    return factors


# Function to determine the probable key length using Kasiski's method
def kasiski_method(ciphertext, seq_length=15):
    # Step 1: Find repeated sequences and their positions
    repeated_sequences = find_repeated_sequences(ciphertext, seq_length)

    # Step 2: Find the longest repeating sequence (by the most number of occurrences)
    longest_sequence = max(
        repeated_sequences, key=lambda k: len(repeated_sequences[k]), default=None
    )
    positions = repeated_sequences.get(longest_sequence, [])

    # If no repeated sequences found, return None
    if not positions:
        return None, None

    # Step 3: Calculate the distances between positions
    distances = [positions[i + 1] - positions[i] for i in range(len(positions) - 1)]

    # Step 4: Find the factors of each distance and the greatest common factor (GCD)
    if distances:
        common_factors = find_factors(distances[0])
        for dist in distances[1:]:
            common_factors &= find_factors(dist)

    return longest_sequence, positions, distances, common_factors


# Ask the user to input the ciphertext
ciphertext = input("Please enter the ciphertext: ")

# Call the kasiski_method function to find the probable key length
longest_sequence, positions, distances, common_factors = kasiski_method(
    ciphertext, seq_length=15
)

if longest_sequence:
    print(f"\nLongest repeating sequence: {longest_sequence}")

    # Display all positions for the longest repeating sequence
    for i, pos in enumerate(positions, start=1):
        print(f"Location of #{i} instance: {pos}")

    # Display the differences between the positions
    for i in range(1, len(positions)):
        print(
            f"Difference between the #{i+1} and #{i} location: {positions[i] - positions[i - 1]}"
        )

    if len(distances) > 0:
        print(
            f"\nThe common factor among all of the differences (greater than 1): {max(common_factors) if common_factors else 'No common factor greater than 1'}"
        )

        # Determine the probable key length as the highest common factor
        probable_key_length = max(common_factors) if common_factors else None
        print(f"The probable key length: {probable_key_length}")
else:
    print("No repeated sequences found.")
