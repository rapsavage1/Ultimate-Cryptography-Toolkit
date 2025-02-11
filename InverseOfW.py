"USE knapsack.py file"

def compute_values(w, n):
    # Compute the multiplicative inverse using Fermat's Little Theorem.
    # For prime n, the inverse is: w^(n-2) mod n.
    inverse = pow(w, n - 2, n)
    
    # Compute the yield of the multiplication: (w * inverse) mod n.
    yield_val = (w * inverse) % n
    
    # Compute M3: w^w mod n.
    m3 = pow(w, w, n)
    
    return inverse, yield_val, m3

# Ask the user for inputs.
w = int(input("Enter the value of w: "))
n = int(input("Enter the value of n: "))

# Compute the values.
inverse, yield_val, m3 = compute_values(w, n)

# Print the computed values.
print(f"M1: w^-1 = w^(n-2) mod n = {inverse}")
# For M2, we want the multiplicative inverse value, not the verification result (1).
print(f"M2: Multiplicative Inverse (expected) = {inverse} (not the verification result of {yield_val})")
print(f"M3: w^w mod n = {m3}")