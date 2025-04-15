def diffie_hellman():
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
diffie_hellman()