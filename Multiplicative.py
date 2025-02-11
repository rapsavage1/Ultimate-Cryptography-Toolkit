from sympy import mod_inverse

W = int(input("Enter W: "))
N = int(input("Enter N: "))

print("Multiplicative inverse:", mod_inverse(W, N))