from collections import Counter
import string

def calculate_ic(text):
    # Remove non-alphabetic characters and convert to uppercase
    text = ''.join(filter(str.isalpha, text)).upper()
    
    # Count letter frequencies
    letter_counts = Counter(text)
    total_letters = sum(letter_counts.values())
    
    # Calculate Index of Coincidence
    ic = sum(f * (f - 1) for f in letter_counts.values()) / (total_letters * (total_letters - 1)) if total_letters > 1 else 0
    
    # Display letter frequencies
    print("Letter frequencies:")
    for letter in string.ascii_uppercase:
        print(f"{letter}: {letter_counts.get(letter, 0)}")
    
    print(f"\nIndex of Coincidence: {ic:.6f}")
    return ic

# Example usage
if __name__ == "__main__":
    sample_text = input("Enter the text: ")
    calculate_ic(sample_text)