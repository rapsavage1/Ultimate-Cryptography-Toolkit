import string

def caesar_cipher(text, shift, decrypt=False):
    if decrypt:
        shift = -shift

    alphabet = string.ascii_uppercase
    shifted_alphabet = alphabet[shift:] + alphabet[:shift]
    translation_table = str.maketrans(alphabet, shifted_alphabet)

    text = text.upper()
    translated_text = text.translate(translation_table)

    return translated_text

# Example usage
if __name__ == "__main__":
    mode = input("Enter 'E' to encrypt or 'D' to decrypt: ").strip().upper()
    text = input("Enter the text: ")
    shift = int(input("Enter the shift value: "))

    decrypt_mode = mode == "D"
    result = caesar_cipher(text, shift, decrypt=decrypt_mode)

    print(f"Result: {result}")