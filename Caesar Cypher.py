# Caesar Cipher Encryption
def caesar_encrypt(text, shift):
    encrypted = ""
    for char in text:
        if char.isalpha():
            base = 'A' if char.isupper() else 'a'
            encrypted += chr((ord(char) - ord(base) + shift) % 26 + ord(base))
        else:
            encrypted += char
    return encrypted

# Caesar Cipher Decryption
def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)

# Main program
if __name__ == "__main__":
    print("Welcome to the Caesar Cipher App!")
    choice = input("Type 'e' to encrypt or 'd' to decrypt: ").lower()

    if choice not in ['e', 'd']:
        print("Invalid choice. Please restart and choose 'e' or 'd'.")
    else:
        text = input("Enter the text: ")
        try:
            shift = int(input("Enter the shift value (e.g., 3): "))
        except ValueError:
            print("Shift must be a number.")
        else:
            if choice == 'e':
                result = caesar_encrypt(text, shift)
                print("Encrypted text:", result)
            else:
                result = caesar_decrypt(text, shift)
                print("Decrypted text:", result)


    
