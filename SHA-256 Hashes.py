import hashlib

# Hash a string using SHA-256
def sha256_string(input_string):
    return hashlib.sha256(input_string.encode()).hexdigest()

# Hash a file using SHA-256
def sha256_file(file_path):
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except FileNotFoundError:
        return "File not found."

# Main program
if __name__ == "__main__":
    print("Welcome to the SHA-256 Hash Generator!")
    choice = input("Type 's' to hash a string or 'f' to hash a file: ").lower()

    if choice == 's':
        user_input = input("Enter the string to hash: ")
        print("SHA-256 hash:", sha256_string(user_input))
    elif choice == 'f':
        file_path = input("Enter the full path to the file: ")
        print("SHA-256 hash:", sha256_file(file_path))
    else:
        print("Invalid choice. Please restart and choose 's' or 'f'.")
