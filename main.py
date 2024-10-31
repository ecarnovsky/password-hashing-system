import hashlib
from argon2 import PasswordHasher
import bcrypt
import os
from database_connection import DatabaseConnection
from user import User

argon2_hasher = PasswordHasher()

# Define functions
def hash_md5(password):
    return hashlib.md5(password.encode()).hexdigest()

def hash_sha512(password):
    return hashlib.sha512(password.encode()).hexdigest()

def hash_pbkdf2(password):
    salt = getSalt()
    hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return salt.hex() + hashed_password.hex()

def hash_argon2(password):
    hash_and_metadata =  argon2_hasher.hash(password)
    hashed_password = hash_and_metadata.split('$')[-1]
    return hashed_password


def hash_bcrypt(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).hex()

def hash_scrypt(password):
    return hashlib.scrypt(password.encode(), salt=getSalt(), n=16384, r=8, p=1).hex()

def getSalt():
    return os.urandom(16)

# Main function
def main():
    # Ensure the user table exists
    DatabaseConnection.create_user_table()

    while True:
        # Prompt the user for a username
        username = input("Enter a username: ")

        # Check if the username already exists in the database
        user = User(username, None, None, None, None)
        found_user = DatabaseConnection.find_user(user)

        if found_user:
            # Username exists, prompt for password to log in
            print("Username exists. Please log in.")
            stored_password = found_user.hashed_password
            password = input("Enter your password: ")

            # Verify the password
            if stored_password == hash_md5(password) or stored_password == hash_sha512(password) or stored_password == hash_pbkdf2(password):
                print("Login successful.")
            else:
                print("Incorrect password. Try again.")
                continue
        else:
            # Username is new, prompt to create a password
            print("Username created.")
            password = input("Enter a password: ")

        while True:
            # If the user successfully logs in, present the options
            if found_user:
                print("Do you want to:")
                print("1. Log out")
                print("2. Hash the password with a different algorithm")
                print("3. Change the password")
                next_action = input("Enter the number of your choice: ")

                if next_action == '1':
                    return
                elif next_action == '2':
                    pass  # Continue to the hashing algorithm selection
                elif next_action == '3':
                    # Prompt the user for a new password
                    password = input("Enter a new password: ")
                else:
                    print("Invalid choice, please try again.")
                    continue

            # Display a menu for selecting a hashing algorithm
            print("Select a hashing algorithm:")
            print("1. MD5")
            print("2. SHA-512")
            print("3. PBKDF2")
            print("4. Argon2")
            print("5. bcrypt")
            print("6. scrypt")
            choice = input("Enter the number of the hashing algorithm: ")

            # Hash the password using the selected algorithm
            if choice == '1':
                hashed_password = hash_md5(password)
            elif choice == '2':
                hashed_password = hash_sha512(password)
            elif choice == '3':
                hashed_password = hash_pbkdf2(password)
            elif choice == '4':
                hashed_password = hash_argon2(password)
            elif choice == '5':
                hashed_password = hash_bcrypt(password)
            elif choice == '6':
                hashed_password = hash_scrypt(password)
            else:
                print("Invalid choice")
                continue

            # Insert or update the username and hashed password in the database
            new_user = User(username, password, choice, hashed_password, None)
            if found_user:
                DatabaseConnection.add_user(new_user)
            else:
                DatabaseConnection.add_user(new_user)

            # Output the hashed password
            print("Username and hashed password stored in the database successfully.")
            print(f"Hashed password: {hashed_password}")

            # Ask the user if they want to log out, hash the password with a different algorithm, or change the password
            while True:
                print("Do you want to:")
                print("1. Log out")
                print("2. Hash the password with a different algorithm")
                print("3. Change the password")
                next_action = input("Enter the number of your choice: ")

                if next_action == '1':
                    return
                elif next_action == '2':
                    break
                elif next_action == '3':
                    # Prompt the user for a new password
                    password = input("Enter a new password: ")
                    break
                else:
                    print("Invalid choice, please try again.")

            if next_action == '2':
                continue
            elif next_action == '3':
                while True:
                    # Display a menu for selecting a hashing algorithm
                    print("Select a hashing algorithm:")
                    print("1. MD5")
                    print("2. SHA-512")
                    print("3. PBKDF2")
                    print("4. Argon2")
                    print("5. bcrypt")
                    print("6. scrypt")
                    choice = input("Enter the number of the hashing algorithm: ")

                    # Hash the password using the selected algorithm
                    if choice == '1':
                        hashed_password = hash_md5(password)
                    elif choice == '2':
                        hashed_password = hash_sha512(password)
                    elif choice == '3':
                        hashed_password = hash_pbkdf2(password)
                    elif choice == '4':
                        hashed_password = hash_argon2(password)
                    elif choice == '5':
                        hashed_password = hash_bcrypt(password)
                    elif choice == '6':
                        hashed_password = hash_scrypt(password)
                    else:
                        print("Invalid choice")
                        continue

                    # Update the password for the existing username in the database
                    new_user = User(username, password, choice, hashed_password, None)
                    DatabaseConnection.add_user(new_user)

                    # Output the hashed password
                    print("Password updated successfully.")
                    print(f"New hashed password: {hashed_password}")

                    # Ask the user if they want to log out, hash the password with a different algorithm, or change the password
                    break

if __name__ == "__main__":
    main()
