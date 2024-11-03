from .database_connection import DatabaseConnection
from .user import User
from .hashing_algorithm import HashingAlgorithm
from .auth import Auth

# Main function
def main():

    # Ensure the user table exists
    DatabaseConnection.create_user_table_if_not_exist()

    while True:

        user = get_user()
        logged_in_action_loop(user)





def logged_in_action_loop(user: User):

    while True:

        # If the user successfully logs in or creates an account, present the options
        print("Do you want to:")
        print("1. Log out")
        print("2. Hash the password with a different algorithm")
        print("3. Change the password")
        next_action = input("Enter the number of your choice: ")

        if next_action == '1':
            print("You are now logged out.")
            break
        elif next_action == '2':
            hashing_algorithm = get_algorithm_user_choice()
            hashed_password, salt = get_hashed_password(user.plain_text_password, hashing_algorithm)

            # Update the username and hashed password in the database
            updated_user = User(user.username, user.plain_text_password, hashing_algorithm.name, hashed_password, salt)
            DatabaseConnection.update_user(updated_user)

            # Output the hashed password
            print("Password updated in the database successfully.")
            print(f"Hashed password: {hashed_password}")
        elif next_action == '3':
            # Prompt the user for a new password
            password = input("Enter a new password: ")
            hashing_algorithm = get_algorithm_user_choice()
            hashed_password, salt = get_hashed_password(password, hashing_algorithm)

            # Update the username and hashed password in the database
            updated_user = User(user.username, user.plain_text_password, hashing_algorithm.name, hashed_password, salt)
            DatabaseConnection.update_user(updated_user)

            # Output the hashed password
            print("Password updated in the database successfully.")
            print(f"Hashed password: {hashed_password}")
        else:
            print("Invalid choice, please try again.")
            continue




def get_user():
    
    while True:

        # Prompt the user for a username
        username = input("Enter a username: ")

        # Check if the username already exists in the database
        found_user = DatabaseConnection.find_user_by_username(username)

        if found_user:
            # Username exists, prompt for password to log in
            print("Username exists. Please log in.")
            stored_password = found_user.hashed_password
            stored_salt= found_user.salt
            if stored_salt is not None:
                stored_salt = bytes.fromhex(found_user.salt)
            password = input("Enter your password: ")

            # Verify the password
            if (stored_password == Auth.hash_md5(password, stored_salt)[32:] or
                stored_password == Auth.hash_sha512(password, stored_salt)[32:] or
                stored_password == Auth.hash_pbkdf2(password, stored_salt)[32:] or
                stored_password == Auth.hash_argon2(password, stored_salt)[32:] or
                stored_password == Auth.hash_bcrypt(password)[32:] or
                stored_password== Auth.hash_scrypt(password, stored_salt)[32:]
                ):
                print("Login successful.")
                return found_user
            else:
                print("Incorrect password. Try again.")
                continue

        elif not found_user:
            # Username is new, prompt to create a password
            print("Username created.")
            password = input("Enter a password: ")

            hashing_algorithm = get_algorithm_user_choice()
            hashed_password, salt = get_hashed_password(password, hashing_algorithm)

            new_user = User(username, password, hashing_algorithm.name, hashed_password, salt)
            DatabaseConnection.add_user(new_user)

            print("Username and hashed password stored in the database successfully.")
            print(f"Hashed password: {hashed_password}")

            return new_user



def get_algorithm_user_choice():
    """ 
    Allows the user to input a number to choose what hashing 
    algorithm to use on their password.
    """

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

        if not choice.isdigit() or int(choice) > len(HashingAlgorithm) or int(choice) < 1:
            print("Invalid choice")
        else:
            return HashingAlgorithm(int(choice))

def get_hashed_password(password: str, hashingAlgorithm: HashingAlgorithm):
    """
    Returns a hashed password using whatever hashing algorithm is specified.
    """

    hashed_password = None
    salt = None

    if hashingAlgorithm == HashingAlgorithm.MD5:
        hashed_password = Auth.hash_md5(password)
        salt = hashed_password[:32]
        hashed_password = hashed_password[32:]
    elif hashingAlgorithm == HashingAlgorithm.SHA512:
        hashed_password = Auth.hash_sha512(password)
        salt = hashed_password[:32]
        hashed_password = hashed_password[32:]
    elif hashingAlgorithm == HashingAlgorithm.PBKDF2:
        hashed_password = Auth.hash_pbkdf2(password)
        salt = hashed_password[:32]
        hashed_password = hashed_password[32:]
    elif hashingAlgorithm == HashingAlgorithm.ARGON2:
        hashed_password = Auth.hash_argon2(password)
        salt = hashed_password[:32]
        hashed_password = hashed_password[32:]
    elif hashingAlgorithm == HashingAlgorithm.BCRYPT:
        salt,hashed_password = Auth.hash_bcrypt(password)
        salt = salt.hex()
        hashed_password = hashed_password.hex()
    elif hashingAlgorithm == HashingAlgorithm.SCRYPT:
        hashed_password = Auth.hash_scrypt(password)
        salt = hashed_password[:32]
        hashed_password = hashed_password[32:]

    if hashed_password:
        return hashed_password, salt
    else:
        raise Exception("There was an error with hashing the password.")

if __name__ == "__main__":
    main()
