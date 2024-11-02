from enum import Enum

class HashingAlgorithm(Enum):
    """
    An enumeration of all the hashing algorithms used in the app.
    The numbers correspond to the user input options in main.
    
    """
    MD5 = 1
    SHA512 = 2
    PBKDF2 = 3
    ARGON2 = 4
    BCRYPT = 5
    SCRYPT = 6