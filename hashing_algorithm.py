from enum import Enum

class HashingAlgorithm(Enum):
    ARGON2 = 1
    BCRYPT = 2
    MD5 = 3
    SHA512 = 4
    PBKDF2 = 5