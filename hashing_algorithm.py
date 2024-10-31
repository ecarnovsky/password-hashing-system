from enum import Enum

class HashingAlgorithm(Enum):
    MD5 = 1
    SHA512 = 2
    PBKDF2 = 3
    ARGON2 = 4
    BCRYPT = 5
    SCRYPT = 6