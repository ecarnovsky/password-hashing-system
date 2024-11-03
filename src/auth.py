import hashlib
from argon2 import PasswordHasher
from argon2.low_level import hash_secret, Type
import bcrypt
import os

class Auth:
    """
    Handles things related to authenticating the user, such as hashing.
    """

    @staticmethod
    def __getSalt():
        return os.urandom(16)

    """ MD5 """
    @staticmethod
    def hash_md5(password: str, salt: bytes = None):
        if salt is None:
            salt = Auth.__getSalt()

        hashed_password = hashlib.md5(salt + password.encode()).hexdigest()
        return salt.hex() + hashed_password

    """ SHA-512 """
    @staticmethod
    def hash_sha512(password: str, salt: bytes = None):
        if salt is None:
            salt = Auth.__getSalt()
        hashed_password = hashlib.sha512(salt + password.encode()).hexdigest()
        return salt.hex() + hashed_password

    """ PBKDF2 """
    @staticmethod
    def hash_pbkdf2(password: str, salt: bytes = None):
        if salt is None:
            salt = Auth.__getSalt()
        hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        return salt.hex() + hashed_password.hex()

    """ argon2 """
    @staticmethod
    def hash_argon2(password: str, salt: bytes = None):
        if salt is None:
            salt = Auth.__getSalt()
        # Use Argon2 low-level API to specify a custom salt
        hashed_password = hash_secret(
            password.encode(),
            salt,
            time_cost=2,
            memory_cost=102400,
            parallelism=8,
            hash_len=32,
            type=Type.I
        ).hex()
        # Store salt with hash for retrieval
        return salt.hex() + hashed_password

    """ bcrypt """
    @staticmethod
    def hash_bcrypt(password: str, salt: bytes = None):
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password.encode(), salt)
        return salt.hex() + hashed_password.decode()

    """ scrypt """
    @staticmethod
    def hash_scrypt(password: str, salt: bytes = None):
        if salt is None:
            salt = Auth.__getSalt()
        hashed_password = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1).hex()
        return salt.hex() + hashed_password