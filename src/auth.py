import hashlib
from argon2.low_level import hash_secret, Type
import bcrypt
import os
from .hashing_algorithm import HashingAlgorithm

class Auth:
    """
    Handles things related to authenticating the user, such as hashing.
    """


    "All private hashing functions take in bytes and return bytes."

    """ MD5 """
    @staticmethod
    def __hash_md5(password: bytes, salt: bytes):

        hashed_password = hashlib.md5(salt + password).digest()
        return hashed_password, salt

    """ SHA-512 """
    @staticmethod
    def __hash_sha512(password: bytes, salt: bytes):

        hashed_password = hashlib.sha512(salt + password).digest()
        return hashed_password, salt

    """ PBKDF2 """
    @staticmethod
    def __hash_pbkdf2(password: bytes, salt: bytes):

        hashed_password = hashlib.pbkdf2_hmac('sha256', password, salt, 100000)
        return hashed_password, salt

    """ argon2 """
    @staticmethod
    def __hash_argon2(password: bytes, salt: bytes):

        # Use Argon2 low-level API to specify a custom salt
        hashed_password = hash_secret(
            password,
            salt,
            time_cost=2,
            memory_cost=102400,
            parallelism=8,
            hash_len=32,
            type=Type.I
        )

        return hashed_password, salt

    """ bcrypt """
    @staticmethod
    def __hash_bcrypt(password: bytes, salt: bytes):

        # Hash the password with the generated salt
        hashed_password_and_metadata = bcrypt.hashpw(password, salt)
        hashed_password = hashed_password_and_metadata[-31:]

        return hashed_password, salt

    """ scrypt """
    @staticmethod
    def __hash_scrypt(password: bytes, salt: bytes):

        hashed_password = hashlib.scrypt(password, salt=salt, n=16384, r=8, p=1)
        return hashed_password, salt

    @staticmethod
    def get_hashed_password(password: str, salt: str | None, hashing_algorithm: HashingAlgorithm):
        """
        Returns a hashed password and salt using whatever hashing algorithm is specified.
        If no salt is specified, one will be randomly generated. 
        """

        # Changes the password and salt to bytes. If no salt
        # is given, a random one is generated.
        bytes_password = password.encode()
        if salt:
            bytes_salt = bytes.fromhex(salt)
        elif hashing_algorithm == HashingAlgorithm.BCRYPT:
            bytes_salt = bcrypt.gensalt()
        else:
            bytes_salt = os.urandom(16)

        bytes_hashed_password = None

        if hashing_algorithm == HashingAlgorithm.MD5:
            bytes_hashed_password, bytes_salt = Auth.__hash_md5(bytes_password, bytes_salt)
        elif hashing_algorithm == HashingAlgorithm.SHA512:
            bytes_hashed_password, bytes_salt = Auth.__hash_sha512(bytes_password, bytes_salt)
        elif hashing_algorithm == HashingAlgorithm.PBKDF2:
            bytes_hashed_password, bytes_salt = Auth.__hash_pbkdf2(bytes_password, bytes_salt)
        elif hashing_algorithm == HashingAlgorithm.ARGON2:
            bytes_hashed_password, bytes_salt = Auth.__hash_argon2(bytes_password, bytes_salt)
        elif hashing_algorithm == HashingAlgorithm.BCRYPT:
            bytes_hashed_password, bytes_salt = Auth.__hash_bcrypt(bytes_password, bytes_salt)
        elif hashing_algorithm == HashingAlgorithm.SCRYPT:
            bytes_hashed_password, bytes_salt = Auth.__hash_scrypt(bytes_password, bytes_salt)

        if bytes_hashed_password:
            # Changes the salt and hashed_password to a normal string
            # format before being returned.
            salt = bytes_salt.hex()
            hashed_password = bytes_hashed_password.hex()
            return hashed_password, salt
        else:
            raise Exception("There was an error with hashing the password.")

