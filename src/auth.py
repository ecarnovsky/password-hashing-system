import hashlib
from argon2 import PasswordHasher
from argon2.low_level import hash_secret, Type
import bcrypt
import os
from .hashing_algorithm import HashingAlgorithm

class Auth:
    """
    Handles things related to authenticating the user, such as hashing.
    """

    
    @staticmethod
    def __get_bytes_and_str_salt(str_salt: str | None, bcrypt_version: bool = False):
        if str_salt:
            bytes_salt = bytes.fromhex(str_salt)
        elif str_salt is None:
            if bcrypt_version: 
                bytes_salt = bcrypt.gensalt()
            else:
                bytes_salt = os.urandom(16)
            str_salt = bytes_salt.hex()

        return bytes_salt, str_salt
    


    """ MD5 """
    @staticmethod
    def __hash_md5(password: str, str_salt: str | None = None):

        bytes_salt, str_salt = Auth.__get_bytes_and_str_salt(str_salt)

        hashed_password = hashlib.md5(bytes_salt + password.encode()).hexdigest()
        return hashed_password, str_salt

    """ SHA-512 """
    @staticmethod
    def __hash_sha512(password: str, str_salt: str | None = None):

        bytes_salt, str_salt = Auth.__get_bytes_and_str_salt(str_salt)

        hashed_password = hashlib.sha512(bytes_salt + password.encode()).hexdigest()
        return hashed_password, str_salt

    """ PBKDF2 """
    @staticmethod
    def __hash_pbkdf2(password: str, str_salt: str | None = None):

        bytes_salt, str_salt = Auth.__get_bytes_and_str_salt(str_salt)

        hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes_salt, 100000)
        return hashed_password.hex(), str_salt

    """ argon2 """
    @staticmethod
    def __hash_argon2(password: str, str_salt: str | None = None):

        bytes_salt, str_salt = Auth.__get_bytes_and_str_salt(str_salt)

        # Use Argon2 low-level API to specify a custom salt
        hashed_password = hash_secret(
            password.encode(),
            bytes_salt,
            time_cost=2,
            memory_cost=102400,
            parallelism=8,
            hash_len=32,
            type=Type.I
        ).hex()

        # Store salt with hash for retrieval
        return hashed_password, str_salt

    """ bcrypt """
    @staticmethod
    def __hash_bcrypt(password: str, str_salt: str | None = None):

        bytes_salt, str_salt = Auth.__get_bytes_and_str_salt(str_salt, True)

        # Convert the password to bytes (bcrypt requires byte input)
        password_bytes = password.encode('utf-8')

        # Hash the password with the generated salt
        bytes_hashed_password_and_metadata = bcrypt.hashpw(password_bytes, bytes_salt)
        bytes_hashed_password = bytes_hashed_password_and_metadata[-31:]
        str_hashed_password = bytes_hashed_password.hex()

        return  str_hashed_password, str_salt

    """ scrypt """
    @staticmethod
    def __hash_scrypt(password: str, str_salt: str | None = None):

        bytes_salt, str_salt = Auth.__get_bytes_and_str_salt(str_salt)

        hashed_password = hashlib.scrypt(password.encode(), salt=bytes_salt, n=16384, r=8, p=1).hex()
        return hashed_password, str_salt

    @staticmethod
    def get_hashed_password(password: str, salt: str | None, hashingAlgorithm: HashingAlgorithm):
        """
        Returns a hashed password using whatever hashing algorithm is specified.
        """

        hashed_password = None

        if hashingAlgorithm == HashingAlgorithm.MD5:
            hashed_password, salt = Auth.__hash_md5(password, salt)
        elif hashingAlgorithm == HashingAlgorithm.SHA512:
            hashed_password, salt = Auth.__hash_sha512(password, salt)
        elif hashingAlgorithm == HashingAlgorithm.PBKDF2:
            hashed_password, salt = Auth.__hash_pbkdf2(password, salt)
        elif hashingAlgorithm == HashingAlgorithm.ARGON2:
            hashed_password, salt = Auth.__hash_argon2(password, salt)
        elif hashingAlgorithm == HashingAlgorithm.BCRYPT:
            hashed_password, salt = Auth.__hash_bcrypt(password, salt)
        elif hashingAlgorithm == HashingAlgorithm.SCRYPT:
            hashed_password, salt = Auth.__hash_scrypt(password, salt)

        if hashed_password:
            return hashed_password, salt
        else:
            raise Exception("There was an error with hashing the password.")

