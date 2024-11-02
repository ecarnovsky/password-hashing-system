import hashlib
from argon2 import PasswordHasher
import bcrypt
import os

class Auth:
    """
    Handles things related to authenticating the user, such as hashing.

    """


    """ MD5 """
    @staticmethod
    def hash_md5(password: str):
        return hashlib.md5(password.encode()).hexdigest()

    """ SHA-512 """
    @staticmethod
    def hash_sha512(password: str):
        return hashlib.sha512(password.encode()).hexdigest()
    
    """ PBKDF2 """
    @staticmethod
    def hash_pbkdf2(password: str):
        salt = Auth.__getSalt()
        hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        return salt.hex() + hashed_password.hex()

    """ argon2 """
    @staticmethod
    def hash_argon2(password: str):
        argon2_hasher = PasswordHasher()
        hash_and_metadata =  argon2_hasher.hash(password)
        hashed_password = hash_and_metadata.split('$')[-1]
        return hashed_password
 
    """ bcrypt """
    # bcrypt's salting library is used here instead of our function
    @staticmethod
    def hash_bcrypt(password: str):
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).hex()

    """ scrypt """
    @staticmethod
    def hash_scrypt(password: str):
        return hashlib.scrypt(password.encode(), salt=Auth.__getSalt(), n=16384, r=8, p=1).hex()

    @staticmethod
    def __getSalt():
        return os.urandom(16)