import hashlib
from argon2 import PasswordHasher
import bcrypt
import os

class Auth:

    @staticmethod
    def hash_md5(password):
        return hashlib.md5(password.encode()).hexdigest()

    @staticmethod
    def hash_sha512(password):
        return hashlib.sha512(password.encode()).hexdigest()

    @staticmethod
    def hash_pbkdf2(password):
        salt = Auth.__getSalt()
        hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        return salt.hex() + hashed_password.hex()

    @staticmethod
    def hash_argon2(password):
        argon2_hasher = PasswordHasher()
        hash_and_metadata =  argon2_hasher.hash(password)
        hashed_password = hash_and_metadata.split('$')[-1]
        return hashed_password

    # bcrypt's salting library is used instead of ours here
    @staticmethod
    def hash_bcrypt(password):
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).hex()

    @staticmethod
    def hash_scrypt(password):
        return hashlib.scrypt(password.encode(), salt=Auth.__getSalt(), n=16384, r=8, p=1).hex()

    @staticmethod
    def __getSalt():
        return os.urandom(16)