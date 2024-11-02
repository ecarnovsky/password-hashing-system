from .hashing_algorithm import HashingAlgorithm
class User:
    """
    Represents an end user of the application.

    """

    def __init__(self, username: str, plain_text_password: str, hashing_algorithm: HashingAlgorithm, hashed_password: str, salt: str):
        self.username = username
        self.plain_text_password = plain_text_password
        self.hashing_algorithm = hashing_algorithm
        self.hashed_password = hashed_password
        self.salt = salt