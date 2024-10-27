class User:
    def __init__(self, username, plain_text_password, hashing_algorithm, hashed_password, salt):
        self.username = username
        self.plain_text_password = plain_text_password
        self.hashing_algorithm = hashing_algorithm
        self.hashed_password = hashed_password
        self.salt = salt