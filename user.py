class User:
    def __init__(self, username, plainTextPassword, hashingAlgorithm, hashedPassword, salt):
        self.username = username
        self.plainTextPassword = plainTextPassword
        self.hashingAlgorithm = hashingAlgorithm
        self.hashedPassword = hashedPassword
        self.salt = salt