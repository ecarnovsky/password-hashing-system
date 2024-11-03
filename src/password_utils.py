from enum import Enum
import nltk
from nltk.corpus import words
import random


class PasswordUtils:

    def generate_super_strong_password():
        password = ""
        #
        return password

    def generate_memorable_password():
        password = ""
        #
        # nltk.download('words')
        # word_list = words.words()
        # short_words = [word for word in word_list if len(word) <= 4]  
        # print(random.choice(short_words))
        return password

    def get_password_strength(password: str):
        strength: PasswordStrength = None
        # 
        return strength

class PasswordStrength(Enum):
    WEAK = 1
    MEDIUM = 2
    STRONG = 3


if __name__ == "__main__":
    PasswordUtils.generate_super_strong_password()