from enum import Enum
import requests


class PasswordUtils:

    def generate_super_strong_password() -> str:
        password = ""
        #
        return password

    def generate_memorable_password() -> str:
        password = ""

        response = requests.get('https://words-api.netlify.app/.netlify/functions/getword?number=2&min=3&max=6')
        data = response.json()
        print(data['words'])

        #

        return password

    def get_password_strength(password: str) -> 'PasswordStrength':
        """
        Returns strong if a password has a length of at least 12, a lowercase
        character, an uppercase character, a special character, and a number.
        Returns medium if a password has a length of at least 6, and has at least 
        three of the above four types of characters.
        Return weak otherwise.
        """

        length: int = len(password)
        has_lowercase: bool = False
        has_uppercase: bool = False
        has_special_char: bool = False
        has_number: bool = False

        char_list = list(password)

        for char in char_list:
            if char.islower():
                has_lowercase = True
            elif char.isupper():
                has_uppercase = True
            elif not char.isalnum():
                has_special_char = True
            elif char.isdigit():
                has_number = True


        if (length >= 12 ) and has_lowercase and has_uppercase and has_special_char and has_number:
            return PasswordStrength.STRONG
        elif (length >= 6) and sum([has_lowercase, has_uppercase, has_special_char, has_number]) >= 3:
            return PasswordStrength.MEDIUM
        else:
            return PasswordStrength.WEAK

        

class PasswordStrength(Enum):
    WEAK = 1
    MEDIUM = 2
    STRONG = 3


if __name__ == "__main__":
    # PasswordUtils.generate_memorable_password()

    print(PasswordUtils.get_password_strength("pasw$f$Fi5rd"))