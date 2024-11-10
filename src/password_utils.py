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

        return password

    def get_password_strength(password: str) -> 'PasswordStrength':
        strength: PasswordStrength = None
        # 
        return strength

class PasswordStrength(Enum):
    WEAK = 1
    MEDIUM = 2
    STRONG = 3


if __name__ == "__main__":
    PasswordUtils.generate_memorable_password()