import pytest
import main
from hashing_algorithm import HashingAlgorithm


@pytest.mark.parametrize("user_input, expected", [
    ("1", HashingAlgorithm.MD5),
    ("2", HashingAlgorithm.SHA512),
    ("3", HashingAlgorithm.PBKDF2),
    ("4", HashingAlgorithm.ARGON2),
    ("5", HashingAlgorithm.BCRYPT),
    ("6", HashingAlgorithm.SCRYPT)
])

def test_get_algorithm_user_choice(monkeypatch, user_input, expected):

    monkeypatch.setattr("builtins.input", lambda _: user_input)                 
    result = main.get_algorithm_user_choice()
    assert result == expected



