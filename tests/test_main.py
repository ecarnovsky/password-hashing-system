import pytest
from unittest.mock import patch
import src.main as main
from src.hashing_algorithm import HashingAlgorithm
from src.database_connection import DatabaseConnection


DatabaseConnection.create_user_table_if_not_exist()

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


@pytest.mark.parametrize("algorithm", list(HashingAlgorithm))
def test_get_hashed_password(algorithm):
    hashed_password, salt = main.get_hashed_password("password123", algorithm)
    assert isinstance(hashed_password, str)
    assert len(hashed_password) > 10
    assert salt is None or isinstance(salt, str)



"""
Tests if a user can create an account and then login afterwords
using every hashing algorithm.

"""
@pytest.mark.parametrize("algorithm_number_choice", ["1","2","3","4","5","6"])
def test_get_user(monkeypatch, algorithm_number_choice):
    

    TEST_USERNAME = "test_user"
    TEST_PASSWORD = "password123"

    DatabaseConnection.delete_user_by_username(TEST_USERNAME)

    inputs = iter([
            TEST_USERNAME,     
            TEST_PASSWORD,
            algorithm_number_choice,
            TEST_USERNAME,     
            TEST_PASSWORD     
        ])
    with patch("builtins.print") as mock_print:  
        monkeypatch.setattr("builtins.input", lambda _: next(inputs))
        main.get_user()
        main.get_user()

        mock_print.assert_any_call("Username created.")
        mock_print.assert_any_call("Login successful.")

        DatabaseConnection.delete_user_by_username(TEST_USERNAME)