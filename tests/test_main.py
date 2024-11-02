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
    result = main.get_hashed_password("password123", algorithm)
    assert isinstance(result, str)
    assert len(result) > 10




# @pytest.mark.parametrize("algorithm_number_choice", ["1","2","3","4","5","6"])
# def test_get_user(monkeypatch, algorithm_number_choice):
#     inputs = iter([
#             "testuser" + algorithm_number_choice,     
#             "password123",
#             algorithm_number_choice,
#             "testuser" + algorithm_number_choice,     
#             "password123",
#             algorithm_number_choice     
#         ])
#     with patch("builtins.print") as mock_print:  
#         monkeypatch.setattr("builtins.input", lambda _: next(inputs))
#         main.get_user()
#         main.get_user()

#         mock_print.assert_any_call("Username created.")
#         mock_print.assert_any_call("Login successful.")

            
    

    




# @pytest.mark.parametrize("algorithm_number_choice", ["1","2","3","4","5","6"])
# def test_creating_account_then_logging_in(monkeypatch, algorithm_number_choice):

#     inputs = iter([
#             "testuser2",     
#             "password123",
#             algorithm_number_choice,  
#             "1",
#             "testuser2",  
#             "password123"       
#         ])
    
#     monkeypatch.setattr("builtins.input", lambda _: next(inputs))
#     with patch("builtins.print") as mock_print:  

#         user = main.getUser()


#         # monkeypatch.setattr("builtins.input", lambda _: "testuser2") 
#         mock_print.assert_any_call("Username created.")
#         # monkeypatch.setattr("builtins.input", lambda _: "password123") 
#         # monkeypatch.setattr("builtins.input", lambda _: algorithm_number_choice) 
#         mock_print.assert_any_call("Username and hashed password stored in the database successfully.")

#         main.loggedInActionLoop(user)
#         # monkeypatch.setattr("builtins.input", lambda _: "1") 

#         # monkeypatch.setattr("builtins.input", lambda _: "testuser2") 
#         # monkeypatch.setattr("builtins.input", lambda _: "password123") 
#         mock_print.assert_any_call("Login successful.")







#             # user = main.getUser() 
#             # mock_print.assert_any_call("Username created.")
#             # mock_print.assert_any_call("Username and hashed password stored in the database successfully.")

#             # main.loggedInActionLoop(user)
#             # mock_print.assert_any_call("Login successful.")
