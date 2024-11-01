from src.database_connection import DatabaseConnection
from src.user import User

def test_adding_and_finding_user():

    DatabaseConnection.create_user_table()

    user = User('test_user', 'password123', 'argon2', '1111111111111111', '1111')
    DatabaseConnection.add_user(user)

    returned_user = DatabaseConnection.find_user_by_username(user.username)

    assert returned_user.username == user.username
    assert returned_user.hashing_algorithm == user.hashing_algorithm
    assert returned_user.hashed_password == user.hashed_password
    assert returned_user.salt == user.salt


