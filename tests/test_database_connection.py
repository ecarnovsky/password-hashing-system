from src.database_connection import DatabaseConnection
from src.user import User
from src.hashing_algorithm import HashingAlgorithm

DatabaseConnection.create_user_table_if_not_exist()

def test_adding_finding_deleting_user():


    user = User('test_user_dbtest', 'password123', HashingAlgorithm.ARGON2, '1111111111111111', '1111')
    DatabaseConnection.add_user(user)

    returned_user = DatabaseConnection.find_user_by_username(user.username)

    assert returned_user.username == user.username
    assert returned_user.hashing_algorithm == user.hashing_algorithm
    assert returned_user.hashed_password == user.hashed_password
    assert returned_user.salt == user.salt

    #Delete the test user
    success = DatabaseConnection.delete_user_by_username(user.username)
    assert success == True

    #Should return false since the test user was already deleted 
    success = DatabaseConnection.delete_user_by_username(user.username)
    assert success == False


