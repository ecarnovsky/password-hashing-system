import pytest
from src.hashing_algorithm import HashingAlgorithm
from src.database_connection import DatabaseConnection
from src.auth import Auth


DatabaseConnection.create_user_table_if_not_exist()


@pytest.mark.parametrize("algorithm", list(HashingAlgorithm))
def test_get_hashed_password(algorithm):
    hashed_password, salt = Auth.get_hashed_password("password123", None, algorithm)
    assert isinstance(hashed_password, str)
    assert len(hashed_password) > 10
    assert salt is None or isinstance(salt, str)

