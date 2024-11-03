import sqlite3
from .user import User

class DatabaseConnection:
    _DATABASE_NAME = "password-hashing.db"

    @staticmethod
    def add_user(user: User):
        con = sqlite3.connect(DatabaseConnection._DATABASE_NAME)
        cur = con.cursor()
        cur.execute(
            "INSERT INTO user (username, hashing_algorithm, hashed_password, salt) VALUES (?, ?, ?, ?)",
            (user.username, user.hashing_algorithm, user.hashed_password, user.salt)
        )
        con.commit()
        con.close()

    @staticmethod
    def update_user(user: User):
        con = sqlite3.connect(DatabaseConnection._DATABASE_NAME)
        cur = con.cursor()
        cur.execute(
            "UPDATE user SET hashing_algorithm = ?, hashed_password = ?, salt = ? WHERE username = ?",
            (user.hashing_algorithm, user.hashed_password, user.salt, user.username)
        )
        con.commit()
        con.close()

    @staticmethod
    def find_user_by_username(username: str):
        con = sqlite3.connect(DatabaseConnection._DATABASE_NAME)
        cur = con.cursor()
        res = cur.execute("SELECT * FROM user WHERE username=?", (username,))
        user_row = res.fetchone()
        con.commit()
        con.close()
        if user_row is None:
            return None
        else:
            return User(user_row[0], None, user_row[1], user_row[2], user_row[3])
        
    @staticmethod
    def delete_user_by_username(username: str):
        """ Returns true if successful """

        con = sqlite3.connect(DatabaseConnection._DATABASE_NAME)
        cur = con.cursor()
        cur.execute("DELETE FROM user WHERE username=?", (username,))
        num_of_deleted_rows = cur.rowcount
        con.commit()
        con.close()
        return (num_of_deleted_rows > 0)
    


    @staticmethod
    def create_user_table_if_not_exist():
        con = sqlite3.connect(DatabaseConnection._DATABASE_NAME)
        cur = con.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS user (
                username TEXT NOT NULL,
                hashing_algorithm TEXT,
                hashed_password TEXT,
                salt TEXT
            )
        """)
        con.commit()
        con.close()
