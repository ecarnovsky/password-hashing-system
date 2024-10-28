import sqlite3
from user import User

class DatabaseConnection:
    DATABASE_NAME = "password-hashing.db"

    @staticmethod
    def add_user(user):
        con = sqlite3.connect(DatabaseConnection.DATABASE_NAME)
        cur = con.cursor()
        cur.execute(f"INSERT INTO user VALUES ('{user.username}', '{user.hashing_algorithm}', '{user.hashed_password}', '{user.salt}')")
        con.commit()
        con.close()

    @staticmethod
    def find_user(user):
        con = sqlite3.connect(DatabaseConnection.DATABASE_NAME)
        cur = con.cursor()
        res = cur.execute(f"SELECT * FROM user WHERE username='{user.username}'")
        user_row = res.fetchone()
        con.commit()
        con.close()
        if user_row is None:
            return None
        else:
            return User(user_row[0], None, user_row[1], user_row[2], user_row[3])
# had to update this so IF NOT EXISTS works
    @staticmethod
    def create_user_table():
        con = sqlite3.connect(DatabaseConnection.DATABASE_NAME)
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

def tests():
    print("Test starting...")
    test_user = User('Cool$$32', 'password123', 'argon2', 'jhgftr5678uijhvcxdser56', 'jhgfd8')
    DatabaseConnection.add_user(test_user)
    # print(DatabaseConnection.find_user(test_user))
    print("Test done.")

if __name__ == "__main__":
    tests()