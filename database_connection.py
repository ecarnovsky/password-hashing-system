import sqlite3
from user import User

class DatabaseConnection:


    def add_user(user):
        con = sqlite3.connect("password-hashing.db")
        cur = con.cursor()
        cur.execute(f"INSERT INTO user VALUES ('{user.username}', '{user.hashing_algorithm}', '{user.hashed_password}', '{user.salt}')")
        con.commit() 
        con.close()


    def find_user(user):
        print("")


    # This method is only used for initial setup
    def create_user_table():
        con = sqlite3.connect("password-hashing.db")
        cur = con.cursor()
        cur.execute("CREATE TABLE user(username, hashing_algorithm, hashed_password, salt)")
        con.commit() 
        con.close()




def tests():
    print("Test starting...")
    test_user = User('Cool$$32', 'password123', 'argon2', 'jhgftr5678uijhvcxdser56', 'jhgfd8')
    DatabaseConnection.add_user(test_user)
    print("Test done.")


if __name__ == "__main__":
    tests()