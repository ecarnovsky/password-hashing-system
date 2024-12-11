# Password Hashing System

### Overview
This is a proof-of-concept application designed to securely hash and store sensitive user data. It uses six different hashing algorithms: MD5, SHA512, PBKDF2, Argon2, bcrypt, and scrypt, along with salting to improve security. The application allows users to choose which hashing algorithm they would like to use, then stores the hashed passwords in an SQLite database.

### Testing
The project was developed using a test-driven approach. Pytest was used to write unit tests that verified the application's processes were working correctly. This allowed the development team to verify that all hashes and salts were generated and stored correctly.  This provided a strong foundation for the application, which allowed for the easier addition of new features. 
