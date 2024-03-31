import sqlite3
import secrets
import hmac
import binascii
from hashlib import pbkdf2_hmac


def hash_password(password: str, salt: bytes) -> str:
    """
    Hashes a password using PBKDF2-HMAC with SHA-256 algorithm.

    Args:
        password (str): The password to hash.
        salt (bytes): The salt used to increase hashing security.

    Returns:
        str: The hashed password in hexadecimal format.
    """
    return binascii.hexlify(pbkdf2_hmac('sha256', password.encode(), salt, 100000)).decode()


class PasswordVerification:
    """
    Class for managing secure password storage and verification in SQLite database.
    """
    def __init__(self, db_file: str):
        """
        Initializes the SecurePasswordManager object.

        Args:
            db_file (str): The path to the SQLite database file.
        """
        self.conn = sqlite3.connect(db_file)
        self.create_table()

    def create_table(self):
        """
        Creates a table in the database if it doesn't exist.
        """
        cursor = self.conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS passwords (
                            id INTEGER PRIMARY KEY,
                            hash TEXT,
                            salt TEXT
                          )''')
        self.conn.commit()

    def store_password(self, password: str) -> None:
        """
        Stores a password in the database.

        Args:
            password (str): The password to store.
        """
        salt = secrets.token_bytes(16)
        hashed_password = hash_password(password, salt)
        cursor = self.conn.cursor()
        cursor.execute("INSERT INTO passwords (hash, salt) VALUES (?, ?)", (hashed_password, salt))
        self.conn.commit()

    def verify_password(self, password: str) -> bool:
        """
        Verifies a password.

        Args:
            password (str): The password to verify.

        Returns:
            bool: True if the password is correct, False otherwise.
        """
        cursor = self.conn.cursor()
        cursor.execute("SELECT hash, salt FROM passwords")
        stored_data = cursor.fetchone()
        if stored_data:
            hashed_password, salt = stored_data
            return hmac.compare_digest(hash_password(password, salt), hashed_password)
        return False

    def close_connection(self):
        """
        Closes the connection to the database.
        """
        self.conn.close()


def example_of_password_verification():
    """
    Example usage of the PasswordVerification class.
    """
    db_file = 'secure_passwords.db'
    manager = PasswordVerification(db_file)
    password = input("Enter password: ")
    manager.store_password(password)
    password_to_check = input("Enter password to verify: ")
    if manager.verify_password(password_to_check):
        print("Password is correct.")
    else:
        print("Incorrect password.")
    manager.close_connection()


if __name__ == "__main__":
    example_of_password_verification()
