# Password Verification with SQLite

This Python script demonstrates secure password storage and verification using SQLite database.

## Overview

The script provides a class `PasswordVerification` for managing secure password storage and verification in an SQLite database. It utilizes PBKDF2-HMAC with SHA-256 algorithm for hashing passwords and uses randomly generated salts to increase security.

## Requirements

- Python 3.x
- SQLite3

## Usage

1. Run the script `exercise_3.py`.
2. Follow the prompts to enter and verify a password.
3. The password will be securely stored in the SQLite database.
4. You can then verify passwords against the stored hashes.

## Files

- `exercise_3.py`: Main Python script for password management.
- `README.md`: This README file.
