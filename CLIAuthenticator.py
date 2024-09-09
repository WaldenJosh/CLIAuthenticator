"""
CLIAuthenticator - A command-line tool for generating TOTP codes securely.

MIT License

Copyright (c) 2024 Joshua Walden

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import json
import sys
import pyotp
import getpass
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
import hashlib
import base64
import binascii
import re
import time


def generate_key_from_password(password):
    """Generate a key for encryption/decryption from a password."""
    key = hashlib.sha256(password.encode()).digest()
    return urlsafe_b64encode(key)


def encrypt_seeds(data, password):
    """Encrypt the 'secret' field for each account in the JSON data using the provided password."""
    key = generate_key_from_password(password)
    fernet = Fernet(key)

    for account in data.get("accounts", []):
        if 'secret' in account and account['secret']:
            account['secret'] = fernet.encrypt(
                account['secret'].encode()).decode()

    data['encrypted'] = True
    return data


def decrypt_seeds(data, password):
    """Decrypt the 'secret' field for each account in the JSON data using the provided password."""
    key = generate_key_from_password(password)
    fernet = Fernet(key)

    for account in data.get("accounts", []):
        if 'secret' in account and account['secret']:
            account['secret'] = fernet.decrypt(
                account['secret'].encode()).decode()

    data['encrypted'] = False
    return data


def is_base32(s):
    """Check if a string is a valid base32-encoded string after converting it to uppercase."""
    base32_pattern = re.compile(r'^[A-Z2-7=]+$')
    s = s.upper()
    return base32_pattern.match(s) is not None


def normalize_secret(secret):
    """Normalize the secret to ensure it is a valid base32-encoded string."""
    secret = secret.upper()
    secret = re.sub(r'[^A-Z2-7]', '', secret)
    return secret


def find_totp_fields(data):
    """Recursively search for TOTP fields in the JSON structure."""
    if isinstance(data, dict):
        # Check if required fields are found in this dictionary
        if 'secret' in data and is_base32(normalize_secret(data['secret'])):
            # Return the dictionary if it contains the required TOTP fields
            return [data]
        else:
            # Recursively search for TOTP fields in nested objects
            found_accounts = []
            for key, value in data.items():
                found_accounts.extend(find_totp_fields(value))
            return found_accounts
    elif isinstance(data, list):
        # Recursively search for TOTP fields in list elements
        found_accounts = []
        for item in data:
            found_accounts.extend(find_totp_fields(item))
        return found_accounts
    else:
        # Base case: return empty if neither a list nor a dictionary
        return []


def generate_totp_codes(file_path):
    try:
        with open(file_path, 'r') as json_file:
            data = json.load(json_file)

        if data.get('encrypted', False):
            password = getpass.getpass("Enter decryption password: ")
            try:
                data = decrypt_seeds(data, password)
            except Exception as e:
                print(f"Error decrypting seeds: {e}")
                return
        else:
            print("Warning: The seeds are stored in plain text and are unprotected.")

        # Find accounts with TOTP fields in the JSON data
        accounts = find_totp_fields(data)

        if not accounts:
            print("No valid TOTP accounts found in the JSON file.")
            return

        for account in accounts:
            seed = normalize_secret(account.get("secret", ""))
            if seed and is_base32(seed):
                # Default to 30 seconds if not specified
                time_step = account.get("timeStep", 30)
                totp = pyotp.TOTP(seed, digits=account.get(
                    "digits", 6), interval=time_step, digest=account.get("algorithm", 'sha1'))
                code = totp.now()
                remaining_time = time_step - (int(time.time()) % time_step)
                print(f"{account.get('issuerName', 'Unknown')}: {
                      code} (Valid for {remaining_time} seconds)")
            else:
                print(f"Error: The 'secret' for account '{account.get(
                    'issuerName', 'Unknown')}' is not a valid base32-encoded string after normalization.")

    except FileNotFoundError:
        print(f"Error: The file {file_path} was not found.")
    except json.JSONDecodeError:
        print(f"Error: Failed to parse JSON from the file {file_path}.")
    except Exception as e:
        print(f"An error occurred: {str(e)}")


def encrypt_json_file(file_path):
    try:
        with open(file_path, 'r') as json_file:
            data = json.load(json_file)

        if data.get('encrypted', False):
            print("Seeds are already encrypted. Encryption aborted.")
            return

        password = getpass.getpass("Enter encryption password: ")
        confirm_password = getpass.getpass("Confirm encryption password: ")

        if password != confirm_password:
            print("Passwords do not match. Encryption aborted.")
            return

        data = encrypt_seeds(data, password)

        with open(file_path, 'w') as json_file:
            json.dump(data, json_file, indent=4)
        print(f"File {file_path} encrypted successfully.")

    except FileNotFoundError:
        print(f"Error: The file {file_path} was not found.")
    except json.JSONDecodeError:
        print(f"Error: Failed to parse JSON from the file {file_path}.")
    except Exception as e:
        print(f"An error occurred: {str(e)}")


def decrypt_json_file(file_path):
    try:
        with open(file_path, 'r') as json_file:
            data = json.load(json_file)

        if not data.get('encrypted', False):
            print("Seeds are already decrypted. Decryption aborted.")
            return

        password = getpass.getpass("Enter decryption password: ")

        try:
            data = decrypt_seeds(data, password)
        except Exception as e:
            print(f"Error decrypting seeds: {e}")
            return

        with open(file_path, 'w') as json_file:
            json.dump(data, json_file, indent=4)
        print(f"File {file_path} decrypted successfully.")

    except FileNotFoundError:
        print(f"Error: The file {file_path} was not found.")
    except json.JSONDecodeError:
        print(f"Error: Failed to parse JSON from the file {file_path}.")
    except Exception as e:
        print(f"An error occurred: {str(e)}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python generate_totp.py <json_file_path> or python generate_totp.py encrypt <json_file_path> or python generate_totp.py decrypt <json_file_path>")
    elif sys.argv[1] == "encrypt":
        if len(sys.argv) != 3:
            print("Usage: python generate_totp.py encrypt <json_file_path>")
        else:
            json_file_path = sys.argv[2]
            encrypt_json_file(json_file_path)
    elif sys.argv[1] == "decrypt":
        if len(sys.argv) != 3:
            print("Usage: python generate_totp.py decrypt <json_file_path>")
        else:
            json_file_path = sys.argv[2]
            decrypt_json_file(json_file_path)
    else:
        json_file_path = sys.argv[1]
        generate_totp_codes(json_file_path)
