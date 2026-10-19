import time
import os
import json
import sqlite3
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from google import genai
from google.genai.errors import APIError
from instagrapi import Client
from instagrapi.exceptions import BadPassword, UnknownError, LoginRequired, ChallengeRequired, ClientBadRequestError, TwoFactorRequired, ChallengeError, ChallengeUnknownStep, ChallengeSelfieCaptcha, RecaptchaChallengeForm, ClientError
from instagrapi.mixins.challenge import ChallengeChoice

#Initialize the database for the first time, if you later modify the tables, it will check and add them
def init_db() -> bool:
    with sqlite3.connect("app.db") as connection: 
        cursor = connection.cursor()

        create_table_query = """
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username VARCHAR(30) NOT NULL UNIQUE,
            password VARCHAR(255),
            session_nonce BLOB,
            session_data BLOB
        );

        CREATE UNIQUE INDEX idx_users_username on users(username);
        """

        cursor.executescript(create_table_query)
        print("Succesfully initialized database!")
    connection.close()
    return True

#Creates or load the key in charge of encrypting the session data json files that go into the database
def get_or_create_json_key ():

    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as f:

            data = json.load(f)
            key_hex = data["SECRET_KEY"]
            print("Returning key")
            return bytes.fromhex(key_hex)
    else:
        print("No key found, making a new one")
        new_key_bytes = AESGCM.generate_key(bit_length=256)

        payload = {"SECRET_KEY": new_key_bytes.hex()}

        with open(CONFIG_FILE, "w") as f:
            json.dump(payload, f, indent=4)

        print(f"Saved new key to ./{CONFIG_FILE}")
        return new_key_bytes

#Loads the Gemini AI client from the API key in the config file
def load_ai () -> bool:
    with open(CONFIG_FILE, "r") as f:
        config = json.load(f)

    try:
        gemini_key = config.get("GEMINI_API_KEY")

        if not gemini_key:
            print("Gemini API key is missing from the config.json file, please add it")
            return False

        ai_client = genai.Client(api_key=gemini_key)
        print("Api key loaded succesfully")
        return True

    except FileNotFoundError:
        print("Error: Could not find your 'config.json' file.")
        return False
    except json.JSONDecodeError:
        print("Error: 'config.json' is badly formatted (check your commas/brackets).")
        return False
    except ValueError as e:
        print(f"Configuration Error: {e}")
        return False
    except APIError as e:
        print(f"Google API Authentication Error: {e.message}")
        return False

#Saves the sessions.json file from the instagrapi client to the database of the user
def session_logging (username) -> bool:
    cl = Client()
    session_bytes = json.dumps(cl.get_settings()).encode()
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, session_bytes, username.encode)

    with sqlite3.connect("app.db") as connection:
        cursor = connection.cursor()

        update_query = """
        UPDATE users
        SET session_nonce = ?, session_data = ?
        WHERE username = ?;
        """
        cursor.execute(update_query, [nonce, ciphertext, username])

        print("Session succesfully saved to database")
    connection.close()
    return True

#Loads the session data from the database into the instagrapi client
def session_recupering (username):

    with sqlite3.connect("app.db") as connection:
        cursor = connection.cursor()

        retrieve_query = """
        SELECT session_nonce, session_data FROM users WHERE username = ?
        """

        cursor.execute(retrieve_query, [username])
        row = cursor.fetchone()

        session_dict = json.loads(str(aesgcm.decrypt(row[0], row[1], username.encode()).decode()))
    connection.close()
    return session_dict

#Log the user in, will need to be used in the instagrapi full client loading logic later
def instagrapi_login (username, password) -> bool:
    cl = Client()
    cl.challenge_code_handler = challenge_code_handler

    try: #to login
        cl.login(username, password)
        print("You're logged in!")
    except TwoFactorRequired:
        print("2FA triggered")
        twoFA_code = input("Input you code from your authentificator app: ").strip()
        if cl.login(username, password, verification_code=twoFA_code):
            print("You are logged in!")
            return True
        else:
            print("There's been an issue, please restart")
            return False

#Loads back the session if it exists
def instagrapi_backin (username, password) -> bool:
    cl = Client() 
    session_data = session_recupering(username)
    cl.load_settings(session_data)

    try:
        cl.get_timeline_feed()
        print("You are logged in")
        return True
    
    except LoginRequired: #session is expired
        old_settings = cl.get_settings()
        cl.set_settings({})
        cl.set_uuids(old_settings["uuids"])
        cl.set_device(old_settings["device_settings"])
        cl.set_user_agent(old_settings["user_agent"])
        if not instagrapi_login(username, password):
            print("Stopping program")
            exit()
        if not (session_logging(username) == True):
            print("There's been an issue, stopping program")
        print("You are logged in")
        return True

#Handles the code request from instagram
def challenge_code_handler (username, choice):
    print(f"Challenge triggered for {username}")
    if choice == ChallengeChoice.SMS:
        return input("Input your code received via SMS: ").strip()
    if choice == ChallengeChoice.EMAIL:
        return input("Input your code received via Email: ").strip()
    return False


#App logic
if __name__ == "__main__":
    init_db() #Initializes Database
    CONFIG_FILE = "config.json" #Links config.json file to its variable

    #Manages the AES-GCM encryption key, it gets written to your config.json file
    key = get_or_create_json_key()
    aesgcm = AESGCM(key)

    #Load Gemini API key from the config.json file
    print("----------")
    print("If you haven't done it, you need to add your Gemini API key inside the config.json file, like this:")
    print("""
    {
        "SECRET_KEY": "a3f09c...",
        "GEMINI_API_KEY": "your-api-key-here"
    }
    """)
    print("Do not touch the SECRET_KEY as it is automatically generated")
    print("----------")
    if load_ai():
        print("Gemini API succesfully loaded")
    else:
        print("Check error")
        exit()