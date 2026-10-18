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
from instagrapi.exceptions import BadPassword, UnknownError, LoginRequired, ChallengeRequired, ClientBadRequestError

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
def session_saving (cl, username) -> bool:
    
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
def session_loading (cl, username) -> bool:

    with sqlite3.connect("app.db") as connection:
        cursor = connection.cursor()

        retrieve_query = """
        SELECT session_nonce, session_data FROM users WHERE username = ?
        """

        cursor.execute(retrieve_query, [username])
        row = cursor.fetchone()

        session_dict = json.loads(str(aesgcm.decrypt(row[0], row[1], username.encode()).decode()))

        cl.set_settings(session_dict)
    connection.close()
    return True

#Log the user in, will need to be used in the instagrapi full client loading logic later
def user_login() -> bool:

    print("Please Login")
    IG_USERNAME = input("Enter your username: ")
    IG_PASSWORD = input("Enter your password: ", echo_char="*")

    ph = PasswordHasher()

    try:
        with sqlite3.connect("app.db") as connection:    
            cursor = connection.cursor()

            cursor.execute("SELECT password_hash FROM users WHERE username = ?", [IG_USERNAME])
            row = cursor.fetchone()

            if row is None:
                return False #wrong username

            stored_hash = row[0]

            ph.verify(stored_hash, IG_PASSWORD)
        
    except VerifyMismatchError:
        return False #wrong password

    finally:
        connection.close()
        return True #grant access to session

#Adds the user to the database and should be used to initialize the session, to use in full instagrapi client initialization later
def user_signup () -> bool: 

    print("Please signup")
    IG_USERNAME = input("Enter your username: ")
    IG_PASSWORD = input("Enter your password: ")

    IG_cl = Client()

    try:
        IG_cl.login("username", "password")
        print("You are logged in to your instagram account")
        return True

    #Wrong password
    except BadPassword as e:
        print(f"Error: {e}")
        print("Either the password is wrong, or Instagram has flagged your IP address/Proxy.")
        return False

    #Generally wrong username
    except UnknownError as e:
        #checks the specific error received
        if "couldn't find an account" in str(e):
            print("Authentication Failed: That username does not exist.")
            return False
        else:
            print(f"An unexpected Instagram error occurred: {e}")
            return False

    #Code sent
    except ChallengeRequired as e:
        print("A verification code as been sent ")

        #Get the challenge data from IG_cl.lastjson where instagrapi stores it
        challenge_data = IG_cl.last_json

        #Check where the challenge was sent
        step_name = challenge_data.get("step_name", "")
        step_data = challenge_data.get("step_data", {})

        if "email" in step_name:
            obscured_email = step_data.get("contact_point", "your registered email")
            print(f"Check your inbox! A security code was sent to: {obscured_email}")

        elif "sms" in step_name or "phone" in step_name:
            obscured_phone = step_data.get("contact_point", "your registered phone number")
            print(f"Check your texts! A security code was sent to: {obscured_phone}")
        
        elif "two_factor" in step_name:
            print("2FA Active: Please generate a code from your Authenticator App.")
        
        else:
            print(f"Unknown checkpoint type ({step_name}). Raw data: {challenge_data}")

        verification_code = input("Enter the verification code: ").strip()

        try:
            IG_cl.challenge_resolve(verification_code)
            print("Challenge Solved, you are now logged in")
            return True

        except ClientBadRequestError as e:
            #Triggers when Instagram rejects the 6-digit code (400 Bad Request)
            print(f"Verification failed: The code you provided was wrong or has expired.")
            print(f"Raw Instagram response details: {e}")
            return False

#Login system for instagram client
IG_USERNAME = input()
IG_PASSWORD = input()

IG_cl = Client()
IG_session = "session.json"

if os.path.exists(IG_session):
    IG_cl.load_settings(IG_session)

try: #makes sure session is not expired by requesting something
    IG_cl.get_timeline_feed()

except LoginRequired: #if it returns the error that says we are not logged in, it means the session UUID expired, so we need to store the thing we don't want to reset (device info), wipe the settings, restore the device info and relogging to get a new session
    old_settings = IG_cl.get_settings()
    IG_cl.set_settings({})
    IG_cl.set_uuids(old_settings["uuids"])
    IG_cl.set_device(old_settings["device_settings"])
    IG_cl.set_user_agent(old_settings["user_agent"])
    IG_cl.login(IG_USERNAME, IG_PASSWORD)
    IG_cl.dump_settings("session.json")

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