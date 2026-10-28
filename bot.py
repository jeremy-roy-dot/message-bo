from datetime import datetime
import os
import json
import sqlite3
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from google import genai
from google.genai.errors import APIError
from instagrapi import Client
from instagrapi.exceptions import BadPassword, UnknownError, LoginRequired, ChallengeRequired, ClientBadRequestError, TwoFactorRequired, ChallengeError, ChallengeUnknownStep, ChallengeSelfieCaptcha, RecaptchaChallengeForm, ClientError
from instagrapi.mixins.challenge import ChallengeChoice
from pydantic import BaseModel, Field

# ==============================================
# Database, Gemini and Encryption key initiation
# ==============================================

#Initialize the database for the first time, if you later modify the tables, it will check and add them
def init_db() -> bool:
    with sqlite3.connect("app.db") as connection: 
        cursor = connection.cursor()

        create_table_query = """
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username VARCHAR(30) NOT NULL UNIQUE,
            session_nonce BLOB,
            session_data BLOB
        );

        CREATE TABLE IF NOT EXISTS threads (
            thread_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username VARCHAR(30) NOT NULL UNIQUE,
            current_feeling TEXT NOT NULL,
            character TEXT NOT NULL,
            last_msg TEXT
        );

        CREATE TABLE IF NOT EXISTS messages (
            message_id INTEGER PRIMARY KEY,
            thread_id INTEGER NOT NULL,
            sender TEXT NOT NULL,
            text_content TEXT,
            timestamp TEXT NOT NULL,
            FOREIGN KEY (thread_id) REFERENCES threads(thread_id)
        );

        CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username on users(username);

        CREATE UNIQUE INDEX IF NOT EXISTS idx_conversations_username on conversations(username);
        """

        cursor.executescript(create_table_query)
        print("Succesfully initialized database!")
    return True

#Creates or load the key in charge of encrypting the session data json files that go into the database
def get_or_create_json_key ():

    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as f:

            data = json.load(f)
            key_hex = data["SECRET_KEY"]
            print("Loaded key for AES-GCM")
            return bytes.fromhex(key_hex)
    else:
        print("No key found, making a new one")
        new_key_bytes = AESGCM.generate_key(bit_length=256)

        payload = {"SECRET_KEY": new_key_bytes.hex()}

        with open(CONFIG_FILE, "w") as f:
            json.dump(payload, f, indent=4)

        print(f"Saved new key for AES-GCM to ./{CONFIG_FILE}")
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

        global ai_client
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
    
# ===========================================================
# Instagrapi Session logging and retrieving with encryption
# ===========================================================

#Saves the sessions.json file from the instagrapi client to the database of the user
def session_logging (username) -> bool:
    cl = Client()
    session_bytes = json.dumps(cl.get_settings()).encode()
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, session_bytes, username.encode())

    with sqlite3.connect("app.db") as connection:
        cursor = connection.cursor()

        update_query = """
        UPDATE users
        SET session_nonce = ?, session_data = ?
        WHERE username = ?;
        """
        cursor.execute(update_query, [nonce, ciphertext, username])

        print("Session succesfully saved to database")
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
    return session_dict

# ========================================================
# Instagrapi login and loading (when user already exists)
# ========================================================

#Log the user in, will need to be used in the instagrapi full client loading logic later
def instagrapi_login (username, password) -> bool:
    cl = Client()
    cl.challenge_code_handler = challenge_code_handler

    try: #to login
        cl.login(username, password)
        print("You're logged in!")
        return True
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
    cl.set_settings(session_data)

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
            exit()
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

# ============================
# AI loop
# ============================

class CharacterResponse(BaseModel):
    message: str = Field(description="Only the text of the next message, written by the persona in the same style as the earlier 'me' messages. No timestamp, no quotes, no labels.")
    new_feeling: str = Field(description="The persona's mood right after sending this message, which is also the mood they will be in when the reply arrives. A short phrase of 2 to 6 words (example: 'tired but chill'). It should be a small change from the previous mood, shaped by the time that passed and any small event.")


def message_maker(convo_id: int):
    with sqlite3.connect("app.db") as connection:
        cursor = connection.cursor()

        cursor.execute("SELECT character, current_feeling, last_msg FROM threads WHERE thread_id = ?", (convo_id,))
        thread = cursor.fetchone()
        # In case the cursor found nothing with the inputted thread_id
        if not thread:
            return False
        personality, feeling, last_msg = thread

        cursor.execute("SELECT timestamp, sender, text_content FROM messages WHERE thread_id = ? ORDER BY message_id ASC", (convo_id,))
        messages = cursor.fetchall()
    connection.close()
    
    now = datetime.now()
    now_text = now.strftime("%A %Y-%m-%d %H:%M")

    # Time since the last message, if none is figured out: keep unknown
    gap_text = "unknown"
    if messages:
        try:
            gap = now - datetime.fromisoformat(str(messages[-1][0]))
            minutes = gap.total_seconds() / 60
            if minutes < 60:
                gap_text = f"{int(minutes)} minutes"
            elif minutes < 48 * 60:
                gap_text = f"{round(minutes / 60)} hours"
            else:
                gap_text = f"{gap.days} days"
        except ValueError:
            pass

    system_instruction = (
        "You are texting someone on a private messaging app. You are a real person, not an assistant.\n\n"
        f"PERSONA: {personality or 'a friend of the other sender'}\n"
        f"MOOD (as of your last message): {feeling or 'neutral happy'}\n"
        f"LAST THING YOU REMEMBER: {last_msg or 'nothing, this is a brand new chat'}\n"
        f"RIGHT NOW: {now_text}\n"
        f"TIME SINCE THE LAST MESSAGE: {gap_text}\n\n"
        "YOUR TASK: Read the chat history and write the next message your persona would send.\n\n"
        "HOW THE HISTORY LOOKS: Your own earlier messages are the 'model' turns. The other person's messages are the 'user' turns. "
        "Each one starts with a [timestamp] that is only there to help you judge timing. "
        "Never write a timestamp in your message.\n\n"
        "HOW TO USE THESE RULES: The persona is the boss. Every message you write must pass through it. "
        "The rules below describe a normal, average person. Whenever the persona says something different "
        "(busy, shy, loud, funny, tired...), follow the persona and drop the default. "
        "If the persona says nothing about something, use the default. "
        "Never invent new traits for the persona.\n\n"
        "RULES:\n"
        "1) NORMAL HUMAN: By default you are an average person on DMs. Casual, mostly short messages, "
        "not always excited, doesn't always ask a question back, sometimes dry or distracted. "
        "Never sound like an assistant (no 'Sure!', no offering help, no summaries). "
        "The weaker the persona is, the more you act like this normal person.\n"
        "2) VOICE: Look at your own earlier messages in the history. Write the same way: "
        "same length, slang, punctuation, emojis, capital letters, language. Stay consistent. "
        "Over time you may slowly pick up a little of how the other person writes, like real friends do, "
        "but your own voice always comes first. Do not copy them.\n"
        "3) TIME AND MOOD: Use RIGHT NOW and TIME SINCE THE LAST MESSAGE to judge what day and time it is, and how long you were away. "
        "Your mood should not stay the same forever. By default, life is boring: most days nothing special happens, "
        "you are just a little tired. Weekends are relaxed. "
        "Then let the persona change this (a busy parent who works out has a tired weekend, for example).\n"
        "4) LIFE EVENTS: After a longer gap, something small may have happened to you. Keep it ordinary and fitting for the persona. "
        "A few hours = nothing. A few days = a small thing. A few weeks = something bigger. "
        "Most of the time, nothing big happened.\n"
        "5) EVENTS STAY HIDDEN: Never announce or explain what happened. It only shows through your mood and tone "
        "(shorter, more tired, more upbeat...). Whether you talk about it depends on the persona: "
        "open, talkative personas may bring it up, quiet personas only say it if asked. "
        "If the persona doesn't say, don't say much, like a normal person.\n"
        "6) NEW CHAT: If the only thing in the history is a note saying it is a brand new chat, "
        "start the conversation the way the persona naturally would, short and casual. "
        "Never mention missing history and never invent a past.\n\n"
        "FINAL CHECK: Persona first, normal human second. Only the message text, no timestamp."
    )

    contents = []
    for timestamp, sender, text_content in messages:
        # Map your custom database senders to API roles ('user' or 'model')
        role = "model" if sender == "me" else "user"
        contents.append({
            "role": role,
            "parts": [{"text": f"[{timestamp}] {text_content}"}]
        })

    # The API needs at least one message, so a brand new chat gets one note
    if not contents:
        contents.append({
            "role": "user",
            "parts": [{"text": f"[{now_text}] (Brand new chat. No messages yet. Send the first message.)"}]
        })

    try:
        # Generate content with the JSON structure
        output = ai_client.models.generate_content(
            model="gemini-3-flash",
            contents=contents,
            config={
                "system_instruction": system_instruction,
                "response_mime_type": "application/json",
                "response_schema": CharacterResponse,
                "temperature": 0.7,  # Adds natural, human-like variance
            }
        )

        result = output.parsed
        return result.message, result.new_feeling
    
    except Exception as e:
        print(f"Generation or parsing failed: {e}")
        return False

# ==============================================
# Main loop and initiation logic
# ==============================================

#App logic
if __name__ == "__main__":
    print()

    init_db() #Initializes Database
    CONFIG_FILE = "config.json" #Links config.json file to its variable
    #Manages the AES-GCM encryption key, it gets written to your config.json file
    key = get_or_create_json_key()
    aesgcm = AESGCM(key)
    print()
    
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
    print("----------\n")

    #Tries to load Gemini
    if load_ai():
        print("Gemini API succesfully loaded!")
        print("----------")
    else:
        print("Check error above")
        exit()

    #Instagrapi initiation
    while True:
        print("Instagrapi Initiation:")
        print("- Login to existing user [1]\n- Sign up with new user [2]\n- Close program [3] or [ctrl + c]")
        key = input().strip()
        print("----------\n")
        
        #Close program
        if key == "3":
            print("Stopping program...")
            exit()

        #Log into an existing user
        elif key == "1":
            #Gets all users from the database and prints them
            with sqlite3.connect("app.db") as connection:
                cursor = connection.cursor()

                query = "SELECT username FROM users;"
                cursor.execute(query)
                profiles = cursor.fetchall()

                print("Select User:")
                user_count = 1
                #If there are no registered user, says it and goes back to the start with instagrapi initialization
                if not profiles:
                    print("No User exists")
                    continue
                for username in profiles:
                    print(f"User: {username[0]} [{user_count}]")
                    user_count += 1
            print("(ctrl + c to close)")

            #Requests the user to choose a user
            while True:
                user_number = input("Input number of the user you want: ").strip()
                try:
                    user_number = int(user_number)
                    break
                except ValueError:
                    print("Uses a number next time.")
                    continue
            print(f"Success choosing user[{user_number}]: {profiles[user_number - 1][0]}")

            #Requests password and tries to login, if instagrapi_backin fails, it auto closes the program
            user_password = input("Input password: ").strip()
            if instagrapi_backin(profiles[user_number - 1][0], user_password):
                print(f"Successfully logged in as: {profiles[user_number - 1][0]}")
                break

        #Create a new user
        elif key == "2":
            print("Creating a new user: ")
            user_name = input("Input instagram username: ").strip()
            user_password = input("Input instagram password: ").strip()
            if not instagrapi_login(user_name, user_password):
                continue
            #Logs the new session data into the database for a complete table
            with sqlite3.connect("app.db") as connection:
                cursor = connection.cursor()
                cursor.execute("INSERT INTO users (username) VALUES (?);", (user_name,))
            session_logging(user_name)
            print("You are setup!")
            print("----------\n")
            break

        #wrong input handling
        else:
            print("Please input 1, 2 or 3")
            continue

    #Test loop so it doesn't close, this is just a direct messaging with gemini
    while True:

        message = input("Input your message to gemini: ")
        print("----------")

        response = ai_client.models.generate_content(
        model="gemini-2.5-flash",
        contents=message,
        )

        print(response.text)
        print("----------")