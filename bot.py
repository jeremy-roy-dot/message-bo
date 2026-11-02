from datetime import datetime, timezone
import os
import json
import sqlite3
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from google import genai
from google.genai.errors import APIError
from instagrapi import Client
from instagrapi.exceptions import BadPassword, UnknownError, LoginRequired, ChallengeRequired, ClientBadRequestError, TwoFactorRequired, ChallengeError, ChallengeUnknownStep, ChallengeSelfieCaptcha, RecaptchaChallengeForm, ClientError, UserNotFound
from instagrapi.mixins.challenge import ChallengeChoice
from instagrapi.types import DirectThread
from pydantic import BaseModel, Field

cl = None

# ==============================================
# Database, Gemini and Encryption key initiation
# ==============================================

#Initialize the database for the first time, if you later modify the tables, it will check and add them
def init_db() -> bool:
    with sqlite3.connect("app.db") as connection: 
        cursor = connection.cursor()

        create_table_query = """
        CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            username VARCHAR(30) NOT NULL UNIQUE,
            session_nonce BLOB,
            session_data BLOB
        );

        CREATE TABLE IF NOT EXISTS threads (
            thread_id TEXT PRIMARY KEY,
            username VARCHAR(30) NOT NULL UNIQUE,
            current_feeling TEXT,
            character TEXT NOT NULL,
            thread_data BLOB,
            thread_nonce BLOB
        );

        CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username on users(username);

        CREATE UNIQUE INDEX IF NOT EXISTS idx_threads_username on threads(username);
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
# Instagrapi logging and retrieving with encryption
# ===========================================================

#Security function used to raise an error if the client is not initialized and if it is then it sets client to cl
def ensure_logged_in(action_name: str) -> Client:
    global cl
    if cl is None:
        raise LoginRequired(f"{action_name} cannot run before the Instagram client is initialized.")
    if getattr(cl, "user_id", None) is None:
        raise LoginRequired(f"{action_name} cannot run before logging in.")
    return cl

#Saves the sessions.json file from the instagrapi client to the database of the user
def session_logging (username) -> bool:
    client = ensure_logged_in("session_logging")
    session_bytes = json.dumps(client.get_settings()).encode()
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

#Saves the thread object
def thread_saving (username, thread):

    thread_bytes = thread.json().encode()

    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, thread_bytes, username.encode())

    with sqlite3.connect("app.db") as connection:
        cursor = connection.cursor()
        update_query = """
        INSERT OR REPLACE INTO threads (thread_id, username, thread_nonce, thread_data)
        VALUES (?, ?, ?, ?);
        """
        cursor.execute(update_query, [thread.id, username, nonce, ciphertext])
    connection.close()

    print(f"Thread with {thread.users[0].username} has been properly saved and encrypted to the database")
    return True

#Loads the thread obejct from the database
def thread_loader (username, thread_id):
    with sqlite3.connect("app.db") as connection:
        cursor = connection.cursor()

        cursor.execute("SELECT thread_nonce, thread_data FROM threads WHERE thread_id=?", (thread_id,))
        row = cursor.fetchone()

        if not row:
            return False

        nonce, ciphertext = row

        decrypted_thread_bytes = aesgcm.decrypt(nonce, ciphertext, username.encode())
        json_string = decrypted_thread_bytes.decode()

        thread_object = DirectThread.parse_raw(json_string)
    connection.close()

    return thread_object

# ========================================================
# Instagrapi login and loading (when user already exists)
# ========================================================

#Log the user in, will need to be used in the instagrapi full client loading logic later
def instagrapi_login (username, password) -> bool:
    global cl
    if cl is None:
        raise LoginRequired("Instagram client was not initialized before login.")

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
    global cl
    if cl is None:
        raise LoginRequired("Instagram client was not initialized before restoring a session.")

    session_data = session_recupering(username)
    cl.set_settings(session_data)

    try:
        if getattr(cl, "user_id", None) is None:
            raise LoginRequired("Session restore attempted before login.")
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

#=========
# AI loop
#=========

# Makes the response format
class CharacterResponse(BaseModel):
    message: str = Field(description="Only the text of the next message, written by the persona in the same style as the earlier 'me' messages. No timestamp, no quotes, no labels.")
    new_feeling: str = Field(description="The persona's mood right after sending this message, which is also the mood they will be in when the reply arrives. A short phrase of 2 to 6 words (example: 'tired but chill'). It should be a small change from the previous mood, shaped by the time that passed and any small event.")

#Takes the convo_id and outputs a brand new message for the conversation based on the info in the database (takes thread_id, outputs message and new feeling post message)
def message_maker(thread):
    with sqlite3.connect("app.db") as connection:
        cursor = connection.cursor()

        cursor.execute("SELECT character, current_feeling FROM threads WHERE thread_id = ?", (thread.id,))
        row = cursor.fetchone()
        # In case the cursor found nothing with the inputted thread_id
        if not row:
            return False
        personality, feeling = row
    connection.close()
    
    contents = []
    if thread.id == "0":
        contents = ["This is a brand new conversation, start it according to your character"]
        last_msg = ""
        time_since_last = "No previous message"
    else:
        for message in thread.messages:
            sender = "model" if message.is_sent_by_viewer else "user"
            contents.append((message.timestamp, sender, message.text))
        last_msg = contents[0]
        total_seconds = (datetime.now(timezone.utc) - last_msg[0]).total_seconds()
        hours = int(total_seconds // 3600)
        minutes = int((total_seconds % 3600) // 60)
        time_since_last = f"{hours}h{minutes}min"

    prompt = f"""
    Conversation history from newest to oldest:
    {contents}
    """

    system_instruction = (
        "You are texting someone on a private messaging app. You are a real person, not an assistant.\n\n"
        f"PERSONA: {personality or 'a friend of the other sender'}\n"
        f"MOOD (as of your last message): {feeling or 'neutral happy'}\n"
        f"LAST THING MESSAGE: {last_msg or 'nothing, this is a brand new chat'}\n"
        f"RIGHT NOW: {datetime.now}\n"
        f"TIME SINCE THE LAST MESSAGE: {time_since_last}\n\n"
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
        "FINAL CHECK: Persona first, normal human second. Only the message text, no timestamp, no username."
    )

    try:
        # Generate content with the JSON structure
        output = ai_client.models.generate_content(
            model="gemini-3-flash",
            contents=prompt,
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

#=============================
# Instagrapi message manager
#=============================

#Grabs the thread object from instagram, this contains everything about the specific thread
def thread_grabber (username):
    client = ensure_logged_in("thread_grabber")

    user_id = client.user_id_from_username(username)
    thread = client.direct_thread_by_participants([int(user_id)])
    if not thread.id or thread.id == "0":
        print("The thread is new")
        return thread
    thread = client.direct_thread(thread_id=thread.id, amount=1000)
    return thread

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
    cl = Client() #Intialize instagrapi client
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
            user_name = input("Input instagram username: ").strip().lower()
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

    #Initialize a conversation or select one already existant
    with sqlite3.connect("app.db") as connection:
        cursor = connection.cursor()

        cursor.execute("SELECT username FROM thereads")
        rows = cursor.fetchall()

        print("Select a user to message or create a new one")
        count = 1

        usernames = []
        for username in rows:
            usernames.append(username[0])
            print(f"{username[0]} [{count}]")
            count += 1

        print(f"Create a new thread [{count}]")
    connection.close()

    try:
        selection = int(input().strip())
        if selection > count:
            print("Your number is invalid")
            exit()

    except ValueError:
        print("You inputed more than just a number")
        exit()

    #Conversation Initialization logic
    if selection == count:
        new_user = input("Input the username of the person you want to DM on instagram: ").strip().lower()
        try:
            cl.user_id_from_username(new_user)
        except UserNotFound:
            print("The username you input is wrong")
            exit()
        usernames.append(new_user)
        print(f"Will proceed with the initialization of a thread with {new_user}")
        thread = thread_grabber(new_user)

        with sqlite3.connect("app.db") as connection:
            cursor = connection.cursor()

            character = input("Input a description of your new characer, go into as much details as possible: ").lower()
            feeling = input("Input the base feeling you want you character to be in when starting the conversation, make it short and simple: ").lower()

            cursor.execute("INSERT INTO threads (thread_id, username, current_feeling, character) VALUES (?, ?, ?, ?)", ("0", new_user, feeling, character))

            message, new_feeling = message_maker(thread)
            message_response = cl.direct_send(
                text=message,
                user_ids=[thread.user_ids[0]]
            )
            new_thread_id = message_response.thread_id
            cursor.execute("UPDATE threads SET thread_id=? WHERE thread_id=0", (new_thread_id, ))
        connection.close()

        thread = thread_grabber(new_user)

    else:
        selected_user = usernames[selection - 1]
        with sqlite3.connect("app.db") as connection:
            cursor = connection.cursor()

            cursor.execute("SELECT thread_id FROM threads WHERE username=?", (selected_user, ))
            thread_id = cursor.fetchone()[0]
        connection.close()
        thread = thread_loader(selected_user, thread_id)

        #Verifies that the thread is up to date, if not, makes it up to date
        latest_message = cl.direct_messages(thread.id, amount=1)
        if thread.messages[0].id == latest_message.id:
            pass
        else:
            thread = thread_grabber(selected_user)

    #This is the part that finalizes the initialization before loading the main bot loop
    print(f"Activating bot for {usernames[selection - 1]}")
    print("Loading thread for real time display...")

    for msg in thread.messages:
        sender = "bot" if msg.is_sent_by_viewer else "user"
        raw_timestamp = msg.timestamp

        if len(str(raw_timestamp)) >= 16:
            timestamp_seconds = raw_timestamp / 1_000_000  # Microseconds
        else:
            timestamp_seconds = raw_timestamp / 1_000  
        datetime_object = datetime.fromtimestamp(timestamp_seconds)
        log_format = datetime_object.strftime("%Y-%m-%d %H:%M:%S")

        print(f"[{log_format}]{sender}: {msg.text}")
    print("Done printing the message history. You are now live")
    
    while True:
        #have something to retrieve messages in real time and put the answer/send part here

        #Have the timer that does something like this: when receiving new message decides to make the current availibility high, medium or low and based on that we have 3 timers for different time to answer (30s to 1min without time to write, 5-15min, 1h-3h) also use it to implement rest moments where the bot will never answer and add the logic so it can reply a bit faster for a while after a long break since long break = activity and after the activity is done, no reason to go back to long wait time

        #Have a stop to make it so the user can interrupt

        #After each new message update the database

        #Loop (3 things: catch messages, be able to manually message and update the database)
        pass