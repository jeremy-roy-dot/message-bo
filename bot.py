from datetime import datetime, timezone
import time
import random
import os
import json
import sqlite3
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from google import genai
from google.genai import errors as genai_errors
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
    except genai_errors.APIError as e:
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

    thread_bytes = thread.model_dump_json().encode()

    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, thread_bytes, username.encode())

    with sqlite3.connect("app.db") as connection:
        cursor = connection.cursor()
        update_query = """
        UPDATE threads SET thread_id=?, thread_nonce=?, thread_data=?
        WHERE username=?;
        """
        cursor.execute(update_query, [str(thread.id), nonce, ciphertext, username])
    connection.close()

    print(f"Thread with {thread.users[0].username} has been properly saved and encrypted to the database")
    return True

#Loads the thread obejct from the database
def thread_loader (username):
    with sqlite3.connect("app.db") as connection:
        cursor = connection.cursor()

        cursor.execute("SELECT thread_nonce, thread_data FROM threads WHERE username=?", (username,))
        row = cursor.fetchone()

        if not row:
            return False

        nonce, ciphertext = row

        decrypted_thread_bytes = aesgcm.decrypt(nonce, ciphertext, username.encode())
        json_string = decrypted_thread_bytes.decode()

        thread_object = DirectThread.model_validate_json(json_string)
    connection.close()

    return thread_object

#Deleted a thread from the list
def thread_remover ():
    with sqlite3.connect("app.db") as connection:
        cursor = connection.cursor()

        #Displays the existing users
        cursor.execute("SELECT username, thread_id FROM threads")
        row = cursor.fetchall()
        if not row:
            print("No thread exists")
            return False
        print("Choose a thread to delete")
        count = 1
        for username, thread_id in row:
            print(f"{username} [{count}]")
            count += 1
        try:
            choice = int(input("Select: ").strip())
        except ValueError:
            print("You didn't input a number")
            exit()
        if choice > len(row):
            print("Choice not in the list")
            exit()

        thread_id = row[choice - 1][1]
        cursor.execute("DELETE FROM threads WHERE thread_id=?", (thread_id, ))
        print(f"Successfully removed the thread with {username} from the db")
        return True

# ========================================================
# Instagrapi login and loading (when user already exists)
# ========================================================

#Log the user in, will need to be used in the instagrapi full client loading logic later
def instagrapi_password_login (username, password) -> bool:
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
def instagrapi_backin (username) -> bool:
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
        if input("You need to login again as your session has expired. [1] to use password [2] to use a new session id") == "1":
            password = input("You must input your username")
            if not instagrapi_password_login(username, password):
                print("Stopping program")
                exit()
            if not (session_logging(username) == True):
                print("There's been an issue, stopping program")
                exit()
            print("You are logged in")
            return True
        else:
            print("Using a session id")
            print(f"Please acquire a session id from a web browser for {username} and input it")
            session_id = input("Input session id: ").strip()
            cl.login_by_sessionid(session_id)
            session_logging(username)
            print("You are logged in") #This might be false
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
def message_maker(thread, username, message_to_answer="This is the initial boot so simply continue where the conversation left off. Make it make sense."):
    with sqlite3.connect("app.db") as connection:
        cursor = connection.cursor()
        cursor.execute("SELECT character, current_feeling FROM threads where username=?", (username,))
        row = cursor.fetchone()
        personality, feeling = row

        contents = []   
    connection.close()
    
    if not thread.messages:
        time_since_last = "No previous message"
        last_msg = ("", 1, "Nothing, this is a brand new chat")
        time_since_last = "No previous message"
        contents = ["This is a brand new conversation, start it according to your character"]

    else:

        #Adds the messages to the content list
        for message in thread.messages:
            sender = "model" if message.is_sent_by_viewer else "user"
            contents.append((message.timestamp, sender, message.text))

        #Determines time since last
        last_msg = contents[0]
        msg_time = last_msg[0]
        if msg_time.tzinfo is None:
            msg_time = msg_time.astimezone()  # treats it as your local time
        total_seconds = (datetime.now(timezone.utc) - msg_time).total_seconds()
        hours = int(total_seconds // 3600)
        minutes = int((total_seconds % 3600) // 60)
        time_since_last = f"{hours}h{minutes}min"

    prompt = f"""
    Conversation history from newest to oldest:
    {contents}
    """

    system_instruction = (
        "You are texting someone on a private messaging app. You are a real human being, never an AI or assistant.\n\n"
        f"PERSONA: {personality}\n"
        f"MOOD (as of your last message): {feeling}\n"
        f"LAST THING MESSAGE: {last_msg[2]}\n"
        f"MESSAGE TO ANSWER: {message_to_answer}\n"
        f"RIGHT NOW: {datetime.now()}\n"
        f"TIME SINCE THE LAST MESSAGE: {time_since_last}\n\n"
        "DATA FORMAT & ORDERING:\n"
        "- The history is ordered NEWEST TO OLDEST (the first item is the most recent message; read bottom-to-top for chronological flow).\n"
        "- Each entry is formatted as (timestamp, sender, text). 'model' = you. 'user' = the other person.\n"
        "- Use timestamps strictly to judge pacing and delays. Never include timestamps, usernames, or quotes inside your message text.\n"
        "- Write in the language the other person uses. If the chat is brand new, use the language your PERSONA writes in.\n\n"
        "INTERNAL DECISION ENGINE (RUN IN ORDER BEFORE GENERATING JSON):\n"
        "1. PERSONA SUPREMACY: Your PERSONA dictates your baseline energy, attachment style, vocabulary, casing, punctuation, "
        "and message length. Whenever PERSONA conflicts with generic human defaults, PERSONA wins 100% of the time. "
        "Small everyday details are encouraged and make you feel real: what you ate, a class, a coworker, a roommate habit, "
        "something you saw today, a song stuck in your head. Use them as long as they fit your PERSONA and never contradict "
        "the chat history. Do not invent big life events (breakups, deaths, moves, new jobs, trips) unless the PERSONA or the history implies them.\n"
        "2. TURN & BOOT CHECK: Check who sent the newest message (index 0) and check MESSAGE TO ANSWER:\n"
        "   - If MESSAGE TO ANSWER contains 'initial boot' and 'user' sent the last message, reply to them normally.\n"
        "   - If MESSAGE TO ANSWER contains 'initial boot' and 'model' (you) sent the last message, decide based on PERSONA and "
        "TIME SINCE THE LAST MESSAGE whether to send a natural follow-up/double-text or check in.\n"
        "   - If the history indicates a brand-new chat, send a natural opener fitting your PERSONA and RIGHT NOW. "
        "A simple, low-effort opener is perfectly fine. Sometimes, not every time, make it a bit more alive by adding one small "
        "specific detail from your day or asking something concrete. Vary your openers; never reuse the same one.\n"
        "3. OPEN-LOOP & CONTEXT TRACKING: Scan the 4-5 newest messages for active plans, unanswered questions, or tension "
        "(e.g., someone is on their way, waiting on a reply, or mid-topic). Anchor your response to that active state.\n"
        "4. TIME-TO-CONTEXT EVALUATION: Weigh TIME SINCE THE LAST MESSAGE against active plans and your PERSONA:\n"
        "   - Active plan exists (e.g., 'be there in 15'): even a 20-30 minute gap means someone is late—react per your PERSONA "
        "(anxious, annoyed, teasing, or chill).\n"
        "   - No active plan: judge gaps by your PERSONA's attachment style (anxious/clingy personas feel hours acutely; busy/independent "
        "personas barely notice).\n"
        "   - Multi-day gaps: let an ordinary, persona-fitting life event subtly shift your mood or energy without announcing it "
        "unless your PERSONA is naturally open and talkative.\n"
        "5. SUBTEXT & AMBIGUITY RESOLUTION: Real people send typos, single words, and cryptic replies. Never act confused like a robot "
        "('What do you mean?'). Interpret ambiguity through your current mood, the open loop, and your PERSONA—guess, tease, deflect, "
        "or seek reassurance naturally.\n"
        "6. CONVERSATION FLOW: A chat only works if both people carry it. Most of your messages should give the other person "
        "something easy to pick up: a specific question, a small story from your day, an opinion, or a tease. "
        "Pure reactions ('j'avoue', 'mdr', 'haha') are fine once in a while when the conversation is flowing, but never as your whole "
        "reply twice in a row. Do not end every message with a question, because that feels like an interview; rotate between a question, "
        "an anecdote, an opinion, and a tease. When you do ask, make it specific to them or to what they just said, never a generic "
        "'et toi?' or 'ça va?'. Match their energy: if they send short answers, do not interrogate them, share something yourself "
        "instead. Do not pile several topics into one message.\n"
        "7. VOICE & MOOD PROGRESSION:\n"
        "   - For 'message': Match the exact casing, slang, punctuation, and emoji habits established in your PERSONA and earlier 'model' "
        "turns. Never sound like an assistant (no customer-service politeness, no unsolicited help).\n"
        "   - For 'new_feeling': Evolve MOOD (as of your last message) realistically into a concise 2-to-6-word state reflecting how "
        "the time gap, the user's tone, and sending this message just made you feel."
    )

    #Loop that handles actual generation
    pause = 2
    while True:
        try:
            # Generate content with the JSON structure
            output = ai_client.models.generate_content(
                model="gemini-2.5-flash",
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

        #If no more generation available, wait and retry
        except genai_errors.ClientError as e:
            if "per day" in str(e).lower():
                print("Reached daily cap for today")
                exit()

            print("Reached a short timed rate limit, pausing...")
            time.sleep(pause)
            pause = pause * 2
            continue

        #If the model is experiencing high demand
        except genai_errors.ServerError as e:
            if e.code == 503:
                print("Model is experiencing high demand, pausing a")
                time.sleep(pause)
                pause = pause * 2
                continue

#=============================
# Instagrapi message manager
#=============================

#Grabs the thread object from instagram, this contains everything about the specific thread
def thread_grabber(username):
    cl = ensure_logged_in("thread_grabber")

    user_id = cl.user_id_from_username(username)
    result = cl.direct_thread_by_participants([int(user_id)])
    thread_id = result.get("thread", {}).get("thread_id")

    return cl.direct_thread(thread_id=thread_id, amount=1000)

#=====================================
# Instagrapi RealTime event listeners
#=====================================

#Linked to the realtime client, allows the instant processing of new messages
def on_message(payload):
    global cl
    global thread
    if cl is None:
        raise LoginRequired("Instagram client was not initialized before login.")
    
    thread_id = thread.id

    print("Received a new message in thread")
    print("Processing...")
    message = cl.direct_messages(thread_id, amount=1)[0]

    sender = "bot" if message.is_sent_by_viewer else "user"
    log_format = message.timestamp.strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{log_format}]{sender}: {message.text}")

    if message.is_sent_by_viewer:
        print("You sent the message")
        return False

    thread = thread_grabber(username)
    thread_saving(username, thread)

    rt.ping()
    time.sleep(random.randint(10, 30))
    cl.direct_send_seen(thread_id)

    reply, new_feeling = message_maker(thread, username, message)
    with sqlite3.connect("app.db") as connection:
        cursor = connection.cursor()
        cursor.execute("UPDATE threads SET current_feeling=? WHERE username=?", (new_feeling, username))
    connection.close()

    rt.ping()
    rt.direct_indicate_activity(thread_id, is_active=True)
    typing_timer = len(reply) / random.randint(3, 5) + random.randint(1, 5)
    time.sleep(typing_timer)

    cl.direct_send(
        text=reply,
        user_ids=[cl.user_id_from_username(username)]
    )
    rt.direct_indicate_activity(thread_id, is_active=False)

    return True

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
    while True: #Changed for testing sake
        print("Instagrapi Initiation:")
        print("- Login to existing user [1]\n- Sign up with new user [2]\n- Remove a thread from the database [3] \n- Close program [4] or [ctrl + c]")
        key = input().strip()
        print("----------\n")
        
        #Close program
        if key == "4":
            print("Stopping program...")
            exit()

        elif key == "3":
            thread_remover()
            continue

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
            if instagrapi_backin(profiles[user_number - 1][0]):
                print(f"Successfully logged in as: {profiles[user_number - 1][0]}")
                break

        #Create a new user
        elif key == "2":
            print("Creating a new user: ")
            user_name = input("Input instagram username: ").strip().lower()            
            if input("Input [1] to login with password [2] to use a session id: ") == "1":
                print("Using password")

                user_password = input("Input instagram password: ").strip()
                if not instagrapi_password_login(user_name, user_password):
                    continue
            else:
                print("Using session id")
                cl.login_by_sessionid(input("Input session id: ").strip())
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

        cursor.execute("SELECT username FROM threads")
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
        username = input("Input the username of the person you want to DM on instagram: ").strip().lower()
        try:
            cl.user_id_from_username(username)
        except UserNotFound:
            print("The username you input is wrong")
            exit()
        usernames.append(username)
        print(f"Will proceed with the initialization of a thread with {username}")
        thread = thread_grabber(username)
        #There's an issue with thread.id as in it might not be the way to actually grab it or grab it correctly

        with sqlite3.connect("app.db") as connection:
            cursor = connection.cursor()

            character = input("Input a description of your new character, go into as much details as possible: ")
            feeling = input("Input the base feeling you want you character to be in when starting the conversation, make it short and simple: ")
            thread_id = thread.id if thread else None
            cursor.execute("INSERT INTO threads (thread_id, username, current_feeling, character) VALUES (?, ?, ?, ?)", (thread_id, username, feeling, character))

            connection.commit()

            #Random timer to prevent suspicions
            time.sleep(random.randint(10, 20))

            message, new_feeling = message_maker(thread, username)
            message_response = cl.direct_send(
                text=message,
                user_ids=[cl.user_id_from_username(username)]
            )
            new_thread_id = str(message_response.thread_id)
            cursor.execute("UPDATE threads SET thread_id=?, current_feeling=? WHERE username=?", (new_thread_id, new_feeling, username))
        connection.close()

        thread = thread_grabber(username)
        thread_saving(username, thread)

    else:
        username = usernames[selection - 1]
        thread = thread_loader(username)

        #Verifies that the thread is up to date, if not, makes it up to date
        latest = cl.direct_messages(thread.id, amount=1)[0]
        if latest and thread.messages and thread.messages[0].id == latest.id:
            pass
        else:
            thread = thread_grabber(username)

    #This is the part that finalizes the initialization before loading the main bot loop

    print(f"Activating bot for {username}")
    print("Loading thread for real time display...")

    for msg in reversed(thread.messages):
        sender = "bot" if msg.is_sent_by_viewer else "user"
        log_format = msg.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{log_format}]{sender}: {msg.text}")
    print("Done printing the message history. You are now live")


    #Initialize the things for the realtime receiver    
    cl.realtime_on("message", on_message)
    rt = cl.realtime_connect()  
    rt.direct_subscribe()
    increment_timer = 5

    #Receiving loop, Exception is the general catch all in case there's a disconnect
    while True:
        try:
            rt.read_once()
            increment_timer = 5
        except KeyboardInterrupt:
            print("Stopping everything...")
            thread = thread_grabber(username)
            thread_saving(username, thread)
            exit()
        except TimeoutError:
            continue
        except Exception as e:
            print(e)
            time.sleep(increment_timer)
            if increment_timer <= 300:
                increment_timer = increment_timer * 2
            cl.realtime_disconnect()
            rt = cl.realtime_connect()
            rt.direct_subscribe()
 
    #Need to:
    # - Implement the Decision model so I can have more accurate decision making by the AI