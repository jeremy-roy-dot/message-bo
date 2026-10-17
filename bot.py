import time
#import google
import sqlite3
import json
from instagrapi import Client
import os

def init_db():
    pass #initialize database if not already initialized
    #create table for each user I chat with, the actual chat messages and link everything with an auth system for the specific chatbot/personality


def user_auth():
    pass #if no user: create new user/personality:
    #else: login or create new user/personality


def memory_compiler():
    pass #turns big old chat into managable memories I can later hand out to the bot


def memory_cleaner():
    pass #cleans the convo memory so I don't go over the context window or make the chatbot hallucinates
    #also simplifies old memories while making sure to keep context to achieve its goal, uses Ai


def modifier_manager():
    pass #manages the AI modifiers from the conversation, on top of using the messages the interpreter interprets, it should be simulating events to impact mood


def message_interpreter():
    pass #receives/read all info from the messaging plateforms


def convo_starter():
    pass #will start a conversation if the mood checks a few things


def time_manager():
    pass #keeps the internal clock of events 


def terrorist_brain():
    pass #the logic of the bot where it coordinates everything, receive/send all the parameters to the AI and sends the message

#Login system for instagram client
IG_USERNAME = input()
IG_PASSWORD = input()

IG_cl = Client()
IG_session = "session.json"

if os.path.exists(IG_session):
    IG_cl.load_settings(IG_session)

IG_cl.login(IG_USERNAME, IG_PASSWORD)
IG_cl.dump_settings("session.json")