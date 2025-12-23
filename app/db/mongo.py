from dotenv import load_dotenv
load_dotenv()

from pymongo import MongoClient
import os

MONGO_URI = os.getenv("MONGO_URI")

if not MONGO_URI:
    raise RuntimeError("MONGO_URI not found in environment variables")

client = MongoClient(MONGO_URI)

db = client["securescan"]

user_collection = db["users"]
scan_collection = db["scans"]
