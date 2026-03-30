import uuid
import hashlib
from fastapi import APIRouter, HTTPException
from core.database import DatabaseManager

router = APIRouter()
db = DatabaseManager()

def hash_password(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def generate_api_key():
    return str(uuid.uuid4())

@router.post("/signup")
def signup(email: str, password: str):
    user_id = str(uuid.uuid4())

    db.db.table("users").insert({
        "id": user_id,
        "email": email,
        "password_hash": hash_password(password),
        "api_key": generate_api_key(),
        "plan": "free"
    }).execute()

    return {"message": "User created"}

@router.post("/login")
def login(email: str, password: str):
    res = db.db.table("users").select("*").eq("email", email).execute()

    if not res.data:
        raise HTTPException(404, "User not found")

    user = res.data[0]

    if user["password_hash"] != hash_password(password):
        raise HTTPException(403, "Invalid password")

    return {
        "api_key": user["api_key"],
        "user_id": user["id"]
    }