# api/auth.py

import uuid
import hashlib
import os
from fastapi import APIRouter, HTTPException
from core.database import DatabaseManager

router = APIRouter()
db     = DatabaseManager()


def hash_password(pw: str, salt: str = None):
    """
    Hash password with a random salt using SHA-256.
    Returns 'salt:hash' string for storage.
    If salt is provided (for verification), uses that salt.
    """
    if salt is None:
        salt = os.urandom(16).hex()
    digest = hashlib.sha256(f"{salt}{pw}".encode()).hexdigest()
    return f"{salt}:{digest}"


def verify_password(pw: str, stored: str) -> bool:
    """Verify a plaintext password against a stored 'salt:hash' value."""
    try:
        salt, _ = stored.split(":", 1)
        return hash_password(pw, salt) == stored
    except Exception:
        return False


def generate_api_key():
    return str(uuid.uuid4())


@router.post("/signup")
def signup(email: str, password: str):
    user_id = str(uuid.uuid4())

    db.db.table("users").insert({
        "id":            user_id,
        "email":         email,
        "password_hash": hash_password(password),
        "api_key":       generate_api_key(),
        "plan":          "free"
    }).execute()

    return {"message": "User created"}


@router.post("/login")
def login(email: str, password: str):
    res = db.db.table("users").select("*").eq("email", email).execute()

    if not res.data:
        raise HTTPException(404, "User not found")

    user = res.data[0]

    if not verify_password(password, user["password_hash"]):
        raise HTTPException(403, "Invalid password")

    return {
        "api_key": user["api_key"],
        "user_id": user["id"]
    }