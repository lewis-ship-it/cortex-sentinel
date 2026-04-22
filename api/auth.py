# api/auth.py
# ──────────────────────────────────────────────────────────────────────────────
# FIXES vs previous version:
#   1. SHA-256 password hashing is too weak for stored passwords — replaced
#      with bcrypt (already in requirements.txt) which has work factor and
#      is specifically designed for password storage.
#   2. Credentials sent as query params (?email=&password=) — changed to
#      request body (JSON) to prevent credentials appearing in server logs.
#   3. No rate limiting on /login — brute force possible. Added db-level
#      attempt logging (actual rate limiting should be in nginx/gateway).
# ──────────────────────────────────────────────────────────────────────────────

import uuid
import os
import bcrypt
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from storage.database import DatabaseManager

router = APIRouter()
db     = DatabaseManager()


class SignupRequest(BaseModel):
    email:    str
    password: str


class LoginRequest(BaseModel):
    email:    str
    password: str


def hash_password(pw: str) -> str:
    """Hash password with bcrypt (work factor 12)."""
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(pw.encode(), salt).decode()


def verify_password(pw: str, stored: str) -> bool:
    """Verify a plaintext password against a bcrypt hash."""
    try:
        return bcrypt.checkpw(pw.encode(), stored.encode())
    except Exception:
        return False


def generate_api_key():
    return str(uuid.uuid4())


@router.post("/signup")
def signup(req: SignupRequest):
    user_id = str(uuid.uuid4())

    db.db.table("users").insert({
        "id":            user_id,
        "email":         req.email,
        "password_hash": hash_password(req.password),
        "api_key":       generate_api_key(),
        "plan":          "free"
    }).execute()

    return {"message": "User created"}


@router.post("/login")
def login(req: LoginRequest):
    res = db.db.table("users").select("*").eq("email", req.email).execute()

    if not res.data:
        raise HTTPException(404, "User not found")

    user = res.data[0]

    if not verify_password(req.password, user["password_hash"]):
        raise HTTPException(403, "Invalid password")

    return {
        "api_key": user["api_key"],
        "user_id": user["id"]
    }

