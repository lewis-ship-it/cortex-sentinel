# core/security.py
# ──────────────────────────────────────────────────────────────────────────────
# Security utilities — SQLite edition.
# APIKeyManager and TokenManager are now backed by the kv_store table via the
# _RedisShim so they continue to work without any real Redis connection.
# PasswordManager (bcrypt) is unchanged.
# ──────────────────────────────────────────────────────────────────────────────

import bcrypt
import secrets
from typing import Optional
from datetime import datetime, timedelta

from task_queue.redis_client import r   # _RedisShim


# ─────────────────────────────────────────────────────────────────────────────
# PASSWORD MANAGER  (unchanged — bcrypt only, no Redis dependency)
# ─────────────────────────────────────────────────────────────────────────────

class PasswordManager:
    BCRYPT_COST = 12

    @staticmethod
    def hash_password(password: str) -> str:
        if not password or not isinstance(password, str):
            raise ValueError("Password must be a non-empty string")
        salt   = bcrypt.gensalt(rounds=PasswordManager.BCRYPT_COST)
        hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
        return hashed.decode("utf-8")

    @staticmethod
    def verify_password(password: str, hashed: str) -> bool:
        try:
            return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
        except (ValueError, TypeError):
            return False

    @staticmethod
    def needs_rehash(hashed: str) -> bool:
        try:
            return int(hashed.split("$")[2]) < PasswordManager.BCRYPT_COST
        except (ValueError, IndexError):
            return True


# ─────────────────────────────────────────────────────────────────────────────
# API KEY MANAGER  (now uses SQLite kv_store via _RedisShim)
# ─────────────────────────────────────────────────────────────────────────────

class APIKeyManager:
    KEY_PREFIX = "api_key:"
    KEY_INDEX  = "api_keys:index"

    @staticmethod
    def generate_key(prefix: str = "sk") -> str:
        return f"{prefix}_{secrets.token_hex(32)}"

    def create_key(self, user_id: str, name: str, expires_in_days: Optional[int] = 365) -> str:
        api_key  = self.generate_key()
        key_hash = PasswordManager.hash_password(api_key)

        metadata = {
            "user_id":    user_id,
            "name":       name,
            "created_at": datetime.utcnow().isoformat(),
            "last_used":  "",
            "hash":       key_hash,
        }
        if expires_in_days:
            metadata["expires_at"] = (
                datetime.utcnow() + timedelta(days=expires_in_days)
            ).isoformat()

        key_id    = f"key_{secrets.token_hex(4)}"
        redis_key = f"{self.KEY_PREFIX}{key_id}"
        r.hset(redis_key, mapping=metadata)
        r.sadd(self.KEY_INDEX, key_id)

        return api_key

    def validate_key(self, api_key: str, user_id: str) -> bool:
        for key_id in r.smembers(self.KEY_INDEX):
            redis_key = f"{self.KEY_PREFIX}{key_id}"
            meta      = r.hgetall(redis_key)
            if not meta or meta.get("user_id") != user_id:
                continue
            if "expires_at" in meta and meta["expires_at"]:
                if datetime.utcnow() > datetime.fromisoformat(meta["expires_at"]):
                    r.delete(redis_key)
                    continue
            if PasswordManager.verify_password(api_key, meta.get("hash", "")):
                r.hset(redis_key, field="last_used", value=datetime.utcnow().isoformat())
                return True
        return False

    def revoke_key(self, user_id: str, key_name: str) -> bool:
        for key_id in r.smembers(self.KEY_INDEX):
            redis_key = f"{self.KEY_PREFIX}{key_id}"
            meta      = r.hgetall(redis_key)
            if meta.get("user_id") == user_id and meta.get("name") == key_name:
                r.delete(redis_key)
                r.srem(self.KEY_INDEX, key_id)
                return True
        return False


# ─────────────────────────────────────────────────────────────────────────────
# TOKEN MANAGER  (session tokens stored in SQLite kv_store)
# ─────────────────────────────────────────────────────────────────────────────

class TokenManager:
    TOKEN_PREFIX = "token:"

    @staticmethod
    def generate_token(prefix: str = "sess") -> str:
        return f"{prefix}_{secrets.token_hex(32)}"

    def create_session_token(self, user_id: str, expires_in_seconds: int = 3600) -> str:
        token     = self.generate_token("sess")
        redis_key = f"{self.TOKEN_PREFIX}{token}"
        r.hset(redis_key, mapping={
            "user_id":    user_id,
            "created_at": datetime.utcnow().isoformat(),
        })
        # Store expiry in metadata (no native TTL in SQLite)
        r.hset(redis_key, field="expires_at",
               value=(datetime.utcnow() + timedelta(seconds=expires_in_seconds)).isoformat())
        return token

    def validate_token(self, token: str) -> Optional[dict]:
        redis_key = f"{self.TOKEN_PREFIX}{token}"
        data      = r.hgetall(redis_key)
        if not data:
            return None
        # Check expiry
        expires_at = data.get("expires_at", "")
        if expires_at and datetime.utcnow() > datetime.fromisoformat(expires_at):
            r.delete(redis_key)
            return None
        return data

    def revoke_token(self, token: str) -> bool:
        return bool(r.delete(f"{self.TOKEN_PREFIX}{token}"))


# ─────────────────────────────────────────────────────────────────────────────
# SINGLETONS
# ─────────────────────────────────────────────────────────────────────────────

_api_key_manager: Optional[APIKeyManager] = None
_token_manager:   Optional[TokenManager]  = None


def get_api_key_manager() -> APIKeyManager:
    global _api_key_manager
    if _api_key_manager is None:
        _api_key_manager = APIKeyManager()
    return _api_key_manager


def get_token_manager() -> TokenManager:
    global _token_manager
    if _token_manager is None:
        _token_manager = TokenManager()
    return _token_manager