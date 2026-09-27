"""
auth.py — API key based access control for PIIShield.

Adds a minimal but real authentication layer: every protected endpoint
requires a valid API key sent in the X-API-Key header. Keys are stored
hashed (never in plaintext) in the database, each tied to a named client
(e.g. "admin", "analyst"), and each request is logged.

This directly addresses the report's objective:
  "secure access control mechanisms to restrict unauthorized usage and
   protect sensitive operations"
"""

import hashlib
import os
import secrets
from datetime import datetime

from fastapi import Header, HTTPException, Depends
from sqlalchemy import Column, Integer, String, DateTime, Boolean
from sqlalchemy.orm import Session

from models import Base, get_db  # reuse the same declarative Base + db session as the rest of the app


class ApiKey(Base):
    __tablename__ = "api_keys"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)          # e.g. "admin", "analyst-1"
    key_hash = Column(String, nullable=False, unique=True, index=True)
    role = Column(String, default="analyst")        # "admin", "auditor", or "analyst"
    company = Column(String, nullable=True, index=True)  # which company this session/key belongs to
    active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_used_at = Column(DateTime, nullable=True)


def _hash_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Per-company user accounts (real login, replaces the old fake JS-only login)
# ---------------------------------------------------------------------------

def _hash_password(password: str) -> str:
    """Salted PBKDF2 hash — never store plaintext or a bare SHA-256 of a password."""
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100_000)
    return f"{salt}${dk.hex()}"


def _verify_password(password: str, stored: str) -> bool:
    try:
        salt, hash_hex = stored.split("$", 1)
    except ValueError:
        return False
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100_000)
    return secrets.compare_digest(dk.hex(), hash_hex)


def create_user(db: Session, username: str, password: str, company: str, role: str, security_question: str = "", security_answer: str = ""):
    """Registers a new user. Raises ValueError if the username is already taken."""
    from models import User  # local import avoids a circular import with models.py

    existing = db.query(User).filter(User.username == username).first()
    if existing:
        raise ValueError("That username is already registered.")

    user = User(
        username=username,
        password_hash=_hash_password(password),
        company=company,
        role=role,
    )
    if security_question:
        user.security_question = security_question
    if security_answer:
        import hashlib as _h, secrets as _s
        user.security_answer_hash = _h.pbkdf2_hmac("sha256", security_answer.strip().lower().encode(), username.encode(), 10_000).hex()
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def authenticate_user(db: Session, username: str, password: str):
    """Returns the User row if credentials are correct, else None."""
    from models import User

    user = db.query(User).filter(User.username == username).first()
    if not user or not _verify_password(password, user.password_hash):
        return None
    return user


def issue_session_token(db: Session, user) -> str:
    """
    Called right after a successful login. Creates a fresh ApiKey row acting
    as this session's token — tied to the user's company and role — and
    returns the raw token (shown once, same pattern as generate_api_key).
    """
    raw_key = f"pii_{secrets.token_urlsafe(32)}"
    entry = ApiKey(name=user.username, key_hash=_hash_key(raw_key), role=user.role, company=user.company)
    db.add(entry)
    db.commit()
    return raw_key


def generate_api_key(db: Session, name: str, role: str = "analyst") -> str:
    """
    Creates a new API key, stores only its hash, and returns the RAW key once.
    The raw key is never stored or retrievable again — same principle as
    GitHub/Stripe-style API keys.
    """
    raw_key = f"pii_{secrets.token_urlsafe(32)}"
    entry = ApiKey(name=name, key_hash=_hash_key(raw_key), role=role)
    db.add(entry)
    db.commit()
    return raw_key


def require_api_key(
    x_api_key: str = Header(None, alias="X-API-Key"),
    db: Session = Depends(get_db),
) -> ApiKey:
    """
    FastAPI dependency — attach with Depends(require_api_key) on any
    endpoint that should require authentication.
    """
    if not x_api_key:
        raise HTTPException(status_code=401, detail="Missing X-API-Key header")

    key_hash = _hash_key(x_api_key)
    entry = db.query(ApiKey).filter(ApiKey.key_hash == key_hash, ApiKey.active == True).first()

    if not entry:
        raise HTTPException(status_code=401, detail="Invalid or inactive API key")

    entry.last_used_at = datetime.utcnow()
    db.commit()
    return entry


def require_admin(current_key: ApiKey) -> ApiKey:
    """Use after require_api_key for endpoints that need admin role specifically."""
    if current_key.role != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")
    return current_key
