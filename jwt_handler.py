"""
JWT creation and verification.

IMPORTANT: In a real deployment, SECRET_KEY must come from an environment
variable / secrets manager — never hardcoded and never committed to git.
For this student project, generate your own key once with:
    python -c "import secrets; print(secrets.token_hex(32))"
and store it in a .env file (add .env to .gitignore).
"""

import os
from datetime import datetime, timedelta, timezone
from jose import jwt, JWTError

SECRET_KEY = os.getenv("NETSENTRY_SECRET_KEY", "CHANGE_ME_DEV_ONLY_NOT_FOR_PRODUCTION")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60


def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_access_token(token: str) -> dict | None:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None
