"""Hash de contraseñas (PBKDF2) y tokens JWT (pre_auth vs access)."""
import hashlib
import hmac
import os
import secrets
import time

import jwt

JWT_SECRET = os.environ["JWT_SECRET"]
PRE_AUTH_TTL = 5 * 60
ACCESS_TTL = 15 * 60


class AuthError(Exception):
    pass


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 200_000).hex()
    return f"{salt}${h}"


def verify_password(password: str, stored: str) -> bool:
    salt, h = stored.split("$")
    return hmac.compare_digest(hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 200_000).hex(), h)


def issue_token(user_id: str, scope: str, ttl: int, **claims) -> str:
    now = int(time.time())
    return jwt.encode({"sub": user_id, "scope": scope, "iat": now, "exp": now + ttl, **claims}, JWT_SECRET, "HS256")


def decode_token(token: str, scope: str) -> dict:
    try:
        claims = jwt.decode(token, JWT_SECRET, ["HS256"])
    except jwt.PyJWTError as e:
        raise AuthError(f"Token inválido: {e}")
    if claims.get("scope") != scope:
        raise AuthError(f"Se requiere un token con scope '{scope}'")
    return claims
