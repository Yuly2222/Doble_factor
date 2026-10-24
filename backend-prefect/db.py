"""Acceso a la tabla `users` en Supabase (ver schema.sql).

`totp_secret` se cifra en reposo con AES-256-GCM: se cifra al escribir y se descifra al leer,
así ninguna otra parte del código puede guardarlo en claro por accidente.
Formato en BD: "v1:" + base64(nonce de 12 bytes + ciphertext + tag). El id del usuario va como
dato asociado (AAD): una semilla cifrada copiada a otra fila no se puede descifrar.
"""
import base64
import os
from functools import cache

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from supabase import create_client

PREFIX = "v1:"


@cache
def client():
    return create_client(os.environ["SUPABASE_URL"], os.environ["SUPABASE_KEY"])


@cache
def _aes() -> AESGCM:
    key = base64.b64decode(os.environ["TOTP_ENC_KEY"])
    if len(key) != 32:
        raise RuntimeError("TOTP_ENC_KEY debe ser 32 bytes en base64 (AES-256). Ver .env.example")
    return AESGCM(key)


def encrypt_secret(user_id: str, secret: str) -> str:
    nonce = os.urandom(12)
    return PREFIX + base64.b64encode(nonce + _aes().encrypt(nonce, secret.encode(), user_id.encode())).decode()


def decrypt_secret(user_id: str, stored: str) -> str:
    if not stored.startswith(PREFIX):
        raise RuntimeError(f"totp_secret del usuario {user_id} no está cifrado. Ejecuta encrypt_existing_secrets.py")
    raw = base64.b64decode(stored[len(PREFIX):])
    try:
        return _aes().decrypt(raw[:12], raw[12:], user_id.encode()).decode()
    except InvalidTag:
        raise RuntimeError(f"No se pudo descifrar totp_secret del usuario {user_id}: clave incorrecta o dato alterado")


def _one(rows):
    user = rows.data[0] if rows.data else None
    if user and user.get("totp_secret"):
        user["totp_secret"] = decrypt_secret(user["id"], user["totp_secret"])
    return user


def get_user(username: str):
    return _one(client().table("users").select("*").eq("username", username).limit(1).execute())


def get_user_by_id(user_id: str):
    return _one(client().table("users").select("*").eq("id", user_id).limit(1).execute())


def create_user(username: str, password_hash: str):
    return _one(client().table("users").insert({"username": username, "password_hash": password_hash}).execute())


def update_user(user_id: str, **fields):
    if fields.get("totp_secret"):
        fields["totp_secret"] = encrypt_secret(user_id, fields["totp_secret"])
    return _one(client().table("users").update(fields).eq("id", user_id).execute())
