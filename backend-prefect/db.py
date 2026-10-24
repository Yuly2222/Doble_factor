"""Acceso a la tabla `users` en Supabase (ver schema.sql)."""
import os
from functools import cache

from supabase import create_client


@cache
def client():
    return create_client(os.environ["SUPABASE_URL"], os.environ["SUPABASE_KEY"])


def _one(rows):
    return rows.data[0] if rows.data else None


def get_user(username: str):
    return _one(client().table("users").select("*").eq("username", username).limit(1).execute())


def get_user_by_id(user_id: str):
    return _one(client().table("users").select("*").eq("id", user_id).limit(1).execute())


def create_user(username: str, password_hash: str):
    return _one(client().table("users").insert({"username": username, "password_hash": password_hash}).execute())


def update_user(user_id: str, **fields):
    return _one(client().table("users").update(fields).eq("id", user_id).execute())
