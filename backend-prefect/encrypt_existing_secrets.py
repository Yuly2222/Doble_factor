"""Migración única: cifra las semillas TOTP que quedaron en texto plano en Supabase.

Uso (desde backend-prefect, con el .env completo):  python encrypt_existing_secrets.py
Es idempotente: las filas ya cifradas ("v1:...") se saltan.
"""
from dotenv import load_dotenv

load_dotenv()

import db

rows = db.client().table("users").select("id, username, totp_secret").execute().data
pending = [r for r in rows if r["totp_secret"] and not r["totp_secret"].startswith(db.PREFIX)]
for r in pending:
    encrypted = db.encrypt_secret(r["id"], r["totp_secret"])
    assert db.decrypt_secret(r["id"], encrypted) == r["totp_secret"]
    db.client().table("users").update({"totp_secret": encrypted}).eq("id", r["id"]).execute()
    print(f"Cifrada: {r['username']}")
print(f"{len(pending)} semilla(s) cifrada(s); {len(rows) - len(pending)} fila(s) sin cambios.")
