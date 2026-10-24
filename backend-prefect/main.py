from pathlib import Path
from typing import Literal

from dotenv import load_dotenv

load_dotenv()

import qrcode
import qrcode.image.svg
from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field, SecretStr

from flows import ReplayAttackDetected, login_flow, provision_2fa_flow, register_user, verify_2fa_flow
from security import AuthError, decode_token

app = FastAPI(title="2FA TOTP Step-Up + Prefect")


class Credentials(BaseModel):
    username: str = Field(min_length=3, max_length=254, pattern=r"^[A-Za-z0-9_.+@-]+$")  # usuario o correo
    password: SecretStr = Field(min_length=6, max_length=128)


class PreAuth(BaseModel):
    pre_auth_token: SecretStr


class Verify(PreAuth):
    code: str = Field(min_length=6, max_length=12)
    method: Literal["totp", "backup"] = "totp"


def run(fn, *args):
    try:
        return fn(*args)
    except ReplayAttackDetected as e:
        raise HTTPException(409, f"ReplayAttackDetected: {e}")
    except AuthError as e:
        raise HTTPException(401, str(e))


@app.get("/")
def index():
    return FileResponse(Path(__file__).parent / "static" / "index.html")


@app.post("/auth/register", status_code=201)
def register(body: Credentials):
    user = run(register_user, body.username, body.password.get_secret_value())
    return {"id": user["id"], "username": user["username"]}


@app.post("/auth/login")
def login(body: Credentials):
    return run(login_flow, body.username, body.password)


@app.post("/auth/2fa/setup")
def setup_2fa(body: PreAuth):
    result = run(provision_2fa_flow, body.pre_auth_token)
    svg = qrcode.make(result["otpauth_uri"], image_factory=qrcode.image.svg.SvgPathImage)
    return {**result, "qr_svg": svg.to_string(encoding="unicode"), "mfa_status": "PENDING_VERIFICATION"}


@app.post("/auth/verify-2fa")
def verify_2fa(body: Verify):
    code = body.code.replace(" ", "").replace("-", "").lower()
    return {"access_token": run(verify_2fa_flow, body.pre_auth_token, code, body.method), "mfa_verified": True}


def require_mfa(creds: HTTPAuthorizationCredentials = Depends(HTTPBearer())) -> dict:
    try:
        claims = decode_token(creds.credentials, "access")
    except AuthError as e:
        raise HTTPException(401, str(e))
    if not claims.get("mfa_verified"):
        raise HTTPException(403, "Se requiere mfa_verified=true")
    return claims


@app.get("/api/boveda-secreta")
def boveda(claims: dict = Depends(require_mfa)):
    return {"mensaje": f"Bienvenid@ a la bóveda, {claims['username']}", "tesoro": "🗝️ 42", "claims": claims}
