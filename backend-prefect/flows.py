"""Flujos Prefect: login (pre-auth), aprovisionamiento 2FA y verificación Step-Up."""
import time
from functools import partial
from urllib.parse import quote

from prefect import flow, get_run_logger, task
from prefect.cache_policies import NO_CACHE
from pydantic import SecretStr

import db
from security import ACCESS_TTL, PRE_AUTH_TTL, AuthError, decode_token, hash_password, issue_token, verify_password
from strategies import STRATEGIES, hash_code, new_backup_codes, new_secret

ISSUER = "PatronesLab"
REPLAY_TTL = 90

# Estados del Process Manager de aprovisionamiento
DISABLED, PENDING, ACTIVE = "DISABLED", "PENDING_VERIFICATION", "ACTIVE"

# Sin caché ni persistencia: los resultados contienen secretos/tokens.
secure_task = partial(task, cache_policy=NO_CACHE, persist_result=False)
secure_flow = partial(flow, persist_result=False)

# ponytail: caché en memoria de un solo proceso; usar Redis con SET NX EX si hay varios workers.
_used_codes: dict[tuple[str, str], float] = {}


class ReplayAttackDetected(Exception):
    pass


# ---------- Login (factor 1) ----------

@secure_task
def verify_credentials(username: str, password: SecretStr) -> dict:
    user = db.get_user(username)
    if not user or not verify_password(password.get_secret_value(), user["password_hash"]):
        raise AuthError("Usuario o contraseña incorrectos")
    get_run_logger().info(f"Credenciales OK para '{username}' (estado 2FA: {user['mfa_status']})")
    return user


@secure_task
def issue_pre_auth_token(user: dict) -> str:
    return issue_token(user["id"], "pre_auth", PRE_AUTH_TTL)


@secure_flow(name="login-flow")
def login_flow(username: str, password: SecretStr) -> dict:
    user = verify_credentials(username, password)
    return {"pre_auth_token": issue_pre_auth_token(user), "mfa_status": user["mfa_status"]}


def register_user(username: str, password: str) -> dict:
    if db.get_user(username):
        raise AuthError("El usuario ya existe")
    return db.create_user(username, hash_password(password))


# ---------- Verificación Step-Up (factor 2) ----------

@secure_task
def validate_pre_auth_state(pre_auth_token: SecretStr) -> dict:
    claims = decode_token(pre_auth_token.get_secret_value(), "pre_auth")
    user = db.get_user_by_id(claims["sub"])
    if not user:
        raise AuthError("Usuario no existe")
    get_run_logger().info(f"pre_auth_token válido para '{user['username']}' (estado 2FA: {user['mfa_status']})")
    return user


@secure_task
def check_anti_replay_cache(user_id: str, code: str) -> None:
    now = time.time()
    for k in [k for k, t in _used_codes.items() if now - t > REPLAY_TTL]:
        del _used_codes[k]
    if (user_id, code) in _used_codes:
        raise ReplayAttackDetected(
            f"Código ya usado hace {now - _used_codes[(user_id, code)]:.0f}s por este usuario (ventana anti-replay {REPLAY_TTL}s)")
    get_run_logger().info("Código no usado en los últimos 90s")


@secure_task
def execute_mfa_strategy(user: dict, code: str, method: str) -> None:
    logger = get_run_logger()
    if user["mfa_status"] == DISABLED:
        raise AuthError("El usuario no ha configurado 2FA")
    if method == "backup" and user["mfa_status"] != ACTIVE:
        raise AuthError("Los códigos de respaldo solo sirven con 2FA ACTIVE")
    strategy = STRATEGIES[method]
    logger.info(f"Estrategia seleccionada: {type(strategy).__name__}")
    if not strategy.verify(user, code, logger):
        raise AuthError("Código de segundo factor inválido")


@secure_task
def issue_elevated_session(user: dict, code: str) -> str:
    logger = get_run_logger()
    _used_codes[(user["id"], code)] = time.time()
    if user["mfa_status"] == PENDING:
        db.update_user(user["id"], mfa_status=ACTIVE)
        logger.info(f"Transición de estado: {PENDING} -> {ACTIVE}")
    logger.info("Emitiendo access_token con mfa_verified=true")
    return issue_token(user["id"], "access", ACCESS_TTL, username=user["username"], mfa_verified=True)


@secure_flow(name="verify-2fa-flow")
def verify_2fa_flow(pre_auth_token: SecretStr, code: str, method: str = "totp") -> str:
    user = validate_pre_auth_state(pre_auth_token)
    check_anti_replay_cache(user["id"], code)
    execute_mfa_strategy(user, code, method)
    return issue_elevated_session(user, code)


# ---------- Aprovisionamiento (Process Manager) ----------

@secure_task
def create_pending_configuration(user: dict) -> dict:
    if user["mfa_status"] == ACTIVE:
        raise AuthError("2FA ya está ACTIVE; no se puede re-aprovisionar")
    previous, secret, backup = user["mfa_status"], new_secret(), new_backup_codes()
    db.update_user(user["id"], totp_secret=secret, mfa_status=PENDING, backup_codes=[hash_code(c) for c in backup])
    get_run_logger().info(f"Transición de estado: {previous} -> {PENDING}")
    return {"secret": secret, "backup_codes": backup}


@secure_task
def build_provisioning_uri(username: str, secret: str) -> str:
    label = quote(f"{ISSUER}:{username}")
    return f"otpauth://totp/{label}?secret={secret}&issuer={quote(ISSUER)}&algorithm=SHA1&digits=6&period=30"


@secure_flow(name="provision-2fa-flow")
def provision_2fa_flow(pre_auth_token: SecretStr) -> dict:
    user = validate_pre_auth_state(pre_auth_token)
    config = create_pending_configuration(user)
    return {**config, "otpauth_uri": build_provisioning_uri(user["username"], config["secret"])}
