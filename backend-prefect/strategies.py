"""TOTP (RFC 6238) desde cero + Strategy Pattern para el segundo factor."""
import base64
import hashlib
import hmac
import secrets
import struct
import time
from abc import ABC, abstractmethod

import db

PERIOD = 30
WINDOWS = (("C-1", -1), ("C", 0), ("C+1", 1))


def b32decode(secret: str) -> bytes:
    s = secret.replace(" ", "").upper()
    return base64.b32decode(s + "=" * (-len(s) % 8))


def hotp(key: bytes, counter: int) -> str:
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()  # 20 bytes
    offset = digest[19] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return f"{value % 1_000_000:06d}"


def new_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode()  # 160 bits, 32 chars sin padding


def new_backup_codes(n: int = 8) -> list[str]:
    return [secrets.token_hex(4) for _ in range(n)]


def hash_code(code: str) -> str:
    return hashlib.sha256(code.encode()).hexdigest()


class SecondFactorStrategy(ABC):
    @abstractmethod
    def verify(self, user: dict, code: str, logger) -> bool: ...


class TOTPStrategy(SecondFactorStrategy):
    def verify(self, user, code, logger):
        key = b32decode(user["totp_secret"])
        c = int(time.time()) // PERIOD
        for label, delta in WINDOWS:
            if hmac.compare_digest(hotp(key, c + delta), code):
                logger.info(f"TOTP match en ventana {label} (contador {c + delta}, actual {c})")
                if delta:
                    logger.warning(f"Reloj del celular {'atrasado' if delta < 0 else 'adelantado'} ~{PERIOD}s")
                return True
        logger.warning(f"TOTP sin match en C-1, C, C+1 (contador actual {c})")
        return False


class BackupCodeStrategy(SecondFactorStrategy):
    def verify(self, user, code, logger):
        h = hash_code(code)
        if h not in user["backup_codes"]:
            logger.warning("Código de respaldo inválido o ya consumido")
            return False
        remaining = [x for x in user["backup_codes"] if x != h]
        db.update_user(user["id"], backup_codes=remaining)  # un solo uso
        logger.info(f"Código de respaldo consumido; quedan {len(remaining)}")
        return True


STRATEGIES: dict[str, SecondFactorStrategy] = {"totp": TOTPStrategy(), "backup": BackupCodeStrategy()}


if __name__ == "__main__":
    # Vector de prueba RFC 6238 (SHA1, T=59s): 94287082 -> últimos 6 dígitos 287082
    key = b"12345678901234567890"
    assert hotp(key, 59 // 30) == "287082"
    assert hotp(key, 1111111109 // 30) == "081804"
    assert b32decode(base64.b32encode(key).decode().rstrip("=")) == key
    print("TOTP OK (RFC 6238)")
