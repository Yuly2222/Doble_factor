# 2FA TOTP desde cero + Step-Up Auth + Observabilidad con Prefect

```
/mobile-authenticator   App React Native (Expo) que calcula TOTP sin conexión (RFC 6238 hecho a mano)
/backend-prefect        FastAPI + Prefect + Supabase, incluye la web de login (static/index.html)
```

## Arquitectura

| Patrón | Dónde |
|---|---|
| **Step-Up Auth** | `POST /auth/login` → `pre_auth_token` (scope `pre_auth`, 5 min, no abre recursos). `POST /auth/verify-2fa` → `access_token` con `mfa_verified: true`. `GET /api/boveda-secreta` exige este último. (`security.py`, `main.py`) |
| **Process Manager / Estados** | `DISABLED → PENDING_VERIFICATION` al generar el QR; `PENDING_VERIFICATION → ACTIVE` solo con el primer código válido. Con 2FA `ACTIVE` no se puede re-aprovisionar. (`flows.py`) |
| **Strategy** | `SecondFactorStrategy` con `TOTPStrategy` (ventanas C-1, C, C+1) y `BackupCodeStrategy` (8 códigos de un solo uso, guardados como SHA-256). (`strategies.py`) |
| **Anti-Replay** | Caché en memoria `(user_id, código)` con TTL de 90 s. (`flows.py`) |

Flows de Prefect: `login-flow`, `provision-2fa-flow` y `verify-2fa-flow`. Este último tiene las 4 tareas de la guía:
`validate_pre_auth_state → check_anti_replay_cache → execute_mfa_strategy → issue_elevated_session`.
Contraseñas y tokens se pasan como `SecretStr`, así que la UI de Prefect los muestra enmascarados. Las tareas no usan caché ni guardan resultados.

## 1. Supabase

1. Crea un proyecto en https://supabase.com.
2. En el **SQL Editor**, ejecuta `backend-prefect/schema.sql`.
3. En **Project Settings → API**, copia la `Project URL` y la clave `service_role`.

## 2. Backend + Prefect (Windows)

Comandos para **CMD**. En PowerShell, cambia `.venv\Scripts\activate.bat` por `.\.venv\Scripts\Activate.ps1`. Tras activar, el prompt debe empezar con `(.venv)`.

```powershell
cd backend-prefect
py -m venv .venv
.venv\Scripts\activate.bat
pip install -r requirements.txt
copy .env.example .env
```

Luego abre `.env` y rellena `SUPABASE_URL`, `SUPABASE_KEY` y `JWT_SECRET`.

Terminal 1, servidor de Prefect (UI en http://127.0.0.1:4200):

```bat
cd backend-prefect
.venv\Scripts\activate.bat
prefect server start
```

Terminal 2, API + web:

```bat
cd backend-prefect
.venv\Scripts\activate.bat
uvicorn main:app --host 0.0.0.0 --port 8000
```

Abre http://localhost:8000 para la web de login y http://localhost:8000/docs para Swagger.

Autoprueba del algoritmo TOTP con los vectores de la RFC 6238: `python strategies.py`

## 3. App móvil (Expo)

```bat
cd mobile-authenticator
npm install
npx expo install --fix
npm test           # vectores RFC 6238 / RFC 2202
npx expo start     # escanea el QR de Expo con Expo Go, o pulsa "a" para el emulador Android
```

La app guarda la semilla en `expo-secure-store` y no hace ninguna llamada de red, así que funciona en modo avión.
En el emulador (sin cámara), pega la semilla Base32 que muestra la web.

## Guion de la demo

1. **Paridad**: en la web, regístrate → inicia sesión → **Generar QR**. Escanea el QR con esta app y con Google/Microsoft Authenticator: las dos muestran el mismo código.
2. **Modo avión**: activa el modo avión, espera a que cambie la ventana de 30 s, verifica el código (el estado pasa a `ACTIVE`) → **GET /api/boveda-secreta**.
3. **Replay**: vuelve a pulsar **Verificar** con el mismo código → HTTP 409. En Prefect, `verify-2fa-flow` aparece **Failed** en `check_anti_replay_cache`.
4. **Desfase de reloj / respaldo**: el log de `execute_mfa_strategy` indica la ventana (`C-1`, `C` o `C+1`) donde coincidió el código. También puedes elegir *Código de respaldo* y usar uno de los 8 códigos.

> Para volver a iniciar sesión, primero pulsa *Iniciar sesión* (un nuevo `pre_auth_token`) y luego verifica con un código nuevo.

## Límites (PoC)

- La caché anti-replay vive en el proceso: ejecuta uvicorn con un solo worker. Con varios workers haría falta Redis (`SET NX EX 90`).
- Sin rate limiting en `/auth/verify-2fa`. Para producción, conviene bloquear tras N intentos fallidos.
