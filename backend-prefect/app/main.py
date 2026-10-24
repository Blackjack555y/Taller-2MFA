import re

import segno
from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field, SecretStr

from . import security
from .config import BASE_DIR
from .flows import (AuthError, MFAStateError, mfa_activation_flow,
                    mfa_provisioning_flow, password_login_flow, verify_2fa_flow)
from .mfa_state import InvalidTransition
from .replay_cache import ReplayAttackDetected
from .repository import repository

app = FastAPI(title="Taller 2MFA - Step-Up Auth con Prefect")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
bearer = HTTPBearer()


class Credentials(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    password: SecretStr = Field(min_length=6, max_length=128)


class PreAuthBody(BaseModel):
    pre_auth_token: SecretStr


class CodeBody(PreAuthBody):
    code: str
    method: str = Field(default="totp", pattern="^(totp|backup)$")


def run_flow(fn, *args, **kwargs):
    """Ejecuta un flow de Prefect y traduce sus excepciones a HTTP."""
    try:
        return fn(*args, **kwargs)
    except ReplayAttackDetected as exc:
        raise HTTPException(409, f"ReplayAttackDetected: {exc}")
    except (MFAStateError, InvalidTransition) as exc:
        raise HTTPException(409, str(exc))
    except AuthError as exc:
        raise HTTPException(401, str(exc))


def normalize_code(body: CodeBody) -> str:
    code = re.sub(r"[\s-]", "", body.code)
    expected = r"\d{6}" if body.method == "totp" else r"\d{8}"
    if not re.fullmatch(expected, code):
        raise HTTPException(422, f"Formato de código inválido para el método '{body.method}'")
    return code


@app.get("/", include_in_schema=False)
def web_app():
    return FileResponse(BASE_DIR / "web" / "index.html")


@app.get("/health")
def health():
    return {"status": "ok", "database": repository.name}


@app.post("/auth/register", status_code=201)
def register(body: Credentials):
    if repository.get_by_username(body.username):
        raise HTTPException(409, "El usuario ya existe")
    user = repository.create(body.username, security.hash_password(body.password.get_secret_value()))
    return {"id": user.id, "username": user.username, "mfa_state": user.mfa_state}


@app.post("/auth/login")
def login(body: Credentials):
    """Paso 1 (Step-Up): solo entrega un pre_auth_token restringido."""
    return run_flow(password_login_flow, body.username, body.password)


@app.post("/auth/2fa/setup")
def setup_2fa(body: PreAuthBody):
    """DISABLED/PENDING -> PENDING_VERIFICATION. Devuelve el secreto y el QR."""
    result = run_flow(mfa_provisioning_flow, body.pre_auth_token)
    qr = segno.make(result["otpauth_uri"], error="m")
    result["qr_svg_data_uri"] = qr.svg_data_uri(scale=6, border=2)
    result["mfa_state"] = "PENDING_VERIFICATION"
    return result


@app.post("/auth/2fa/activate")
def activate_2fa(body: CodeBody):
    """Primer código válido: PENDING_VERIFICATION -> ACTIVE (+ códigos de respaldo)."""
    body.method = "totp"
    return run_flow(mfa_activation_flow, body.pre_auth_token, normalize_code(body))


@app.post("/auth/verify-2fa")
def verify_2fa(body: CodeBody):
    """Paso 2 (Step-Up): canjea pre_auth_token + código por el access_token final."""
    return run_flow(verify_2fa_flow, body.pre_auth_token, normalize_code(body), body.method)


def require_mfa_session(cred: HTTPAuthorizationCredentials = Depends(bearer)) -> dict:
    try:
        claims = security.decode_token(cred.credentials, security.SCOPE_ACCESS)
    except security.InvalidToken as exc:
        raise HTTPException(401, str(exc))
    if claims.get("mfa_verified") is not True:
        raise HTTPException(403, "Se requiere sesión con mfa_verified=true")
    return claims


@app.get("/api/boveda-secreta")
def boveda_secreta(claims: dict = Depends(require_mfa_session)):
    return {
        "mensaje": f"Bienvenido a la bóveda, {claims['username']}",
        "secreto": "La respuesta es 42",
        "mfa_verified": claims["mfa_verified"],
        "metodo_segundo_factor": claims["amr"][-1],
    }
