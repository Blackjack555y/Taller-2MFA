"""Flows y tasks de Prefect que orquestan el pipeline de autenticación."""
import time

from prefect import flow, get_run_logger, task
from prefect.cache_policies import NO_CACHE
from pydantic import SecretStr

from . import security, totp
from .config import TOTP_PERIOD
from .mfa_state import MFAState, transition
from .replay_cache import ReplayAttackDetected, replay_cache
from .repository import User, repository
from .strategies import get_strategy


class AuthError(Exception):
    """Credenciales, token o código inválidos (HTTP 401)."""


class MFAStateError(Exception):
    """La operación no aplica al estado 2FA actual del usuario (HTTP 409)."""

# Contraseñas y tokens viajan como SecretStr: Prefect guarda los parámetros de
# cada flow run y los muestra en la UI; así aparecen como '**********'.


# ---------------------------------------------------------------- login ---

@task(name="verify_password_credentials", cache_policy=NO_CACHE)
def verify_password_credentials(username: str, password: SecretStr) -> User:
    logger = get_run_logger()
    user = repository.get_by_username(username)
    if user is None or not security.verify_password(password.get_secret_value(), user.password_hash):
        logger.warning(f"Credenciales inválidas para '{username}'")
        raise AuthError("Usuario o contraseña incorrectos")
    logger.info(f"Contraseña correcta para '{username}' (estado 2FA: {user.mfa_state})")
    return user


@task(name="issue_pre_auth_token", cache_policy=NO_CACHE)
def issue_pre_auth_token(user: User) -> str:
    get_run_logger().info("Emitiendo pre_auth_token (scope=pre_auth, mfa_verified=false)")
    return security.issue_pre_auth_token(user.id, user.username)


@flow(name="password-login-flow")
def password_login_flow(username: str, password: SecretStr) -> dict:
    user = verify_password_credentials(username, password)
    token = issue_pre_auth_token(user)
    return {"pre_auth_token": token, "mfa_state": user.mfa_state}


# ---------------------------------------------------- tasks de verify-2fa ---

@task(name="validate_pre_auth_state", cache_policy=NO_CACHE)
def validate_pre_auth_state(pre_auth_token: SecretStr, required_state: MFAState) -> User:
    logger = get_run_logger()
    try:
        claims = security.decode_token(pre_auth_token.get_secret_value(), security.SCOPE_PRE_AUTH)
    except security.InvalidToken as exc:
        logger.error(str(exc))
        raise AuthError(str(exc)) from exc
    user = repository.get_by_id(claims["sub"])
    if user is None:
        raise AuthError("El usuario del token ya no existe")
    if user.mfa_state != required_state.value:
        msg = f"Estado 2FA es {user.mfa_state}, se requiere {required_state.value}"
        logger.error(msg)
        raise MFAStateError(msg)
    remaining = claims["exp"] - int(time.time())
    logger.info(f"pre_auth_token válido para '{user.username}' (expira en {remaining}s)")
    return user


@task(name="check_anti_replay_cache", cache_policy=NO_CACHE)
def check_anti_replay_cache(user: User, code: str) -> None:
    logger = get_run_logger()
    used_at = replay_cache.used_at(user.id, code)
    if used_at is not None:
        ago = time.time() - used_at
        msg = (f"REPLAY ATTACK: el código {code} ya fue usado por '{user.username}' "
               f"hace {ago:.1f}s (ventana de bloqueo {replay_cache.ttl}s)")
        logger.error(msg)
        raise ReplayAttackDetected(msg)
    logger.info(f"Código no visto antes para '{user.username}' en los últimos {replay_cache.ttl}s")


@task(name="execute_mfa_strategy", cache_policy=NO_CACHE)
def execute_mfa_strategy(user: User, code: str, method: str) -> dict:
    logger = get_run_logger()
    strategy = get_strategy(method)
    logger.info(f"Estrategia seleccionada: {type(strategy).__name__}")
    if method == "totp":
        step = totp.time_step()
        seconds_left = TOTP_PERIOD - int(time.time()) % TOTP_PERIOD
        logger.info(f"Ventana de tiempo actual C={step} (quedan {seconds_left}s). "
                    f"Evaluando C-1={step - 1}, C={step}, C+1={step + 1}")
    result = strategy.verify(user, code)
    if not result.valid:
        logger.error(result.detail)
        raise AuthError(result.detail)
    logger.info(result.detail)
    return {"method": result.method, "window": result.window,
            "consumed_backup_hash": result.consumed_backup_hash}


@task(name="issue_elevated_session", cache_policy=NO_CACHE)
def issue_elevated_session(user: User, code: str, strategy_result: dict) -> str:
    logger = get_run_logger()
    replay_cache.mark_used(user.id, code)
    logger.info(f"Código marcado como usado en la caché anti-replay para '{user.username}'")
    if strategy_result["consumed_backup_hash"]:
        user.backup_code_hashes.remove(strategy_result["consumed_backup_hash"])
        repository.update_mfa(user)
        logger.info(f"Código de respaldo consumido; quedan {len(user.backup_code_hashes)}")
    logger.info("Emitiendo access_token con mfa_verified=true")
    return security.issue_access_token(user.id, user.username, strategy_result["method"])


@flow(name="verify-2fa-flow")
def verify_2fa_flow(pre_auth_token: SecretStr, code: str, method: str = "totp") -> dict:
    user = validate_pre_auth_state(pre_auth_token, MFAState.ACTIVE)
    check_anti_replay_cache(user, code)
    result = execute_mfa_strategy(user, code, method)
    access_token = issue_elevated_session(user, code, result)
    return {"access_token": access_token, "method": result["method"], "window": result["window"]}


# --------------------------------------------------------- aprovisionamiento ---

@task(name="validate_pre_auth_for_setup", cache_policy=NO_CACHE)
def validate_pre_auth_for_setup(pre_auth_token: SecretStr) -> User:
    try:
        claims = security.decode_token(pre_auth_token.get_secret_value(), security.SCOPE_PRE_AUTH)
    except security.InvalidToken as exc:
        raise AuthError(str(exc)) from exc
    user = repository.get_by_id(claims["sub"])
    if user is None:
        raise AuthError("El usuario del token ya no existe")
    if user.mfa_state == MFAState.ACTIVE.value:
        raise MFAStateError("El 2FA ya está ACTIVE; no se puede regenerar el secreto")
    return user


@task(name="generate_totp_secret", cache_policy=NO_CACHE)
def generate_totp_secret(user: User) -> dict:
    logger = get_run_logger()
    previous = user.mfa_state
    user.mfa_state = transition(user.mfa_state, MFAState.PENDING_VERIFICATION).value
    user.totp_secret = totp.generate_secret()
    user.backup_code_hashes = []
    repository.update_mfa(user)
    logger.info(f"Estado 2FA de '{user.username}': {previous} -> {user.mfa_state}")
    return {"secret": user.totp_secret,
            "otpauth_uri": totp.provisioning_uri(user.totp_secret, user.username)}


@flow(name="mfa-provisioning-flow")
def mfa_provisioning_flow(pre_auth_token: SecretStr) -> dict:
    user = validate_pre_auth_for_setup(pre_auth_token)
    return generate_totp_secret(user)


@task(name="activate_mfa_state", cache_policy=NO_CACHE)
def activate_mfa_state(user: User) -> list[str]:
    logger = get_run_logger()
    user.mfa_state = transition(user.mfa_state, MFAState.ACTIVE).value
    codes = security.generate_backup_codes()
    user.backup_code_hashes = [security.hash_backup_code(c) for c in codes]
    repository.update_mfa(user)
    logger.info(f"Estado 2FA de '{user.username}': PENDING_VERIFICATION -> ACTIVE "
                f"({len(codes)} códigos de respaldo generados)")
    return codes


@flow(name="mfa-activation-flow")
def mfa_activation_flow(pre_auth_token: SecretStr, code: str) -> dict:
    """Primer código válido desde la app: PENDING_VERIFICATION -> ACTIVE."""
    user = validate_pre_auth_state(pre_auth_token, MFAState.PENDING_VERIFICATION)
    check_anti_replay_cache(user, code)
    result = execute_mfa_strategy(user, code, "totp")
    backup_codes = activate_mfa_state(user)
    access_token = issue_elevated_session(user, code, result)
    return {"access_token": access_token, "backup_codes": backup_codes, "window": result["window"]}
