"""Strategy Pattern para el segundo factor."""
import hmac
from abc import ABC, abstractmethod
from dataclasses import dataclass

from . import totp
from .repository import User
from .security import hash_backup_code

WINDOW_LABELS = {-1: "C-1", 0: "C", 1: "C+1"}


@dataclass
class StrategyResult:
    valid: bool
    method: str
    detail: str
    window: str | None = None
    consumed_backup_hash: str | None = None


class SecondFactorStrategy(ABC):
    method: str

    @abstractmethod
    def verify(self, user: User, code: str) -> StrategyResult: ...


class TOTPStrategy(SecondFactorStrategy):
    """Valida el código evaluando las ventanas C-1, C y C+1."""
    method = "totp"

    def verify(self, user, code):
        if not user.totp_secret:
            return StrategyResult(False, self.method, "El usuario no tiene secreto TOTP")
        offset = totp.find_matching_window(user.totp_secret, code)
        if offset is None:
            return StrategyResult(False, self.method, "Código no coincide en C-1, C ni C+1")
        label = WINDOW_LABELS[offset]
        hint = {-1: "reloj del celular ATRASADO", 0: "relojes sincronizados",
                1: "reloj del celular ADELANTADO"}[offset]
        return StrategyResult(True, self.method, f"Match en ventana {label} ({hint})", window=label)


class BackupCodeStrategy(SecondFactorStrategy):
    """Valida códigos de emergencia de un solo uso."""
    method = "backup"

    def verify(self, user, code):
        candidate = hash_backup_code(code)
        for stored in user.backup_code_hashes:
            if hmac.compare_digest(stored, candidate):
                return StrategyResult(True, self.method, "Código de respaldo válido (se consumirá)",
                                      consumed_backup_hash=stored)
        return StrategyResult(False, self.method, "Código de respaldo inválido o ya usado")


_STRATEGIES: dict[str, SecondFactorStrategy] = {
    s.method: s for s in (TOTPStrategy(), BackupCodeStrategy())
}


def get_strategy(method: str) -> SecondFactorStrategy:
    try:
        return _STRATEGIES[method]
    except KeyError:
        raise ValueError(f"Método de segundo factor desconocido: {method}") from None
