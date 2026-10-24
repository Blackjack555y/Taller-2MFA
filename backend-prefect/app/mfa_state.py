"""Máquina de estados del aprovisionamiento 2FA (Process Manager).

DISABLED --setup--> PENDING_VERIFICATION --primer código válido--> ACTIVE
PENDING_VERIFICATION --setup (QR nuevo)--> PENDING_VERIFICATION
"""
from enum import Enum


class MFAState(str, Enum):
    DISABLED = "DISABLED"
    PENDING_VERIFICATION = "PENDING_VERIFICATION"
    ACTIVE = "ACTIVE"


class InvalidTransition(Exception):
    pass


_TRANSITIONS = {
    MFAState.DISABLED: {MFAState.PENDING_VERIFICATION},
    MFAState.PENDING_VERIFICATION: {MFAState.PENDING_VERIFICATION, MFAState.ACTIVE},
    MFAState.ACTIVE: set(),
}


def transition(current: str, target: MFAState) -> MFAState:
    current = MFAState(current)
    if target not in _TRANSITIONS[current]:
        raise InvalidTransition(f"Transición no permitida: {current.value} -> {target.value}")
    return target
