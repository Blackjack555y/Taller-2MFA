"""Caché anti-replay en memoria: (user_id, code) -> instante en que se usó."""
import threading
import time

from .config import REPLAY_WINDOW_SECONDS


class ReplayAttackDetected(Exception):
    pass


class AntiReplayCache:
    def __init__(self, ttl_seconds: int = REPLAY_WINDOW_SECONDS):
        self._ttl = ttl_seconds
        self._used: dict[tuple[str, str], float] = {}
        self._lock = threading.Lock()

    @property
    def ttl(self) -> int:
        return self._ttl

    def _purge(self, now: float) -> None:
        expired = [k for k, used_at in self._used.items() if now - used_at > self._ttl]
        for k in expired:
            del self._used[k]

    def used_at(self, user_id: str, code: str) -> float | None:
        with self._lock:
            self._purge(time.time())
            return self._used.get((user_id, code))

    def mark_used(self, user_id: str, code: str) -> None:
        """Check-and-set atómico: si otra petición concurrente ya lo marcó, es replay."""
        with self._lock:
            now = time.time()
            self._purge(now)
            if (user_id, code) in self._used:
                raise ReplayAttackDetected(
                    f"El código {code} ya fue usado por el usuario {user_id} (carrera concurrente)")
            self._used[(user_id, code)] = now


replay_cache = AntiReplayCache()
