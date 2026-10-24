"""Repositorio de usuarios: Supabase (PostgREST) si hay credenciales, si no SQLite."""
import json
import sqlite3
import threading
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

import httpx

from .config import SQLITE_PATH, SUPABASE_SERVICE_KEY, SUPABASE_URL


@dataclass
class User:
    id: str
    username: str
    password_hash: str
    mfa_state: str = "DISABLED"
    totp_secret: str | None = None
    backup_code_hashes: list[str] = field(default_factory=list)


class UserRepository(ABC):
    name: str

    @abstractmethod
    def create(self, username: str, password_hash: str) -> User: ...

    @abstractmethod
    def get_by_username(self, username: str) -> User | None: ...

    @abstractmethod
    def get_by_id(self, user_id: str) -> User | None: ...

    @abstractmethod
    def update_mfa(self, user: User) -> None: ...


class SQLiteUserRepository(UserRepository):
    name = "sqlite"

    def __init__(self, path=SQLITE_PATH):
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                mfa_state TEXT NOT NULL DEFAULT 'DISABLED',
                totp_secret TEXT,
                backup_code_hashes TEXT NOT NULL DEFAULT '[]'
            )""")
        self._conn.commit()

    @staticmethod
    def _row_to_user(row) -> User | None:
        if row is None:
            return None
        return User(row["id"], row["username"], row["password_hash"], row["mfa_state"],
                    row["totp_secret"], json.loads(row["backup_code_hashes"]))

    def create(self, username, password_hash):
        user = User(str(uuid.uuid4()), username, password_hash)
        with self._lock:
            self._conn.execute(
                "INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
                (user.id, user.username, user.password_hash))
            self._conn.commit()
        return user

    def get_by_username(self, username):
        with self._lock:
            row = self._conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        return self._row_to_user(row)

    def get_by_id(self, user_id):
        with self._lock:
            row = self._conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        return self._row_to_user(row)

    def update_mfa(self, user):
        with self._lock:
            self._conn.execute(
                "UPDATE users SET mfa_state = ?, totp_secret = ?, backup_code_hashes = ? WHERE id = ?",
                (user.mfa_state, user.totp_secret, json.dumps(user.backup_code_hashes), user.id))
            self._conn.commit()


class SupabaseUserRepository(UserRepository):
    """Usa la API REST de Supabase (PostgREST) con la service key del backend."""
    name = "supabase"

    def __init__(self, url=SUPABASE_URL, key=SUPABASE_SERVICE_KEY):
        headers = {"apikey": key, "Content-Type": "application/json"}
        # Las claves nuevas (sb_secret_...) no son JWT y van solo en `apikey`;
        # la legacy service_role (JWT) también se manda como Bearer.
        if not key.startswith("sb_"):
            headers["Authorization"] = f"Bearer {key}"
        self._client = httpx.Client(base_url=f"{url}/rest/v1", headers=headers, timeout=10)

    @staticmethod
    def _to_user(data: dict) -> User:
        return User(str(data["id"]), data["username"], data["password_hash"], data["mfa_state"],
                    data.get("totp_secret"), data.get("backup_code_hashes") or [])

    def _get_one(self, column, value):
        resp = self._client.get("/users", params={column: f"eq.{value}", "select": "*"})
        resp.raise_for_status()
        rows = resp.json()
        return self._to_user(rows[0]) if rows else None

    def create(self, username, password_hash):
        resp = self._client.post("/users", headers={"Prefer": "return=representation"},
                                 json={"username": username, "password_hash": password_hash})
        resp.raise_for_status()
        return self._to_user(resp.json()[0])

    def get_by_username(self, username):
        return self._get_one("username", username)

    def get_by_id(self, user_id):
        return self._get_one("id", user_id)

    def update_mfa(self, user):
        resp = self._client.patch("/users", params={"id": f"eq.{user.id}"}, json={
            "mfa_state": user.mfa_state,
            "totp_secret": user.totp_secret,
            "backup_code_hashes": user.backup_code_hashes,
        })
        resp.raise_for_status()


def build_repository() -> UserRepository:
    if SUPABASE_URL and SUPABASE_SERVICE_KEY:
        return SupabaseUserRepository()
    return SQLiteUserRepository()


repository = build_repository()
