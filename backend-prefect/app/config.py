import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret-solo-para-laboratorio")
JWT_ALGORITHM = "HS256"

PRE_AUTH_TTL_SECONDS = 5 * 60
ACCESS_TTL_SECONDS = 30 * 60

ISSUER = "Taller2MFA"
TOTP_PERIOD = 30
TOTP_DIGITS = 6
REPLAY_WINDOW_SECONDS = 90
BACKUP_CODES_COUNT = 8

SUPABASE_URL = os.getenv("SUPABASE_URL", "").rstrip("/")
SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY", "")
SQLITE_PATH = BASE_DIR / "lab.db"
