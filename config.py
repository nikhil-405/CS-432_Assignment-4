import os
from pathlib import Path
from urllib.parse import quote_plus

BASE_DIR = Path(__file__).resolve().parent


def _int_env(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


class Config:
    DB_USER = os.getenv("DB_USER", "SELECT___FROM_IITGN")
    DB_PASSWORD = os.getenv("DB_PASSWORD", "password@123")
    DB_HOST = os.getenv("DB_HOST", "10.0.116.184")
    DB_PORT = _int_env("DB_PORT", 3307)
    DB_NAME = os.getenv("DB_NAME", "SELECT___FROM_IITGN")
    SHARD_COUNT = _int_env("SHARD_COUNT", 3)
    SHARD_0_PORT = _int_env("SHARD_0_PORT", 3307)
    SHARD_1_PORT = _int_env("SHARD_1_PORT", 3308)
    SHARD_2_PORT = _int_env("SHARD_2_PORT", 3309)

    SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "change-me-for-production")
    JWT_SECRET = os.getenv("JWT_SECRET", "change-me-jwt-secret")
    JWT_ALGORITHM = "HS256"
    SESSION_TTL_MINUTES = _int_env("SESSION_TTL_MINUTES", 120)

    DEFAULT_ADMIN_USERNAME = os.getenv("DEFAULT_ADMIN_USERNAME", "admin")
    DEFAULT_ADMIN_PASSWORD = os.getenv("DEFAULT_ADMIN_PASSWORD", "admin123")

    AUDIT_LOG_PATH = os.getenv("AUDIT_LOG_PATH", str(BASE_DIR / "logs" / "audit.log"))

    @classmethod
    def shard_port(cls, shard_index: int) -> int:
        ports = (cls.SHARD_0_PORT, cls.SHARD_1_PORT, cls.SHARD_2_PORT)
        if shard_index < 0 or shard_index >= len(ports):
            raise ValueError(f"Invalid shard index: {shard_index}")
        return ports[shard_index]

    @classmethod
    def database_url(cls, port: int | None = None) -> str:
        quoted_password = quote_plus(cls.DB_PASSWORD)
        resolved_port = cls.DB_PORT if port is None else port
        return (
            f"mysql+pymysql://{cls.DB_USER}:{quoted_password}@"
            f"{cls.DB_HOST}:{resolved_port}/{cls.DB_NAME}"
        )
