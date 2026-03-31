"""Normalize DATABASE_URL for sync SQLAlchemy (Casbin adapter)."""

from __future__ import annotations


def sync_database_url(url: str) -> str:
    u = url.strip()
    if "+asyncpg" in u:
        u = u.replace("postgresql+asyncpg://", "postgresql://", 1)
    if u.startswith("postgres://"):
        u = u.replace("postgres://", "postgresql://", 1)
    if u.startswith("postgresql://"):
        u = u.replace("postgresql://", "postgresql+psycopg://", 1)
    return u
