"""
config.py - chhote helper functions jo .env se settings parhte hain.

Har service (auth server, MCP server, client) sirf wohi variables mangti hai
jo usay chahiye. Agar koi zaroori variable missing ho to start hote hi
saaf error aata hai (galat config ke sath chalne se behtar hai).
"""

import os

from dotenv import load_dotenv

load_dotenv()


def get(name: str, default: str | None = None) -> str:
    value = os.getenv(name, default)
    if value is None:
        raise RuntimeError(f"Missing environment variable: {name} (.env file check karein)")
    return value


def get_int(name: str, default: int | None = None) -> int:
    return int(get(name, None if default is None else str(default)))


def get_bool(name: str, default: bool = False) -> bool:
    return get(name, str(default)).strip().lower() in ("1", "true", "yes")
