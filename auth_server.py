"""
auth_server.py - Authorization Server (token dene wala server)

Kaam:
  1. Login: username/password check karke tokens deta hai
       - access token  (15 min) -> JSON body mein, client memory mein rakhta hai
       - refresh token (7 din)  -> HttpOnly cookie mein (JavaScript/LLM isay nahi dekh sakta)
  2. Refresh: purana refresh token le kar naya jodi deta hai (rotation)
  3. Logout: session ko khatam kar deta hai
  4. JWKS: public key publish karta hai taake MCP server tokens verify kar sake

Run:
    python auth_server.py
"""

import json
import logging
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import bcrypt
import jwt
import uvicorn
from cryptography.hazmat.primitives import serialization
from fastapi import Cookie, FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from jwt.algorithms import RSAAlgorithm
from pydantic import BaseModel, Field
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

import config

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("auth-server")

# ---------------------------------------------------------------------------
# 1. Settings (.env se)
# ---------------------------------------------------------------------------
ALGORITHM = "RS256"
ISSUER = config.get("AUTH_ISSUER")                 # token kis ne banaya
MCP_AUDIENCE = config.get("MCP_AUDIENCE")          # access token kis server ke liye hai
REFRESH_AUDIENCE = config.get("REFRESH_AUDIENCE")  # refresh token sirf Auth Server ke liye hai
KEY_ID = config.get("JWT_KEY_ID", "key-1")
ACCESS_MINUTES = config.get_int("ACCESS_TOKEN_EXPIRE_MINUTES", 15)
REFRESH_DAYS = config.get_int("REFRESH_TOKEN_EXPIRE_DAYS", 7)
IS_PRODUCTION = config.get_bool("IS_PRODUCTION", False)
CORS_ORIGINS = [o.strip() for o in config.get("CORS_ORIGINS", "").split(",") if o.strip()]

# ---------------------------------------------------------------------------
# 2. RSA keys aur JWKS
#    Private key se SIGN karte hain, public key (JWKS) se koi bhi VERIFY kar sakta hai.
# ---------------------------------------------------------------------------
PRIVATE_KEY = serialization.load_pem_private_key(
    Path(config.get("PRIVATE_KEY_PATH")).read_bytes(), password=None
)
PUBLIC_KEY = PRIVATE_KEY.public_key()

JWKS = {
    "keys": [
        {
            **json.loads(RSAAlgorithm.to_jwk(PUBLIC_KEY)),
            "kid": KEY_ID,
            "use": "sig",
            "alg": ALGORITHM,
        }
    ]
}

# ---------------------------------------------------------------------------
# 3. Users (DEMO). Production mein yeh real database (PostgreSQL) se aayega.
#    Passwords hamesha hash karke store hote hain, plain text nahi.
# ---------------------------------------------------------------------------
def _hash(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


USERS = {
    "alice": {
        "password_hash": _hash(config.get("ALICE_PASSWORD")),
        "scopes": ["tools:read", "tools:write"],   # parh bhi sakti hai, likh bhi sakti hai
    },
    "bob": {
        "password_hash": _hash(config.get("BOB_PASSWORD")),
        "scopes": ["tools:read"],                  # sirf parh sakta hai
    },
}
# Agar username galat ho tab bhi password check karte hain, taake response ke
# time se pata na chale ke user mojood hai ya nahi (timing attack se bachao).
DUMMY_HASH = _hash("dummy-password")


# ---------------------------------------------------------------------------
# 4. Refresh token ka hisaab kitab
#    - "family" = ek login se shuru hone wali tokens ki poori chain
#    - Har refresh par purana token "used" ho jata hai
#    - Agar used token dobara aaye -> chori ka shak -> poori family band
#    Production mein yeh Redis hona chahiye (restart par data na jaye).
# ---------------------------------------------------------------------------
class TokenStore:
    def __init__(self) -> None:
        self.used_jtis: set[str] = set()
        self.revoked_families: set[str] = set()


STORE = TokenStore()


# ---------------------------------------------------------------------------
# 5. Token banane ke helpers
# ---------------------------------------------------------------------------
def _now() -> datetime:
    return datetime.now(timezone.utc)


def create_access_token(username: str, scopes: list[str]) -> str:
    now = _now()
    payload = {
        "sub": username,
        "iss": ISSUER,
        "aud": MCP_AUDIENCE,                 # MCP server sirf isi audience ko maanega
        "iat": now,
        "exp": now + timedelta(minutes=ACCESS_MINUTES),
        "jti": str(uuid.uuid4()),
        "scope": " ".join(scopes),           # OAuth ka standard format: space-separated string
        "token_use": "access",
    }
    return jwt.encode(payload, PRIVATE_KEY, algorithm=ALGORITHM, headers={"kid": KEY_ID})


def create_refresh_token(username: str, family_id: str) -> str:
    now = _now()
    payload = {
        "sub": username,
        "iss": ISSUER,
        "aud": REFRESH_AUDIENCE,             # alag audience: MCP server isay kabhi qubool nahi karega
        "iat": now,
        "exp": now + timedelta(days=REFRESH_DAYS),
        "jti": str(uuid.uuid4()),
        "fid": family_id,
        "token_use": "refresh",
    }
    return jwt.encode(payload, PRIVATE_KEY, algorithm=ALGORITHM, headers={"kid": KEY_ID})


def set_refresh_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key="refresh_token",
        value=token,
        httponly=True,                       # JavaScript cookie parh nahi sakti
        secure=IS_PRODUCTION,                # production mein sirf HTTPS par
        samesite="strict",                   # CSRF se bachao
        path="/auth",                        # sirf /auth/* ko jati hai, MCP server ko kabhi nahi
        max_age=REFRESH_DAYS * 24 * 60 * 60,
    )


def decode_refresh_token(token: str) -> dict:
    """Refresh token check karta hai. Kuch bhi galat ho to 401."""
    try:
        payload = jwt.decode(
            token,
            PUBLIC_KEY,
            algorithms=[ALGORITHM],
            audience=REFRESH_AUDIENCE,
            issuer=ISSUER,
            leeway=10,                       # chhote clock difference ki ijazat
        )
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")

    if payload.get("token_use") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    family_id = payload["fid"]

    if family_id in STORE.revoked_families:
        raise HTTPException(status_code=401, detail="Session ended. Please log in again")

    if payload["jti"] in STORE.used_jtis:
        # Purana token dobara aaya: ya to chori hua hai ya koi gadbad hai.
        # Safe tareeqa: poora session band kar do.
        STORE.revoked_families.add(family_id)
        log.warning("Refresh token reuse detected for user=%s, session revoked", payload["sub"])
        raise HTTPException(status_code=401, detail="Refresh token reuse detected. Please log in again")

    return payload


# ---------------------------------------------------------------------------
# 6. FastAPI app
# ---------------------------------------------------------------------------
limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="Auth Server",
    docs_url=None if IS_PRODUCTION else "/docs",     # production mein docs band
    redoc_url=None,
    openapi_url=None if IS_PRODUCTION else "/openapi.json",
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,                          # cookies ke liye zaroori
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization"],
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Cache-Control"] = "no-store"
    if IS_PRODUCTION:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


# ---------------------------------------------------------------------------
# 7. Request / Response models
# ---------------------------------------------------------------------------
class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=64)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int                                  # seconds


# ---------------------------------------------------------------------------
# 8. Endpoints
# ---------------------------------------------------------------------------
@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/.well-known/jwks.json")
def jwks():
    """Public key. MCP server yahan se key le kar token verify karta hai. Public hona theek hai."""
    return JWKS


@app.post("/auth/login", response_model=TokenResponse)
@limiter.limit("5/minute")                           # brute-force se bachao
def login(request: Request, response: Response, body: LoginRequest):
    user = USERS.get(body.username)
    password_ok = bcrypt.checkpw(
        body.password.encode(), (user["password_hash"] if user else DUMMY_HASH).encode()
    )

    if not user or not password_ok:
        log.info("Login failed for username=%s", body.username)
        raise HTTPException(status_code=401, detail="Invalid username or password")

    family_id = str(uuid.uuid4())                    # nayi login = nayi session family
    set_refresh_cookie(response, create_refresh_token(body.username, family_id))
    log.info("Login ok for user=%s", body.username)

    return TokenResponse(
        access_token=create_access_token(body.username, user["scopes"]),
        expires_in=ACCESS_MINUTES * 60,
    )


@app.post("/auth/refresh", response_model=TokenResponse)
@limiter.limit("10/minute")
def refresh(
    request: Request,
    response: Response,
    refresh_token: Optional[str] = Cookie(default=None),   # cookie se aata hai
):
    if not refresh_token:
        raise HTTPException(status_code=401, detail="No refresh token")

    payload = decode_refresh_token(refresh_token)
    username = payload["sub"]

    user = USERS.get(username)
    if not user:
        raise HTTPException(status_code=401, detail="User no longer exists")

    # Rotation: purana token ab dobara use nahi ho sakta
    STORE.used_jtis.add(payload["jti"])

    set_refresh_cookie(response, create_refresh_token(username, payload["fid"]))

    # Scopes har dafa users ki taaza permissions se aate hain
    return TokenResponse(
        access_token=create_access_token(username, user["scopes"]),
        expires_in=ACCESS_MINUTES * 60,
    )


@app.post("/auth/logout", status_code=204)
@limiter.limit("10/minute")
def logout(
    request: Request,
    response: Response,
    refresh_token: Optional[str] = Cookie(default=None),
):
    """Session band. Access token zyada se zyada 15 min mein khud expire ho jayega."""
    if refresh_token:
        try:
            payload = jwt.decode(
                refresh_token,
                PUBLIC_KEY,
                algorithms=[ALGORITHM],
                audience=REFRESH_AUDIENCE,
                issuer=ISSUER,
                leeway=10,
            )
            STORE.revoked_families.add(payload["fid"])
        except jwt.PyJWTError:
            pass                                      # token pehle hi kharab hai, koi masla nahi

    response.delete_cookie(key="refresh_token", path="/auth")


# ---------------------------------------------------------------------------
if __name__ == "__main__":
    uvicorn.run(
        "auth_server:app",
        host=config.get("AUTH_HOST", "127.0.0.1"),
        port=config.get_int("AUTH_PORT", 9000),
    )
