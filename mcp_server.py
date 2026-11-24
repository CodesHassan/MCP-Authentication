"""
mcp_server.py - Secured MCP Server (Resource Server)

Kaam:
  - Har request ka JWT access token verify karna (signature, expiry, issuer, audience)
  - Sirf valid token walon ko tools dena
  - Tools par scope check (tools:read / tools:write)

Yeh server tokens BANATA nahi. Token banana Auth Server ka kaam hai.
Isay sirf public key (JWKS) chahiye, private key kabhi nahi.

Run:
    python mcp_server.py
"""

import logging

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.server.auth.providers.jwt import JWTVerifier
from fastmcp.server.dependencies import get_access_token
from starlette.requests import Request
from starlette.responses import JSONResponse

import config

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("mcp-server")

# ---------------------------------------------------------------------------
# 1. Token verification
#    JWTVerifier khud yeh sab check karta hai, tool ka code chalne se PEHLE:
#      - signature (Auth Server ki public key se)
#      - exp (expire to nahi)
#      - iss (sahi Auth Server ne banaya)
#      - aud (token isi MCP server ke liye hai)
#      - required_scopes (kam az kam tools:read)
#    Kuch bhi galat ho to 401/403 milta hai.
#    JWKS cache hota hai, aur key rotate hone par khud dobara fetch hota hai.
# ---------------------------------------------------------------------------
auth = JWTVerifier(
    jwks_uri=f"{config.get('AUTH_SERVER_URL')}/.well-known/jwks.json",
    issuer=config.get("AUTH_ISSUER"),
    audience=config.get("MCP_AUDIENCE"),
    algorithm="RS256",
    required_scopes=["tools:read"],
)

mcp = FastMCP(name="secure-mcp-server", auth=auth)


# ---------------------------------------------------------------------------
# 2. Helpers: kaun hai aur kya kar sakta hai
# ---------------------------------------------------------------------------
def current_user() -> str:
    token = get_access_token()
    claims = getattr(token, "claims", None) or {}
    return str(claims.get("sub") or getattr(token, "client_id", "unknown"))


def require_scope(scope: str) -> None:
    """Tool ke andar permission check. Scope na ho to tool ruk jata hai."""
    token = get_access_token()
    if token is None or scope not in (token.scopes or []):
        log.warning("Permission denied: user=%s needs scope=%s", current_user(), scope)
        raise ToolError(f"Permission denied: '{scope}' scope required")


# Demo storage (production mein database). Har user ke apne notes.
NOTES: dict[str, list[dict]] = {}


# ---------------------------------------------------------------------------
# 3. Tools
# ---------------------------------------------------------------------------
@mcp.tool
def whoami() -> dict:
    """Token ke mutabiq current user aur uski permissions batata hai."""
    token = get_access_token()
    return {"user": current_user(), "scopes": list(token.scopes or [])}


@mcp.tool
def add(a: float, b: float) -> float:
    """Do numbers ka jama."""
    return a + b


@mcp.tool
def multiply(a: float, b: float) -> float:
    """Do numbers ka zarb."""
    return a * b


@mcp.tool
def greet(name: str) -> str:
    """Kisi ko greet karta hai."""
    return f"Hello, {name}! Aap secured MCP server tak pahunch gaye."


@mcp.tool
def save_note(title: str, content: str) -> str:
    """Note save karta hai. Sirf 'tools:write' scope walay user kar sakte hain."""
    require_scope("tools:write")
    NOTES.setdefault(current_user(), []).append({"title": title, "content": content})
    return f"Note '{title}' save ho gaya."


@mcp.tool
def list_notes() -> list[dict]:
    """Current user ke apne notes dikhata hai."""
    return NOTES.get(current_user(), [])


# ---------------------------------------------------------------------------
# 4. Health check (load balancer / monitoring ke liye, token ki zaroorat nahi)
# ---------------------------------------------------------------------------
@mcp.custom_route("/health", methods=["GET"])
async def health(request: Request) -> JSONResponse:
    return JSONResponse({"status": "ok"})


# ---------------------------------------------------------------------------
if __name__ == "__main__":
    mcp.run(
        transport="streamable-http",
        host=config.get("MCP_HOST", "127.0.0.1"),
        port=config.get_int("MCP_PORT", 8000),
        path="/mcp",
    )
