"""
client.py - MCP Client (LangChain MCP Adapters ke sath)

Kaam:
  1. Auth Server par login (username + password)
       - access token  -> memory mein
       - refresh token -> httpx cookie jar mein (hum isay kabhi directly nahi chhoote)
  2. Har MCP request par "Authorization: Bearer <access token>" lagana
  3. Token expire hone se pehle khud refresh kar lena
  4. Logout

Do tareeqe se chalta hai:
    python client.py            -> LangChain agent (LLM) MCP tools use karta hai
    python client.py --direct   -> bina LLM, seedha tools call karke auth test karta hai
"""

import asyncio
import logging
import sys
import time

import httpx
from langchain_mcp_adapters.client import MultiServerMCPClient

import config

logging.getLogger("httpx").setLevel(logging.WARNING)

AUTH_SERVER_URL = config.get("AUTH_SERVER_URL")
MCP_SERVER_URL = config.get("MCP_SERVER_URL")


# ---------------------------------------------------------------------------
# 1. AuthSession: login, token refresh, logout
# ---------------------------------------------------------------------------
class AuthSession:
    def __init__(self) -> None:
        # Ek hi httpx client rakhte hain taake refresh token wali cookie yaad rahe
        self._http = httpx.AsyncClient(base_url=AUTH_SERVER_URL, timeout=10.0)
        self._token = ""
        self._expires_at = 0.0
        self._lock = asyncio.Lock()   # do jagah se ek saath refresh na ho (rotation safe rahe)

    def _save(self, data: dict) -> None:
        self._token = data["access_token"]
        self._expires_at = time.time() + data["expires_in"]

    async def login(self, username: str, password: str) -> None:
        resp = await self._http.post("/auth/login", json={"username": username, "password": password})
        resp.raise_for_status()
        self._save(resp.json())
        print(f"[auth] '{username}' login ho gaya")

    async def get_token(self) -> str:
        """Valid access token deta hai. Expire hone wala ho to pehle refresh karta hai."""
        async with self._lock:
            if time.time() >= self._expires_at - 30:      # 30 second pehle hi refresh
                print("[auth] token refresh ho raha hai...")
                resp = await self._http.post("/auth/refresh")   # cookie khud chali jati hai
                if resp.status_code == 401:
                    raise RuntimeError("Session khatam ho gaya. Dobara login karein.")
                resp.raise_for_status()
                self._save(resp.json())
            return self._token

    async def logout(self) -> None:
        await self._http.post("/auth/logout")
        self._token = ""
        print("[auth] logout ho gaya")

    async def close(self) -> None:
        await self._http.aclose()


class BearerAuth(httpx.Auth):
    """Har MCP request se pehle fresh token lagata hai (lambe chalne wale agent ke liye zaroori)."""

    def __init__(self, session: AuthSession) -> None:
        self.session = session

    async def async_auth_flow(self, request):
        request.headers["Authorization"] = f"Bearer {await self.session.get_token()}"
        yield request


# ---------------------------------------------------------------------------
# 2. MCP tools load karna (LangChain MCP Adapters)
# ---------------------------------------------------------------------------
async def load_tools(session: AuthSession):
    token = await session.get_token()
    client = MultiServerMCPClient(
        {
            "secure": {
                "transport": "streamable_http",
                "url": MCP_SERVER_URL,
                "headers": {"Authorization": f"Bearer {token}"},   # pehli request ke liye
                "auth": BearerAuth(session),                       # aage har request par fresh token
            }
        }
    )
    return await client.get_tools()


def _leaf_error(exc: BaseException) -> str:
    """ExceptionGroup ke andar se asal error message nikalta hai."""
    inner = getattr(exc, "exceptions", None)
    return _leaf_error(inner[0]) if inner else f"{type(exc).__name__}: {exc}"


# ---------------------------------------------------------------------------
# 3. Demo A: bina LLM, seedha tools call (auth test karne ke liye best)
# ---------------------------------------------------------------------------
async def direct_demo(session: AuthSession) -> None:
    tools = {t.name: t for t in await load_tools(session)}
    print(f"[mcp] tools: {list(tools)}")

    calls = [
        ("whoami", {}),
        ("add", {"a": 3.5, "b": 1.5}),
        ("save_note", {"title": "demo", "content": "auth kaam kar raha hai"}),
        ("list_notes", {}),
    ]
    for name, args in calls:
        try:
            result = await tools[name].ainvoke(args)
            print(f"[tool] {name}({args}) -> {result}")
        except Exception as exc:
            print(f"[tool] {name}({args}) -> ERROR: {_leaf_error(exc)}")


# ---------------------------------------------------------------------------
# 4. Demo B: LangChain agent (LLM) jo MCP tools khud chunta hai
# ---------------------------------------------------------------------------
async def agent_demo(session: AuthSession) -> None:
    from langchain_openai import ChatOpenAI
    from langgraph.prebuilt import create_react_agent

    tools = await load_tools(session)
    llm = ChatOpenAI(
        model=config.get("LLM_MODEL", "gpt-4o-mini"),
        api_key=config.get("LLM_API_KEY"),
        base_url=config.get("LLM_BASE_URL", "") or None,
        temperature=0,
    )
    agent = create_react_agent(llm, tools)

    queries = [
        "Main kaun hoon aur meri permissions kya hain?",
        "What is (3.5 + 1.5) multiplied by 4?",
        "Ek note save karo: title 'todo', content 'MCP auth seekhna'. Phir mere saare notes dikhao.",
    ]
    for q in queries:
        print(f"\n[query]  {q}")
        result = await agent.ainvoke({"messages": [{"role": "user", "content": q}]})
        print(f"[answer] {result['messages'][-1].content}")


# ---------------------------------------------------------------------------
# 5. Demo C: galat token -> server ko reject karna chahiye
# ---------------------------------------------------------------------------
async def invalid_token_demo() -> None:
    client = MultiServerMCPClient(
        {
            "secure": {
                "transport": "streamable_http",
                "url": MCP_SERVER_URL,
                "headers": {"Authorization": "Bearer this-is-not-a-real-token"},
            }
        }
    )
    try:
        await client.get_tools()
        print("[test] UNEXPECTED: galat token qubool ho gaya!")
    except Exception as exc:
        print(f"[test] galat token reject hua (expected): {_leaf_error(exc)}")


# ---------------------------------------------------------------------------
# 6. Main
# ---------------------------------------------------------------------------
async def run_as(username: str, password: str, use_llm: bool) -> None:
    session = AuthSession()
    try:
        await session.login(username, password)
        await (agent_demo(session) if use_llm else direct_demo(session))
    finally:
        await session.logout()       # hamesha logout, chahe error aaye
        await session.close()


async def main() -> None:
    use_llm = "--direct" not in sys.argv

    if use_llm and "dummy" in config.get("LLM_API_KEY", "dummy"):
        raise SystemExit(
            ".env mein LLM_API_KEY dummy hai.\n"
            "Real key daalein, ya bina LLM test ke liye chalayein:  python client.py --direct"
        )

    print("\n===== 1) alice (tools:read + tools:write) =====")
    await run_as("alice", config.get("ALICE_PASSWORD"), use_llm)

    print("\n===== 2) bob (sirf tools:read) - save_note deny hona chahiye =====")
    await run_as("bob", config.get("BOB_PASSWORD"), use_llm)

    print("\n===== 3) galat token =====")
    await invalid_token_demo()


if __name__ == "__main__":
    asyncio.run(main())
