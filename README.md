# MCP Authentication (Production Style) - Complete Guide

Is folder mein ek **secure MCP Server** hai jisko sirf wohi use kar sakta hai jis ke paas **valid JWT token** ho. Client **LangChain MCP Adapters** se is server ke tools use karta hai.

---

## 1. Production mein MCP authentication kaise hoti hai?

MCP ki official authorization (OAuth 2.1 par based) mein 3 hissay hotay hain:

| Hissa | Is project mein | Kaam |
|-------|-----------------|------|
| **Authorization Server** | `auth_server.py` | Login lena, tokens banana, refresh/logout, public key (JWKS) dena |
| **Resource Server** | `mcp_server.py` | Tools dena, har request ka token verify karna |
| **Client** | `client.py` | Login karna, token ke sath MCP call karna, token refresh karna |

**Sab se zaroori usool:** MCP Server tokens **banata nahi**, sirf **verify** karta hai. Token banana alag server ka kaam hai. Is wajah se production mein Auth Server ki jagah Auth0, Keycloak, Azure Entra ID, Okta waghera lagaye ja sakte hain, aur MCP server mein sirf 3 cheezein badalti hain: `JWKS URL`, `issuer`, `audience`.

---

## 2. Folder Structure

```
MCP-Authentication/
├── .env                 # Testing values (dummy). Git mein commit na karein
├── .gitignore
├── requirements.txt
├── config.py            # .env parhne ke chhote helpers
├── generate_keys.py     # RSA private key banati hai (ek baar)
├── auth_server.py       # Auth Server  (port 9000)
├── mcp_server.py        # Secured MCP Server (port 8000)
├── client.py            # LangChain MCP Adapters client
└── keys/                # generate_keys.py chalane ke baad banega
    └── private_key.pem
```

---

## 3. Poora Flow (Aasan Zubaan Mein)

```
 CLIENT                      AUTH SERVER                    MCP SERVER
   |  1. login (user+pass)       |                              |
   |---------------------------->|                              |
   |  2. access token (body)     |                              |
   |     refresh token (cookie)  |                              |
   |<----------------------------|                              |
   |                                                            |
   |  3. tool call + "Authorization: Bearer <access token>"     |
   |----------------------------------------------------------->|
   |                             |  4. public key (JWKS) leta   |
   |                             |<-----------------------------|
   |                             |     token verify hota hai    |
   |  5. tool ka result                                         |
   |<-----------------------------------------------------------|
   |                                                            |
   |  6. token expire hone wala ho -> /auth/refresh             |
   |---------------------------->|  (naya access + naya refresh)|
   |                                                            |
   |  7. logout                  |                              |
   |---------------------------->|                              |
```

---

## 4. Concepts (Detail Mein)

### 4.1 Access Token aur Refresh Token

| | Access Token | Refresh Token |
|---|---|---|
| Umar | 15 minute | 7 din |
| Kahan milta hai | JSON body mein | HttpOnly cookie mein |
| Kis ko jata hai | MCP Server ko | Sirf Auth Server ko |
| `aud` (audience) | `mcp-secure-server` | `auth-server-refresh` |

Do alag tokens isliye ke agar access token chori ho jaye to woh sirf 15 minute chalta hai. Lamba token (refresh) cookie mein chhupa rehta hai jise JavaScript ya LLM parh nahi sakta.

**Ahem:** Refresh token ka `aud` alag hai. Agar koi refresh token ko MCP server par bhejne ki koshish kare to MCP server usay reject kar deta hai, kyunke uska `aud` `mcp-secure-server` nahi hai.

### 4.2 RS256 (Private key / Public key)

- Auth Server **private key** se token par sign karta hai.
- MCP Server **public key** se sign check karta hai.
- MCP server hack bhi ho jaye to attacker naye tokens nahi bana sakta, kyunke private key wahan hai hi nahi.

### 4.3 JWKS

Auth Server public key `GET /.well-known/jwks.json` par publish karta hai. MCP Server yahan se key leta hai aur cache karta hai. Key rotate karni ho to nayi `kid` wali key add karein, MCP server khud nayi key utha leta hai.

### 4.4 Token ke Claims

| Claim | Matlab |
|-------|--------|
| `sub` | User ka naam |
| `iss` | Token kis Auth Server ne banaya |
| `aud` | Token kis server ke liye hai |
| `exp` / `iat` | Expiry / banne ka waqt |
| `jti` | Token ki unique ID |
| `scope` | Permissions, space-separated (`tools:read tools:write`) |
| `token_use` | `access` ya `refresh` |
| `fid` | (sirf refresh) session family ID |

### 4.5 Scopes (Authorization)

Authentication = "aap kaun hain", Authorization = "aap kya kar sakte hain".

| User | Scopes | Kya kar sakta hai |
|------|--------|-------------------|
| `alice` | `tools:read`, `tools:write` | Sab tools, `save_note` bhi |
| `bob` | `tools:read` | Sirf parhne wale tools. `save_note` par **Permission denied** |

- Server level par: `required_scopes=["tools:read"]` (iske bina MCP mein ghusna hi nahi).
- Tool level par: `save_note` ke andar `require_scope("tools:write")`.

### 4.6 Refresh Token Rotation aur Reuse Detection

- Har refresh par **naya** refresh token milta hai aur purana "used" ho jata hai.
- Agar koi "used" token dobara aaye (chori ka shak), to us login ki **poori session family** band ho jati hai aur dobara login karna parta hai.
- Cookie ka path `/auth` hai, is liye `/auth/refresh` aur `/auth/logout` dono ko cookie milti hai, lekin MCP server ko kabhi nahi.

### 4.7 Cookie ke Security Flags

| Flag | Fayda |
|------|-------|
| `HttpOnly` | JavaScript cookie nahi parh sakti |
| `Secure` | Production mein sirf HTTPS par jati hai |
| `SameSite=Strict` | CSRF se bachao |
| `Path=/auth` | Sirf Auth endpoints ko jati hai |

### 4.8 Baqi Security

- **bcrypt** se password hashing, aur galat username par bhi hash check hota hai (timing attack se bachao).
- **Rate limit:** login 5/minute, refresh aur logout 10/minute.
- **Security headers:** `nosniff`, `X-Frame-Options`, `Cache-Control: no-store`, production mein HSTS.
- **Production mein** `/docs` band ho jata hai.
- **CORS** sirf `.env` ki allowed origins ke liye.
- **Health check:** dono servers par `/health` (token ke baghair, monitoring ke liye).

---

## 5. File-by-File

### `config.py`
`.env` se settings parhta hai. Zaroori variable missing ho to start hote hi saaf error aata hai.

### `generate_keys.py`
RSA 2048 private key `keys/private_key.pem` mein banati hai. Agar file pehle se ho to overwrite **nahi** karti (warna purane tokens kharab ho jate). Public key alag save nahi hoti, Auth Server private key se nikal leta hai.

### `auth_server.py`
Endpoints:

| Endpoint | Kaam |
|----------|------|
| `POST /auth/login` | Body: `{"username": "...", "password": "..."}`. Access token body mein, refresh token cookie mein |
| `POST /auth/refresh` | Cookie se refresh token le kar naya jodi deta hai |
| `POST /auth/logout` | Session band, cookie delete (204) |
| `GET /.well-known/jwks.json` | Public key |
| `GET /health` | Status |

### `mcp_server.py`
- `JWTVerifier` har request par signature, expiry, issuer, audience aur scope check karta hai. Fail ho to tool ka code chalta hi nahi.
- Tools: `whoami`, `add`, `multiply`, `greet`, `list_notes` (read), `save_note` (write scope chahiye).
- Notes har user ke alag rakhe jate hain (token ke `sub` se).

### `client.py`
- `AuthSession`: login, token memory mein, expire se 30 second pehle khud refresh, logout. Ek `asyncio.Lock` hai taake do jagah se ek saath refresh na ho.
- `BearerAuth`: har MCP request par fresh token lagata hai, is liye lamba chalne wala agent bhi token expire hone par nahi rukta.
- `load_tools()`: `MultiServerMCPClient` (LangChain MCP Adapters) se tools load karta hai.
- Teen demo: agent (LLM), direct tool calls (bina LLM), galat token ka test.

---

## 6. Run Karne ka Tareeqa

Sab commands is folder ke andar chalayein. Python 3.10 ya naya chahiye.

```bash
# 1. Virtual environment aur packages
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt

# 2. RSA key (sirf ek baar)
python generate_keys.py

# 3. Terminal 1: Auth Server
python auth_server.py

# 4. Terminal 2: MCP Server
python mcp_server.py

# 5. Terminal 3: Client
python client.py --direct     # bina LLM, auth test karne ke liye
python client.py              # LLM ke sath (real LLM_API_KEY chahiye)
```

**Start order:** pehle Auth Server, phir MCP Server, akhir mein Client.

`.env` mein `LLM_API_KEY` abhi dummy hai. `--direct` mode mein LLM ki zaroorat nahi. LLM wala mode chalane ke liye real key daalein. Aap OpenAI ki jagah koi bhi OpenAI-compatible provider (jaise OpenRouter) `LLM_BASE_URL` aur `LLM_MODEL` se use kar sakte hain.

### Expected output (`--direct`)

```
===== 1) alice (tools:read + tools:write) =====
[auth] 'alice' login ho gaya
[tool] whoami({}) -> {"user": "alice", "scopes": ["tools:read", "tools:write"]}
[tool] save_note(...) -> Note 'demo' save ho gaya.

===== 2) bob (sirf tools:read) =====
[tool] save_note(...) -> ERROR: ... Permission denied: 'tools:write' scope required

===== 3) galat token =====
[test] galat token reject hua (expected): ... 401 ...
```

### Manual test (curl)

```bash
# Login
curl -i -X POST http://localhost:9000/auth/login -H "Content-Type: application/json" -d "{\"username\":\"alice\",\"password\":\"alice-pass-123\"}"

# Bina token MCP par -> 401 aana chahiye
curl -i http://localhost:8000/mcp
```

---

## 7. Production Checklist (Demo se Real tak)

| Cheez | Abhi (demo) | Production mein |
|-------|-------------|-----------------|
| Users | Dictionary mein | PostgreSQL + proper user table |
| Token store (used/revoked) | Memory (restart par ghayab) | Redis (TTL ke sath) |
| Private key | File, bina passphrase | Secret manager (Vault, AWS KMS) |
| Secrets (`.env`) | Dummy values | Environment / secret manager se |
| HTTPS | Nahi | Zaroori. `IS_PRODUCTION=true` |
| Auth Server | Khud ka | Auth0 / Keycloak / Entra ID (sirf JWKS URL, issuer, audience badlein) |
| Key rotation | Manual | Nayi `kid` + JWKS mein dono keys kuch din |
| Logging | Console | Central logging, alerts (reuse detection par) |
| Multiple instances | Ek | Redis ke sath load balancer ke peeche |

---

## 8. Maloom Hadood (Limitations)

1. **Access token logout ke baad bhi zyada se zyada 15 minute valid rehta hai.** Yeh JWT ka standard tradeoff hai. Isi liye umar chhoti rakhi hai.
2. **Do requests ek hi refresh token se ek saath** bhejne par doosri ko reuse samjha ja sakta hai aur session band ho jata hai. Client mein `Lock` is se bachata hai, lekin agar aap multiple processes se ek hi cookie use karein to dhyan rakhein.
3. **Demo users aur in-memory store** sirf seekhne ke liye hain (section 7 dekhein).
4. **Full OAuth discovery** (jaise dynamic client registration aur `/.well-known/oauth-protected-resource`) is project mein nahi hai. Yeh sirf Resource Server wala hissa hai jo Claude Desktop jaise OAuth-aware clients ke liye aage badhaya ja sakta hai.

---

## 9. Troubleshooting

| Masla | Wajah / Hal |
|-------|-------------|
| `Missing environment variable` | `.env` check karein |
| `FileNotFoundError: keys/private_key.pem` | `python generate_keys.py` chalayein, aur isi folder se server start karein |
| MCP server start par JWKS error | Auth Server pehle chalayein |
| `401` MCP par | `AUTH_ISSUER` aur `MCP_AUDIENCE` dono servers par same hon |
| `429 Too Many Requests` | Login rate limit, 1 minute ruk jayein |
| `Session khatam ho gaya` | Dobara login karein |
| Auth Server restart ke baad refresh fail | Store memory mein hai, dobara login karein |
| Client mein `401` halanke login theek tha | `langchain-mcp-adapters` ka version purana ho sakta hai. `pip install -U langchain-mcp-adapters` |
| `ModuleNotFoundError` | Virtual environment activate karke `pip install -r requirements.txt` |
