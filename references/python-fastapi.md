# Python / FastAPI / SQLAlchemy / Postgres Security Patterns

Stack-specific implementation patterns for the security review checklist.
Each section maps to the corresponding section in the main SKILL.md.

## Table of Contents

1. [Secrets Management](#1-secrets-management)
2. [Input Validation](#2-input-validation)
3. [Injection Prevention](#3-injection-prevention)
4. [Authentication & Sessions](#4-authentication--sessions)
5. [Authorization](#5-authorization)
6. [XSS Prevention](#6-xss-prevention)
7. [CSRF Protection](#7-csrf-protection)
8. [Rate Limiting](#8-rate-limiting)
9. [Data Exposure Prevention](#9-data-exposure-prevention)
10. [Transport & Infrastructure](#10-transport--infrastructure)
11. [Dependency Security](#11-dependency-security)

---

## 1. Secrets Management

### Loading secrets from environment

```python
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    database_url: str
    secret_key: str
    openai_api_key: str
    allowed_origins: list[str] = ["https://example.com"]

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}

settings = Settings()  # Raises ValidationError if required vars missing
```

This approach validates at startup — the app won't boot with missing secrets.

### What not to do

```python
# DANGEROUS — secrets in source code
API_KEY = "sk-proj-xxxxx"
DB_PASSWORD = "password123"

# RISKY — no validation, silent None
api_key = os.getenv("API_KEY")  # Could be None and fail later
```

### .gitignore

```
.env
.env.local
.env.production
*.pem
*.key
```

---

## 2. Input Validation

### Pydantic models for request validation

```python
from pydantic import BaseModel, EmailStr, Field, field_validator
from fastapi import HTTPException

class CreateUserRequest(BaseModel):
    email: EmailStr
    name: str = Field(min_length=1, max_length=100)
    age: int = Field(ge=0, le=150)

    @field_validator("name")
    @classmethod
    def sanitize_name(cls, v: str) -> str:
        # Strip control characters
        return "".join(c for c in v if c.isprintable())

@app.post("/users")
async def create_user(request: CreateUserRequest):
    # request is already validated by the time we get here
    ...
```

FastAPI validates request bodies automatically when you type-hint with Pydantic
models. Invalid input returns 422 without reaching your handler.

### File upload validation

```python
from fastapi import UploadFile, HTTPException
import magic  # python-magic for reliable MIME detection

ALLOWED_MIME = {"image/jpeg", "image/png", "image/gif"}
ALLOWED_EXT = {".jpg", ".jpeg", ".png", ".gif"}
MAX_SIZE = 5 * 1024 * 1024  # 5 MB

async def validate_upload(file: UploadFile) -> bytes:
    # Read content (enforces size limit)
    content = await file.read()
    if len(content) > MAX_SIZE:
        raise HTTPException(413, "File too large (max 5MB)")

    # Check MIME type from file content, not the claimed type
    detected_mime = magic.from_buffer(content, mime=True)
    if detected_mime not in ALLOWED_MIME:
        raise HTTPException(400, "Invalid file type")

    # Check extension
    ext = Path(file.filename).suffix.lower() if file.filename else ""
    if ext not in ALLOWED_EXT:
        raise HTTPException(400, "Invalid file extension")

    # Generate a safe filename — never trust user-provided names
    safe_name = f"{uuid4().hex}{ext}"

    return content, safe_name
```

Key point: check the actual file content with `python-magic`, not the
user-supplied `Content-Type` header. Attackers can set any Content-Type they want.

### Path traversal prevention

```python
from pathlib import Path

UPLOAD_DIR = Path("/app/uploads").resolve()

def safe_path(user_filename: str) -> Path:
    """Resolve path and verify it's inside the upload directory."""
    # Use only the filename, strip any directory components
    clean_name = Path(user_filename).name
    target = (UPLOAD_DIR / clean_name).resolve()
    if not str(target).startswith(str(UPLOAD_DIR)):
        raise HTTPException(400, "Invalid filename")
    return target
```

---

## 3. Injection Prevention

### SQL injection — SQLAlchemy ORM (safe by default)

```python
# Safe — ORM parameterizes automatically
user = session.query(User).filter(User.email == user_email).first()

# Safe — using select()
stmt = select(User).where(User.email == user_email)
result = session.execute(stmt).scalar_one_or_none()
```

### SQL injection — raw SQL (use bind parameters)

```python
# DANGEROUS — string formatting in SQL
query = f"SELECT * FROM users WHERE email = '{user_email}'"  # SQLi!
query = "SELECT * FROM users WHERE email = '%s'" % user_email  # SQLi!

# Safe — bind parameters
result = session.execute(
    text("SELECT * FROM users WHERE email = :email"),
    {"email": user_email}
)
```

### SQL injection — dynamic column/table names

Bind parameters only work for values, not identifiers. When you need dynamic
column or table names, use an allowlist:

```python
ALLOWED_SORT_COLUMNS = {"name", "created_at", "email"}

def get_users(sort_by: str):
    if sort_by not in ALLOWED_SORT_COLUMNS:
        raise HTTPException(400, "Invalid sort column")
    # Safe — sort_by is from a known set
    return session.execute(text(f"SELECT * FROM users ORDER BY {sort_by}"))
```

### Command injection

```python
import shlex
import subprocess

# DANGEROUS — shell=True with user input
subprocess.run(f"convert {user_filename} output.png", shell=True)

# Safe — argument list, no shell
subprocess.run(["convert", user_filename, "output.png"], check=True)

# If you absolutely need shell (try not to) — escape input
subprocess.run(f"convert {shlex.quote(user_filename)} output.png", shell=True)
```

---

## 4. Authentication & Sessions

### Password hashing with bcrypt

```python
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)
```

### JWT tokens in httpOnly cookies

```python
from fastapi.responses import JSONResponse
from datetime import datetime, timedelta, timezone
import jwt

def create_access_token(user_id: str, expires_minutes: int = 60) -> str:
    payload = {
        "sub": user_id,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=expires_minutes),
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, settings.secret_key, algorithm="HS256")

@app.post("/login")
async def login(credentials: LoginRequest):
    user = await authenticate(credentials.email, credentials.password)
    if not user:
        # Don't reveal whether the email or password was wrong
        raise HTTPException(401, "Invalid credentials")

    token = create_access_token(user.id)
    response = JSONResponse({"message": "Logged in"})
    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,       # JS can't read it — mitigates XSS token theft
        secure=True,         # HTTPS only
        samesite="strict",   # Mitigates CSRF
        max_age=3600,
    )
    return response
```

### Extracting the current user from cookies

```python
from fastapi import Cookie, Depends, HTTPException

async def get_current_user(access_token: str = Cookie(None)) -> User:
    if not access_token:
        raise HTTPException(401, "Not authenticated")
    try:
        payload = jwt.decode(access_token, settings.secret_key, algorithms=["HS256"])
        user = await get_user_by_id(payload["sub"])
        if not user:
            raise HTTPException(401, "User not found")
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(401, "Invalid token")
```

---

## 5. Authorization

### Dependency-based authorization in FastAPI

```python
from fastapi import Depends

async def require_admin(user: User = Depends(get_current_user)) -> User:
    if user.role != "admin":
        raise HTTPException(403, "Admin access required")
    return user

@app.delete("/users/{user_id}")
async def delete_user(user_id: str, admin: User = Depends(require_admin)):
    await db.delete_user(user_id)
    return {"status": "deleted"}
```

### Object-level authorization (IDOR prevention)

This is one of the most commonly exploited vulnerabilities. Always verify the
requesting user owns or has access to the resource:

```python
@app.get("/documents/{doc_id}")
async def get_document(doc_id: str, user: User = Depends(get_current_user)):
    doc = await db.get_document(doc_id)
    if not doc:
        raise HTTPException(404, "Not found")

    # CRITICAL — verify ownership before returning
    if doc.owner_id != user.id and user.role != "admin":
        raise HTTPException(404, "Not found")  # 404, not 403 — don't confirm existence

    return doc
```

Returning 404 instead of 403 prevents attackers from enumerating which resources
exist.

### Postgres Row-Level Security

```sql
-- Enable RLS
ALTER TABLE documents ENABLE ROW LEVEL SECURITY;

-- Users see only their own documents
CREATE POLICY "users_own_documents" ON documents
    FOR ALL
    USING (owner_id = current_setting('app.current_user_id')::uuid);

-- Set user context per request (do this in middleware)
SET LOCAL app.current_user_id = '<user_uuid>';
```

RLS is defense in depth — application-level checks are still needed. RLS catches
the bugs your application code misses.

---

## 6. XSS Prevention

### Jinja2 autoescaping

```python
from fastapi.templating import Jinja2Templates

# Jinja2 autoescapes by default for .html files
templates = Jinja2Templates(directory="templates")
```

In templates, `{{ user_content }}` is auto-escaped. Only use `{{ content | safe }}`
or `Markup()` with content you've explicitly sanitized.

### Sanitizing user HTML

```python
import bleach

ALLOWED_TAGS = ["b", "i", "em", "strong", "p", "br", "ul", "ol", "li"]
ALLOWED_ATTRS = {}  # No attributes — prevents onclick, onerror, etc.

def sanitize_html(user_html: str) -> str:
    return bleach.clean(user_html, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRS)
```

### API responses returning HTML content

If your API returns HTML content for client-side rendering, sanitize server-side
before returning. Don't rely on the frontend to sanitize.

---

## 7. CSRF Protection

### FastAPI CSRF with cookies

```python
# pip install fastapi-csrf-protect
from fastapi_csrf_protect import CsrfProtect
from pydantic import BaseModel

class CsrfSettings(BaseModel):
    secret_key: str = settings.secret_key

@CsrfProtect.load_config
def get_csrf_config():
    return CsrfSettings()

@app.post("/transfer")
async def transfer_funds(request: Request, csrf_protect: CsrfProtect = Depends()):
    await csrf_protect.validate_csrf(request)
    # Process the transfer
```

For API-only backends with token auth (no cookies), CSRF protection is less
critical since the browser won't auto-attach credentials. But if you're using
session cookies for auth, CSRF protection is essential.

---

## 8. Rate Limiting

### slowapi for FastAPI

```python
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# General endpoint
@app.get("/api/items")
@limiter.limit("100/15minutes")
async def list_items(request: Request):
    ...

# Sensitive endpoint — stricter limit
@app.post("/api/login")
@limiter.limit("5/minute")
async def login(request: Request):
    ...

# Expensive operation
@app.post("/api/search")
@limiter.limit("10/minute")
async def search(request: Request):
    ...
```

### Rate limiting by authenticated user

```python
def get_rate_limit_key(request: Request) -> str:
    """Rate limit by user ID if authenticated, otherwise by IP."""
    token = request.cookies.get("access_token")
    if token:
        try:
            payload = jwt.decode(token, settings.secret_key, algorithms=["HS256"])
            return payload["sub"]
        except jwt.InvalidTokenError:
            pass
    return get_remote_address(request)

limiter = Limiter(key_func=get_rate_limit_key)
```

---

## 9. Data Exposure Prevention

### Pydantic response models (only return what's needed)

```python
class UserResponse(BaseModel):
    id: str
    email: str
    name: str
    # Note: no password_hash, no internal flags, no API keys

    model_config = {"from_attributes": True}

@app.get("/users/{user_id}", response_model=UserResponse)
async def get_user(user_id: str):
    # Even if the DB model has 20 fields, only these 3 are returned
    return await db.get_user(user_id)
```

### Safe logging

```python
import logging
import structlog

# DANGEROUS
logger.info("Login attempt", email=email, password=password)
logger.error("Payment failed", card_number=card_number)

# Safe — redact sensitive fields
logger.info("Login attempt", email=email, user_id=user_id)
logger.error("Payment failed", last_four=card[-4:], user_id=user_id)
```

### Safe error handling

```python
from fastapi import Request
from fastapi.responses import JSONResponse

@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    # Log full details server-side
    logger.exception("Unhandled error", path=request.url.path)
    # Return generic message to client
    return JSONResponse(
        status_code=500,
        content={"error": "An unexpected error occurred. Please try again."},
    )
```

---

## 10. Transport & Infrastructure

### Security headers middleware

```python
from starlette.middleware import Middleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "0"  # Disabled — CSP is preferred
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: https:; "
        "connect-src 'self' https://api.example.com"
    )
    return response
```

### CORS configuration

```python
from fastapi.middleware.cors import CORSMiddleware

# DANGEROUS — allows everything
app.add_middleware(CORSMiddleware, allow_origins=["*"])

# Safe — explicit origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,  # ["https://myapp.com"]
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)
```

---

## 11. Dependency Security

```bash
# Check for known vulnerabilities
pip audit

# Keep dependencies updated
pip install --upgrade <package>

# Pin exact versions in production
pip freeze > requirements.txt
# Or better — use pip-compile from pip-tools
pip-compile requirements.in --generate-hashes

# Always commit lock files
git add requirements.txt
```

Enable Dependabot or similar on your GitHub repo for automated vulnerability alerts.
