# Python Security Patterns (General / Stdlib)

Security patterns for any Python project — scripts, CLI tools, Flask, Django, data pipelines.
Each section maps to the corresponding section in the main SKILL.md.
For FastAPI / SQLAlchemy / Pydantic patterns, see `python-fastapi.md`.

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

### Cryptographically secure random values

```python
import secrets

api_token = secrets.token_urlsafe(32)   # URL-safe base64, 256 bits
session_id = secrets.token_hex(32)      # hex string, 256 bits
otp_code = secrets.randbelow(1_000_000) # 6-digit OTP (0–999999)

import random
# DANGEROUS — random is a Mersenne Twister PRNG, predictable
token = random.getrandbits(128)   # Attacker can recover state from 624 outputs
code = random.randint(0, 999999)  # Predictable OTP
```

`random` is for simulations. `secrets` is for anything security-relevant:
tokens, passwords, OTPs, nonces, API keys.

### Loading and validating secrets from environment

```python
import os, sys

REQUIRED = ("DATABASE_URL", "SECRET_KEY", "API_TOKEN")

def load_secrets() -> dict[str, str]:
    """Validate at startup — fail fast if missing."""
    missing = [k for k in REQUIRED if not os.environ.get(k)]
    if missing:
        sys.exit(f"FATAL: missing env vars: {', '.join(missing)}")
    return {k: os.environ[k] for k in REQUIRED}

api_key = os.getenv("API_KEY")  # RISKY — silent None, fails later
API_KEY = "sk-proj-xxxxx"       # DANGEROUS — secrets in source code
```

---

## 2. Input Validation

### os.path.join absolute path bypass

```python
os.path.join("/app/uploads", "/etc/passwd")  # DANGEROUS — result is "/etc/passwd"!

from pathlib import Path
UPLOAD_DIR = Path("/app/uploads").resolve()

def safe_path(user_filename: str) -> Path:
    clean_name = Path(user_filename).name  # basename only — strips ../ and /
    if not clean_name or clean_name == ".":
        raise ValueError("Invalid filename")
    target = (UPLOAD_DIR / clean_name).resolve()
    if not target.is_relative_to(UPLOAD_DIR):
        raise ValueError("Path traversal attempt")
    return target
```

### assert is removed with -O

```python
# DANGEROUS — assert statements are stripped when Python runs with -O
assert amount > 0           # Gone with python -O!
assert amount <= balance    # Gone with python -O!

# Safe — explicit checks survive optimization
if amount <= 0:
    raise ValueError("Amount must be positive")
```

Never use `assert` for input validation or security checks.

### re.fullmatch vs re.match

```python
import re
PAT = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")

re.match(PAT, "ok@ex.com\n<script>")     # DANGEROUS — matches (no end anchor)
re.fullmatch(PAT, "ok@ex.com\n<script>")  # Safe — None (anchors both ends)
```

### File upload validation

```python
import magic  # python-magic — detect MIME from content, not claimed Content-Type
ALLOWED_MIME = {"image/jpeg", "image/png", "image/gif"}
ALLOWED_EXT = {".jpg", ".jpeg", ".png", ".gif"}

def validate_upload(content: bytes, filename: str) -> str:
    if len(content) > 5 * 1024 * 1024:
        raise ValueError("File too large")
    if magic.from_buffer(content, mime=True) not in ALLOWED_MIME:
        raise ValueError("Invalid file type")
    ext = Path(filename).suffix.lower()
    if ext not in ALLOWED_EXT:
        raise ValueError("Invalid extension")
    return f"{uuid4().hex}{ext}"  # safe filename — never trust user-provided names
```

---

## 3. Injection Prevention

### SQL injection — parameterized queries by driver

```python
# sqlite3 — use ? placeholders
conn.execute("SELECT * FROM users WHERE email = ?", (user_email,))

# psycopg2 (Postgres) — use %s placeholders (driver-processed, NOT Python's %)
cur.execute("SELECT * FROM users WHERE email = %s", (user_email,))
cur.execute("SELECT * FROM users WHERE email = %(email)s", {"email": email})

# PyMySQL — use %s placeholders
cur.execute("SELECT * FROM users WHERE email = %s", (user_email,))

# DANGEROUS — string formatting in SQL (all drivers)
conn.execute(f"SELECT * FROM users WHERE email = '{user_email}'")         # SQLi!
cur.execute("SELECT * FROM users WHERE email = '%s'" % user_email)        # SQLi!
```

psycopg2's `%s` is a driver placeholder, not Python's `%` operator. Never mix them.

### Dynamic column/table names — use allowlists

```python
ALLOWED_SORT = {"name", "created_at", "email"}

def get_users_sorted(conn, sort_by: str):
    if sort_by not in ALLOWED_SORT:
        raise ValueError("Invalid sort column")
    return conn.execute(f"SELECT * FROM users ORDER BY {sort_by}")  # Safe — from known set
```

### eval / exec / compile — code injection

```python
# DANGEROUS — arbitrary code execution
result = eval(user_input)                  # Full Python expression
exec(user_input)                           # Full Python statements
obj = __import__(user_input)               # Arbitrary module loading
eval(user_input, {"__builtins__": {}})     # Bypassable — don't rely on this

# Safe alternative for literal values only
import ast
value = ast.literal_eval(user_input)  # Only strings, numbers, tuples, lists, dicts, bools, None
```

There is no safe way to `eval` untrusted input. Use a purpose-built parser.

### Deserialization — pickle, yaml, marshal

```python
import pickle
data = pickle.loads(user_bytes)   # DANGEROUS — executes arbitrary code on load (RCE!)

import yaml
data = yaml.load(user_input)                          # DANGEROUS — RCE with crafted YAML
data = yaml.load(user_input, Loader=yaml.FullLoader)  # DANGEROUS — still allows some objects
data = yaml.safe_load(user_input)                      # Safe — basic types only

import marshal
data = marshal.loads(user_bytes)  # DANGEROUS — never use on untrusted input
```

Rule: never deserialize untrusted data with `pickle`, `marshal`, or
`yaml.load`. Use JSON, `yaml.safe_load`, or protocol buffers.

### XML External Entity (XXE) injection

```python
from xml.etree.ElementTree import parse
tree = parse(user_xml)  # DANGEROUS — XXE, SSRF, billion-laughs DoS

import defusedxml.ElementTree as ET
tree = ET.parse(user_xml)          # Safe — blocks XXE, entity expansion, DTD
root = ET.fromstring(user_string)  # Safe
```

Always use `defusedxml` instead of stdlib `xml.*` for untrusted XML.

### Command injection — subprocess

```python
import subprocess, shlex

subprocess.run(f"convert {user_file} out.png", shell=True)             # DANGEROUS
subprocess.run(["convert", user_file, "out.png"], check=True)          # Safe — no shell
subprocess.run(f"convert {shlex.quote(user_file)} out.png", shell=True)  # Last resort
```

Prefer `shell=False` (the default) with arguments as a list.

---

## 4. Authentication & Sessions

### Password hashing — bcrypt (direct, without passlib)

```python
import bcrypt

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())
```

### Password hashing — argon2

```python
from argon2 import PasswordHasher
ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)

hashed = ph.hash(password)
ph.verify(hashed, password)  # Returns True or raises VerifyMismatchError
```

argon2 is the Password Hashing Competition winner. Prefer for new projects.

### Timing-safe comparison

```python
import hmac

# DANGEROUS — == short-circuits on first differing byte (timing side-channel)
provided == expected

# Safe — constant-time comparison
hmac.compare_digest(provided.encode(), expected.encode())
```

Use `hmac.compare_digest()` for tokens, API keys, CSRF tokens, or any secret.

### HMAC message signing

```python
import hmac, hashlib

def sign(key: bytes, message: bytes) -> str:
    return hmac.new(key, message, hashlib.sha256).hexdigest()

def verify(key: bytes, message: bytes, signature: str) -> bool:
    expected = hmac.new(key, message, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)
```

Use for webhook signatures, signed URLs, and message integrity.

### JWT in httpOnly cookies

```python
import jwt
from datetime import datetime, timedelta, timezone

def create_token(user_id: str, secret: str, expires_min: int = 60) -> str:
    return jwt.encode({
        "sub": user_id,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=expires_min),
    }, secret, algorithm="HS256")

# Cookie flags: httponly=True, secure=True, samesite="Strict", max_age=3600
```

---

## 5. Authorization

### Decorator-based role checks

```python
import functools

def require_role(*roles):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            user = get_current_user()  # framework-specific
            if not user or user.role not in roles:
                raise PermissionError("Access denied")
            return func(*args, **kwargs)
        return wrapper
    return decorator

@require_role("admin")
def delete_user(user_id): ...
```

### Object-level authorization (IDOR prevention)

```python
def get_document(doc_id: str, user: User) -> Document:
    doc = db.get_document(doc_id)
    if not doc:
        raise NotFoundError("Not found")
    # CRITICAL — verify ownership before returning
    if doc.owner_id != user.id and user.role != "admin":
        raise NotFoundError("Not found")  # 404, not 403 — don't confirm existence
    return doc
```

### File system authorization

```python
USER_DATA_ROOT = Path("/data/users")

def get_user_file(user_id: str, filename: str) -> Path:
    user_dir = (USER_DATA_ROOT / user_id).resolve()
    target = (user_dir / Path(filename).name).resolve()
    if not target.is_relative_to(user_dir):
        raise PermissionError("Access denied")
    return target
```

---

## 6. XSS Prevention

### html.escape from stdlib

```python
import html

safe = html.escape(user_input)
# "<script>alert(1)</script>" → "&lt;script&gt;alert(1)&lt;/script&gt;"

output = f"<p>{user_input}</p>"  # DANGEROUS — XSS if user_input contains HTML/JS
```

### Jinja2 autoescaping (standalone)

```python
from jinja2 import Environment, FileSystemLoader, select_autoescape

env = Environment(  # Safe — autoescape enabled
    loader=FileSystemLoader("templates"),
    autoescape=select_autoescape(["html", "htm", "xml"]),
)

env = Environment(loader=FileSystemLoader("templates"))  # DANGEROUS — autoescape OFF!
```

Standalone Jinja2 has autoescaping **disabled** by default. Always pass
`select_autoescape`.

### Sanitizing user HTML

```python
import bleach  # or nh3

ALLOWED_TAGS = ["b", "i", "em", "strong", "p", "br", "ul", "ol", "li"]

def sanitize_html(user_html: str) -> str:
    return bleach.clean(user_html, tags=ALLOWED_TAGS, attributes={})
```

### URL scheme validation

```python
from urllib.parse import urlparse
ALLOWED_SCHEMES = {"http", "https", "mailto"}

def validate_url(url: str) -> str:
    if urlparse(url).scheme.lower() not in ALLOWED_SCHEMES:
        raise ValueError("Disallowed URL scheme")  # blocks javascript:, data:, etc.
    return url
```

---

## 7. CSRF Protection

### Double-submit cookie pattern

```python
import secrets, hmac

def generate_csrf_token() -> str:
    return secrets.token_urlsafe(32)

def validate_csrf(cookie_token: str, form_token: str) -> bool:
    if not cookie_token or not form_token:
        return False
    return hmac.compare_digest(cookie_token, form_token)
```

### Origin / Referer header validation

```python
from urllib.parse import urlparse

ALLOWED_ORIGINS = {"https://myapp.com", "https://www.myapp.com"}

def validate_origin(headers: dict) -> bool:
    origin = headers.get("Origin")
    if origin:
        return origin in ALLOWED_ORIGINS
    referer = headers.get("Referer")
    if referer:
        p = urlparse(referer)
        return f"{p.scheme}://{p.netloc}" in ALLOWED_ORIGINS
    return False  # No Origin or Referer — reject state-changing requests
```

---

## 8. Rate Limiting

### In-memory rate limiter with stdlib

```python
import time, threading
from collections import defaultdict

class RateLimiter:
    """Sliding-window rate limiter using time.monotonic()."""
    def __init__(self, max_requests: int, window_seconds: float):
        self.max_requests = max_requests
        self.window = window_seconds
        self._lock = threading.Lock()
        self._requests: dict[str, list[float]] = defaultdict(list)

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            self._requests[key] = [
                t for t in self._requests[key] if now - t < self.window
            ]
            if len(self._requests[key]) >= self.max_requests:
                return False
            self._requests[key].append(now)
            return True

general_limiter = RateLimiter(max_requests=100, window_seconds=900)  # 100/15min
auth_limiter = RateLimiter(max_requests=5, window_seconds=60)        # 5/min
```

Use `time.monotonic()`, not `time.time()` — wall-clock time can jump backwards
(NTP, DST) and break rate limiting.

For multi-process/multi-server deployments, use Redis (e.g., `limits` library).

---

## 9. Data Exposure Prevention

### Logging format string attack

```python
import logging
logger = logging.getLogger(__name__)

# DANGEROUS — user input as the format string itself
logger.info(user_input)  # %(name)s, %(filename)s in input leak LogRecord fields

# Safe — user data as arguments
logger.info("User action: %s", user_input)
```

When `user_input` is the format string, attackers can trigger exceptions or
extract data from the `LogRecord` via `%(name)s`, `%(filename)s`, etc.

### __repr__ / __str__ leaking sensitive data

```python
class User:
    def __init__(self, name, email, ssn):
        self.name = name
        self.email = email
        self.ssn = ssn
    # DANGEROUS — default repr exposes all attributes in logs/tracebacks

    def __repr__(self):  # Safe — explicit repr excludes sensitive fields
        return f"User(name={self.name!r}, email={self.email!r})"
```

### Safe error responses

```python
logger.exception("Unhandled error")                    # Full details server-side
return {"error": "An unexpected error occurred"}, 500  # Generic message to client

return {"error": str(exc)}, 500               # DANGEROUS — SQL queries, file paths
return {"error": traceback.format_exc()}, 500  # DANGEROUS — full stack trace
```

### Filtering API responses

```python
from dataclasses import dataclass, asdict

@dataclass
class UserRecord:
    id: str
    email: str
    name: str
    password_hash: str  # Never expose these in API responses
    stripe_id: str

PUBLIC_FIELDS = {"id", "email", "name"}
user_response = lambda u: {k: v for k, v in asdict(u).items() if k in PUBLIC_FIELDS}
```

---

## 10. Transport & Infrastructure

### TLS certificate verification

```python
import ssl
ctx = ssl.create_default_context()  # Safe — TLS 1.2+, cert verification, secure ciphers
ctx.check_hostname = False          # DANGEROUS
ctx.verify_mode = ssl.CERT_NONE     # DANGEROUS — MITM possible

import requests
requests.get(url, verify=False)  # DANGEROUS — disables cert verification
requests.get(url)                # Safe — verify=True by default
requests.get(url, verify="/path/to/ca-bundle.crt")  # Safe — custom CA

import urllib3
urllib3.disable_warnings()  # DANGEROUS — hiding the symptom, not fixing the cause
```

If you find `verify=False`, investigate. Self-signed certs and corporate
proxies have proper solutions (custom CA bundles).

### Secure temporary files

```python
import tempfile

open("/tmp/myapp_data.txt", "w")  # DANGEROUS — predictable name, symlink attack

# Safe — unpredictable name, 0o600 permissions, auto-cleanup
with tempfile.NamedTemporaryFile(mode="w", suffix=".txt") as f:
    f.write(sensitive_data)

with tempfile.TemporaryDirectory() as tmpdir:  # Safe — secure temp directory
    (Path(tmpdir) / "data.txt").write_text(sensitive_data)
```

### Security headers

Apply via framework middleware: `X-Content-Type-Options: nosniff`,
`X-Frame-Options: DENY`, `Strict-Transport-Security: max-age=31536000`,
`Content-Security-Policy: default-src 'self'`, `Referrer-Policy: strict-origin-when-cross-origin`.

---

## 11. Dependency Security

```bash
# bandit — Python-specific static security analysis
bandit -r src/

# pip-audit — check installed packages for known vulnerabilities
pip-audit

# safety — check requirements files
safety check -r requirements.txt
```

### Pinning dependencies

```bash
# pip-tools — compile exact versions with hashes
pip-compile requirements.in --generate-hashes

# Poetry
poetry lock && poetry install
```

Always commit lock files (`requirements.txt` with pins, `poetry.lock`,
`Pipfile.lock`). Without them, builds are vulnerable to dependency confusion.

Enable Dependabot or similar for automated vulnerability alerts.
