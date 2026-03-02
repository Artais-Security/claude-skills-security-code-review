# OWASP Top 10 (2021)

Deep-dive reference for the OWASP Top 10 with CWE mappings, attack patterns, and
detection guidance. Each category maps back to the checklist in SKILL.md — focus on
categories marked Partial or Gap where the checklist alone may miss things. Use CWE
IDs for compliance mapping. Complements offensive-perspective.md (attacker mindset)
with formal industry classification.

---

## Quick Reference: Checklist Mapping

| # | Category | Checklist Sections | Coverage | Key CWEs |
|---|----------|--------------------|----------|----------|
| A01 | Broken Access Control | 4 (Auth), 5 (Authz) | Strong | CWE-284, CWE-285, CWE-639 |
| A02 | Cryptographic Failures | 1 (Secrets), 9 (Data Exposure), 10 (Transport) | Partial | CWE-327, CWE-330, CWE-916 |
| A03 | Injection | 2 (Input Validation), 3 (Injection Prevention) | Strong | CWE-74, CWE-79, CWE-89 |
| A04 | Insecure Design | All (design-level) | **Gap** | CWE-362, CWE-501, CWE-656 |
| A05 | Security Misconfiguration | 10 (Transport & Infra) | Partial | CWE-16, CWE-611 |
| A06 | Vulnerable & Outdated Components | 10 (Transport & Infra) | Partial | CWE-937, CWE-1104 |
| A07 | Identification & Authentication Failures | 4 (Auth & Sessions) | Strong | CWE-287, CWE-384, CWE-613 |
| A08 | Software & Data Integrity Failures | — | **Gap** | CWE-345, CWE-494, CWE-502 |
| A09 | Security Logging & Monitoring Failures | 9 (Data Exposure, partial) | **Gap** | CWE-117, CWE-778 |
| A10 | Server-Side Request Forgery (SSRF) | 2 (Input Validation, oblique) | Partial | CWE-918 |

---

## A01: Broken Access Control

> **Checklist:** Sections 4, 5 | **Coverage:** Strong | **CWEs:** CWE-284, CWE-285, CWE-639

**What this covers:** Users acting outside intended permissions — accessing others'
data, elevating privileges, or bypassing access controls.

### Attack Patterns

- **IDOR.** Changing resource IDs in URLs or request bodies to access another user's
  data. UUIDs without authorization checks are just as vulnerable as integers.
- **Forced browsing.** Hitting admin pages or internal endpoints that lack auth checks:
  `/admin`, `/api/internal`, backup files, deployment artifacts.
- **CORS misconfiguration.** Wildcard or reflected `Access-Control-Allow-Origin` lets
  attackers read responses cross-origin from malicious sites.
- **Metadata manipulation.** Tampering with JWTs, hidden fields, or API parameters that
  encode permissions without server-side verification.

### Dangerous Patterns

```
// No ownership check — any authenticated user can access any record
function getDocument(request):
    return db.documents.findById(request.params.id)
```

### Secure Patterns

```
// Ownership enforced at the query level
function getDocument(request):
    doc = db.documents.findOne(id=request.params.id, owner_id=request.user.id)
    if not doc: return 404
    return doc
```

### Detection Tips

- Search for queries that take a resource ID from input without filtering by the
  authenticated user's ID.
- Look for endpoints missing auth middleware, especially internal routes added late.
- Check CORS for wildcard origins or dynamic origin reflection.

---

## A02: Cryptographic Failures

> **Checklist:** Sections 1, 9, 10 | **Coverage:** Partial | **CWEs:** CWE-327, CWE-330, CWE-916

**What this covers:** Weak or missing cryptography that exposes sensitive data —
bad algorithms, poor key management, insufficient randomness, missing encryption.

### Attack Patterns

- **Weak password hashing.** MD5, SHA-1, or unsalted SHA-256 for passwords. Only
  bcrypt, scrypt, or argon2 resist GPU-accelerated attacks.
- **Hardcoded keys.** Encryption keys or signing secrets in source code or config files
  checked into version control. Once found, all protected data is compromised.
- **Insufficient randomness.** `Math.random()`, `rand()`, or time-based seeds for
  tokens, reset links, or CSRF tokens — predictable and brute-forceable.
- **Missing TLS.** Serving sensitive data over HTTP, missing HSTS, or using outdated
  TLS versions with known vulnerabilities.

### Dangerous Patterns

```
password_hash = md5(password)
reset_token = str(timestamp) + str(user_id)
ENCRYPTION_KEY = "mySecretKey123"
```

### Secure Patterns

```
password_hash = bcrypt.hash(password, cost=12)
reset_token = crypto.randomBytes(32).toHex()
encryption_key = env.get("ENCRYPTION_KEY")
```

### Detection Tips

- Search for `md5`, `sha1`, `sha256` used on passwords.
- Look for `Math.random`, `rand()` used for tokens or secrets.
- Check for hardcoded strings that look like keys or connection strings.

---

## A03: Injection

> **Checklist:** Sections 2, 3 | **Coverage:** Strong | **CWEs:** CWE-74, CWE-79, CWE-89

**What this covers:** Untrusted data sent to an interpreter as part of a command or
query — SQL, NoSQL, OS command, LDAP, template, and expression language injection.

### Attack Patterns

- **SQL injection beyond login forms.** Hides in search filters, sort params, reporting
  queries, and bulk operations where developers drop to raw SQL.
- **NoSQL injection.** MongoDB `$gt`/`$ne`/`$regex` operators in JSON bodies bypass
  auth when queries are built from unsanitized input.
- **SSTI.** User input rendered directly in template engines. If `{{7*7}}` produces
  `49`, full RCE is typically one step away.
- **OS command injection.** User input reaching `exec()`, `system()`, `popen()` — common
  in image processing, file conversion, and PDF generation.

### Dangerous Patterns

```
query = "SELECT * FROM users WHERE name = '" + username + "'"
template = Template("Hello " + user_input)
exec("convert " + uploaded_filename + " output.png")
```

### Secure Patterns

```
db.execute("SELECT * FROM users WHERE name = ?", [username])
Template("Hello {{ name }}").render(name=user_input)
subprocess.run(["convert", validated_filename, "output.png"], shell=False)
```

### Detection Tips

- Search for string concatenation/interpolation inside SQL, especially in sort,
  filter, and reporting code paths.
- Look for `shell=True`, `exec()`, `system()`, `eval()` with variable input.
- Check template rendering for user input passed as the template itself.

---

## A04: Insecure Design

> **Checklist:** All sections (design-level) | **Coverage:** **Gap** | **CWEs:** CWE-362, CWE-501, CWE-656

**What this covers:** Flaws in the design itself — not implementation bugs, but missing
or ineffective controls that should have been designed in from the start.

### Attack Patterns

- **Business logic abuse.** Applying discount codes multiple times, skipping checkout
  steps, manipulating client-trusted price/quantity fields. These aren't injection or
  auth bugs — they're design oversights.
- **Race conditions (TOCTOU).** Concurrent requests exploiting time-of-check-to-time-of-use
  gaps: double-spending balances, redeeming single-use vouchers twice, racing uniqueness
  checks against inserts.
- **Client-side trust.** Security decisions based on client-controlled data: trusting
  client-calculated totals, relying on hidden fields for pricing, enforcing access only
  through UI visibility.
- **Missing threat modeling.** Critical features (password reset, payment, data export)
  shipping without abuse scenarios considered.

### Dangerous / Secure Patterns

```
// DANGEROUS: Client-controlled pricing
charge(request.user, request.body.total)

// SECURE: Server-side price calculation
items = db.getCartItems(request.user.id)
charge(request.user, calculateTotal(items))

// DANGEROUS: Race condition — no concurrency control
voucher = db.findVoucher(code); if voucher.used: return error()
applyDiscount(...); voucher.used = true; db.save(voucher)

// SECURE: Atomic redemption
result = db.atomicUpdate("vouchers",
    filter={code: code, used: false}, update={used: true})
if result.matchedCount == 0: return error("Invalid or redeemed")
```

### Detection Tips

- Look for values affecting pricing/permissions that come from client requests.
- Search for read-then-write sequences without transactions or atomic operations.
- Check multi-step processes for steps skippable by calling later endpoints directly.

---

## A05: Security Misconfiguration

> **Checklist:** Section 10 | **Coverage:** Partial | **CWEs:** CWE-16, CWE-611

**What this covers:** Insecure defaults, incomplete configs, verbose error messages,
unnecessary features enabled, and missing security hardening.

### Attack Patterns

- **Debug mode in production.** Django, Flask, Rails debug modes expose stack traces,
  environment variables, SQL queries, and sometimes interactive consoles.
- **XXE processing.** XML parsers with external entity processing enabled (often the
  default) allow file reads, SSRF, and denial of service.
- **Default credentials.** Admin panels, databases, and monitoring tools with
  factory-default passwords. Automated scanners check these first.
- **Directory listing.** Web servers exposing directory contents, revealing backup files,
  config files, or source code.

### Dangerous Patterns

```
app = createApp({debug: true, verbose_errors: true})
parser = XMLParser()  // external entities enabled by default
app.use(cors({origin: "*", credentials: true}))
```

### Secure Patterns

```
app = createApp({debug: env.get("DEBUG", false) && !isProduction()})
parser = XMLParser(resolve_entities=false, no_network=true)
app.use(cors({origin: ["https://app.example.com"], credentials: true}))
```

### Detection Tips

- Search for `debug`/`DEBUG`/`verbose` settings — verify they're off in production.
- Look for XML parsing without explicitly disabling external entities.
- Check for default credentials in config files and Docker compose files.

---

## A06: Vulnerable and Outdated Components

> **Checklist:** Section 10 | **Coverage:** Partial | **CWEs:** CWE-937, CWE-1104

**What this covers:** Libraries, frameworks, or components with known vulnerabilities.
Also covers supply chain attacks: dependency confusion, typosquatting, and compromised
build pipelines.

### Attack Patterns

- **Known CVE exploitation.** Running a library version with a published CVE.
  Attackers fingerprint versions via HTTP headers, JS bundles, or public repos.
- **Dependency confusion.** Publishing a malicious public package with the same name as
  a private internal package — the package manager may install the public one.
- **Typosquatting.** Malicious packages with names similar to popular ones (`reqeusts`
  vs `requests`). Install scripts run arbitrary code.
- **Transitive vulnerabilities.** A direct dependency is secure, but one of *its*
  dependencies has a critical vulnerability — invisible without deep tree inspection.

### Dangerous Patterns

```
// Loose version ranges, no lock file
"dependencies": { "some-lib": "^2.0.0" }
// No dependency auditing in CI, no SBOM generated
```

### Secure Patterns

```
npm ci                    // installs exactly from lock file
npm audit / pip audit     // regular vulnerability scanning
"auth-library": "2.3.1"  // exact pinning for critical packages
```

### Detection Tips

- Check for missing lock files (`package-lock.json`, `Pipfile.lock`, `go.sum`).
- Run `npm audit`, `pip audit`, or equivalent — even low-severity issues can chain.
- Verify CI/CD includes dependency scanning as a gate, not just a report.

---

## A07: Identification and Authentication Failures

> **Checklist:** Section 4 | **Coverage:** Strong | **CWEs:** CWE-287, CWE-384, CWE-613

**What this covers:** Failures in confirming identity, managing sessions, and protecting
authentication mechanisms from attack.

### Attack Patterns

- **Credential stuffing.** Leaked username/password pairs from other breaches tried
  against your site. Users reuse passwords — without detection, these work directly.
- **Session fixation.** Attacker sets a known session ID before the victim logs in. If
  the session ID isn't regenerated on authentication, the attacker hijacks it.
- **Brute force / password spraying.** Many passwords against one account, or one
  common password against many accounts. Succeeds without rate limiting.
- **Missing session invalidation.** Tokens remain valid after logout or password change.
  A captured token grants indefinite access.

### Dangerous Patterns

```
// Session not regenerated — fixation risk
function login(request):
    if verifyPassword(request.body.password, user.hash):
        session.user = user  // same session ID as before auth
        return success()
```

### Secure Patterns

```
function login(request):
    if verifyPassword(request.body.password, user.hash):
        session.regenerate()  // new session ID
        session.user = user
        return success()
```

### Detection Tips

- Check whether session IDs regenerate after login.
- Verify logout invalidates sessions server-side, not just client-side.
- Look for missing rate limiting on login, registration, and password reset.

---

## A08: Software and Data Integrity Failures

> **Checklist:** Not directly covered | **Coverage:** **Gap** | **CWEs:** CWE-345, CWE-494, CWE-502

**What this covers:** Missing integrity protections — untrusted deserialization,
unsigned updates, insecure CI/CD pipelines, and absent integrity checks.

### Attack Patterns

- **Insecure deserialization.** Formats that allow arbitrary object instantiation
  (Python `pickle`, Java `ObjectInputStream`, PHP `unserialize`, Ruby `Marshal.load`)
  achieve RCE when processing attacker-controlled data.
- **CI/CD pipeline poisoning.** `pull_request_target` workflows that run untrusted PR
  code with repo secrets, exposed build logs, or unscoped runners.
- **Missing SRI.** CDN scripts without `integrity` attributes — a compromised CDN
  injects malicious code into every user's browser.
- **Data tampering.** Serialized data in cookies or hidden fields without HMAC
  verification — attackers freely modify prices, roles, permissions.

### Dangerous / Secure Patterns

```
// DANGEROUS: Deserialization RCE
user_prefs = pickle.loads(request.cookies.get("prefs"))

// SECURE: Safe format with validation
user_prefs = json.loads(request.cookies.get("prefs"))
validate_schema(user_prefs, PREFS_SCHEMA)

// DANGEROUS: No SRI
<script src="https://cdn.example.com/lib.js"></script>

// SECURE: Subresource integrity
<script src="https://cdn.example.com/lib.js"
        integrity="sha384-abc123..." crossorigin="anonymous"></script>
```

### Detection Tips

- Search for `pickle.loads`, `yaml.load` (without SafeLoader), `ObjectInputStream`,
  `unserialize`, `Marshal.load` on untrusted input.
- Check `<script>` and `<link>` tags for missing `integrity` attributes.
- Review CI/CD workflows for `pull_request_target` triggers.

---

## A09: Security Logging and Monitoring Failures

> **Checklist:** Section 9 (partial) | **Coverage:** **Gap** | **CWEs:** CWE-117, CWE-778

**What this covers:** Insufficient logging of security events, missing alerting, log
injection, and inability to detect or investigate breaches.

### Attack Patterns

- **Missing audit trail.** No logging of auth attempts, authorization failures, or admin
  actions. Breaches go undetected; forensics are impossible.
- **Log injection.** User input written directly into logs without sanitization.
  Attackers inject newlines and fake entries to cover tracks or exploit log viewers.
- **Secrets in logs.** Logging full request bodies that contain passwords, tokens, or
  PII. Logs often have weaker access controls than the application database.
- **No alerting.** Failed login bursts, unusual data exports, and privilege escalation
  attempts go unnoticed without configured thresholds.

### Dangerous / Secure Patterns

```
// DANGEROUS: No auth logging — brute force invisible
function login(request):
    user = authenticate(request.body)
    if user: return createSession(user)
    return error("Invalid credentials")

// SECURE: Structured security event logging with redaction
function login(request):
    user = authenticate(request.body)
    if user:
        auditLog.info("auth.login.success", {userId: user.id, ip: request.ip})
        return createSession(user)
    auditLog.warn("auth.login.failure", {
        username: sanitizeForLog(request.body.username), ip: request.ip})
    return error("Invalid credentials")

// DANGEROUS: log.info("Login for: " + username)       // newline injection
// SECURE:   log.info("login_attempt", {user: sanitize(username)})
// DANGEROUS: log.debug("Request: " + json.stringify(body)) // logs passwords
// SECURE:   redact ["password","token","ssn"] before logging
```

### Detection Tips

- Check auth and payment flows for logging — no `log` call on failure means attacks
  are invisible.
- Search for `log.*request.body` patterns that may dump sensitive fields.
- Look for user input in log messages without sanitization.

---

## A10: Server-Side Request Forgery (SSRF)

> **Checklist:** Section 2 (oblique) | **Coverage:** Partial | **CWEs:** CWE-918

**What this covers:** Tricking the server into making requests to unintended
destinations — internal services, cloud metadata, or arbitrary hosts — via
user-controlled URLs.

### Attack Patterns

- **Cloud metadata theft.** Fetching `http://169.254.169.254/latest/meta-data/` returns
  IAM credentials with whatever permissions the instance role grants.
- **DNS rebinding.** Server validates a URL's IP, but DNS changes between validation
  and fetch to point at an internal address.
- **Protocol smuggling.** `gopher://`, `file://`, `dict://` URLs interact with internal
  services (Redis, SMTP) via line-based protocols.
- **Redirect bypass.** Validated URL redirects to an internal address, bypassing the
  initial allowlist check.

### Dangerous / Secure Patterns

```
// DANGEROUS: Unvalidated URL fetch
httpClient.get(request.body.url)

// DANGEROUS: Substring check — attacker.com?x=example.com bypasses
if "example.com" in url: httpClient.get(url)

// SECURE: Protocol allowlist + DNS resolution + IP check
url = parseUrl(request.body.url)
if url.scheme not in ["http", "https"]: return error()
if isPrivateIP(dns.resolve(url.hostname)): return error()
if url.hostname not in ALLOWED_DOMAINS: return error()
httpClient.get(url, followRedirects=false, timeout=5)
```

### Detection Tips

- Search for HTTP client calls where the URL comes from user input.
- Look for webhook, URL preview, image-from-URL, and PDF generation features.
- Check if outbound requests disable redirect following and block private IPs.

---

## Cross-Cutting Concerns

**Defense in depth.** No single control is sufficient. Combine input validation,
parameterized queries, output encoding, and CSP headers.

**Secure defaults.** If security requires explicit opt-in, it will be forgotten.
Auto-escaping, parameterized queries, and httpOnly cookies should be the defaults.

**Least privilege.** Every component gets minimum necessary permissions. A compromised
read-only DB user is far less damaging than a full admin.

**Fail closed.** A crashed auth middleware should return 500, not silently pass through.

---

## Resources

- [OWASP Top 10 (2021)](https://owasp.org/Top10/) — official project page
- [OWASP Top 10 CWE Mappings](https://owasp.org/Top10/A00_2021-How_to_use_the_OWASP_Top_10_as_a_Standard/) — methodology and CWE details
- [CWE/SANS Top 25](https://cwe.mitre.org/top25/) | [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/) | [Cheat Sheets](https://cheatsheetseries.owasp.org/)
