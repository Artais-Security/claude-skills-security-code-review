# Offensive Security Perspective

What pentesters actually look for, what gets exploited first, and how attackers
chain findings into impact. Read this alongside the universal checklist to understand
*why* each control matters — not in theory, but because these are the things that
get popped in real assessments.

## Table of Contents

1. [What Gets Exploited First](#what-gets-exploited-first)
2. [The Attacker's Playbook by Category](#the-attackers-playbook-by-category)
3. [Vulnerability Chains](#vulnerability-chains)
4. [Common Assessment Findings by Severity](#common-assessment-findings-by-severity)
5. [Red Flags in Code Review](#red-flags-in-code-review)
6. [Questions to Ask Every Endpoint](#questions-to-ask-every-endpoint)

---

## What Gets Exploited First

In a real engagement, pentesters don't work through a checklist top-to-bottom.
They go for the highest-value, lowest-effort targets first. Here's the typical
priority order:

1. **Exposed secrets** — Hardcoded API keys, leaked `.env` files, secrets in
   git history, credentials in client-side bundles. This is often game over
   in minutes. Automated tools like truffleHog and gitleaks find these instantly.

2. **Broken authorization (IDOR)** — Can user A access user B's data by changing
   an ID in the URL or request body? This is the single most common high-severity
   finding in application assessments. It's easy to test and frequently missed
   because developers test their own accounts and never think to swap IDs.

3. **Missing authentication on internal endpoints** — Endpoints that were "only
   for internal use" but are reachable from the internet. Admin panels, debug
   endpoints, health checks that leak config, API routes that forgot the auth
   middleware.

4. **SQL injection in search and filter parameters** — Login forms get tested by
   everyone. But sort parameters, search queries, date range filters, and
   CSV export endpoints are where injection actually lives in modern apps.

5. **Privilege escalation via parameter tampering** — Changing `role: "user"` to
   `role: "admin"` in a signup request, or `is_admin: true` in a profile update.
   Mass assignment vulnerabilities where the API blindly accepts whatever fields
   the client sends.

6. **SSRF in integrations** — Webhook URLs, image fetchers, PDF generators, URL
   preview features — anything that makes the server fetch a URL the user
   controls. This can pivot to internal services, cloud metadata endpoints, and
   credential theft.

7. **Default credentials and misconfigurations** — Default admin passwords on
   dashboards, debug mode enabled in production, verbose error pages, open
   Swagger/OpenAPI docs with "Try it out" enabled against production.

---

## The Attacker's Playbook by Category

### Secrets Management — What Attackers Actually Do

The first thing a pentester does with a new target:

- **Check the JavaScript bundle** — Search for API keys, tokens, and endpoints
  in the client-side JS. `NEXT_PUBLIC_` variables are visible to everyone. Tools
  like `LinkFinder` automate this.
- **Search git history** — Even if secrets are removed from the current commit,
  `git log -p` reveals everything. Rotating a secret without changing git history
  means the old secret still works.
- **Check common paths** — `/.env`, `/config.json`, `/api/debug`, `/.git/config`,
  `/server-status`. You'd be surprised how often these are accessible.
- **Check cloud metadata** — If SSRF exists, `http://169.254.169.254/latest/meta-data/`
  gives AWS credentials. Similar endpoints exist for GCP and Azure.

**What this means for your code:** Validate that secrets aren't just absent from
source code, but also absent from built artifacts, error messages, logs, and
anywhere an HTTP response could leak them. Test by actually curling your endpoints
and reading the responses carefully.

### Authorization — How IDOR Gets Exploited

IDOR is the bread and butter of application pentesting. The attack is trivial:

1. Create two test accounts (user A and user B)
2. Perform an action as user A, capture the request
3. Replay the request but with user B's session
4. If user B's data comes back, that's an IDOR

What makes this deadly is that it scales. Once you find one broken endpoint,
you can often enumerate every user's data with a simple loop.

**Common IDOR patterns pentesters check:**
- `GET /api/users/123/documents` — change 123 to 124
- `GET /api/invoices?user_id=123` — change the query param
- `PUT /api/profile` with another user's ID in the body
- `DELETE /api/comments/456` — can you delete someone else's comment?
- Sequential integer IDs are worse than UUIDs (easier to enumerate), but UUIDs
  aren't a fix — they're just obscurity. Authorization checks are the fix.

**What this means for your code:** Every endpoint that takes a resource ID needs
an ownership check. Not just "is the user authenticated?" but "does this
authenticated user have access to *this specific resource*?" Test by actually
making requests with swapped IDs.

### Input Validation — Where Injection Actually Hides

Modern ORMs prevent basic SQL injection in simple queries. Pentesters know this,
so they target the places where developers drop down to raw queries or build
dynamic logic:

- **Sort and order parameters** — `?sort=name` becomes `?sort=name;DROP TABLE users--`
- **Search with LIKE clauses** — raw `LIKE '%{input}%'` patterns
- **Bulk operations** — Import CSV, bulk update endpoints that iterate user input
- **GraphQL** — Nested queries, field injection, introspection left enabled
- **JSON fields** — Postgres JSONB queries built from user input
- **Reporting/export endpoints** — Often built hastily, use raw queries for
  performance, skip the ORM

Beyond SQL, attackers test for:
- **SSTI (Server-Side Template Injection)** — User input rendered in templates
  without escaping. Test with `{{7*7}}` — if you see `49`, it's injectable.
- **Command injection** — Anywhere user input reaches a shell: filename
  processing, image conversion, PDF generation, log parsers.
- **Path traversal** — `../../etc/passwd` in file upload paths, download
  endpoints, or include mechanisms.
- **Header injection** — User input in HTTP headers (especially `Location` for
  redirects, `Set-Cookie`, or logging).

**What this means for your code:** Don't just validate the obvious inputs (login
forms, signup). Validate *every* parameter — especially the ones in sorting,
filtering, pagination, and export features that developers often treat as "safe"
because they're not user-facing text fields.

### Authentication — How Sessions Get Hijacked

- **Token in localStorage** — One XSS vulnerability and the attacker has the
  session token. They can exfiltrate it to their server and use it from anywhere.
  httpOnly cookies prevent this because JavaScript can't read them at all.
- **No session invalidation** — User clicks "logout" but the token is still
  valid. Attacker who captured the token earlier can keep using it.
- **Predictable reset tokens** — Sequential IDs, timestamps, or short random
  strings. Should be cryptographically random and single-use.
- **Username enumeration** — "User not found" vs "Incorrect password" tells the
  attacker which emails are registered. This feeds credential stuffing attacks.
- **Missing brute-force protection** — No rate limit on login means an attacker
  can try thousands of passwords. Even with rate limits, check they can't be
  bypassed by rotating IPs or using different headers.

### Rate Limiting — How It Gets Bypassed

Pentesters routinely bypass rate limiting. Common techniques:

- **IP rotation** — Trivial with cloud functions or proxy services
- **Header manipulation** — Adding `X-Forwarded-For`, `X-Real-IP`,
  `X-Originating-IP` headers. If your rate limiter trusts these without
  validation, it's defeated.
- **Parameter variation** — Adding extra params, changing case, using URL
  encoding (`/api/login` vs `/api/login/` vs `/api/Login`)
- **Distributed attacks** — Spreading requests across multiple IPs to stay
  under per-IP limits

**What this means for your code:** Rate limiting is defense in depth, not a
primary control. Combine it with proper authentication, account lockouts, and
monitoring. Test your rate limits by actually sending requests — verify they
trigger and that the obvious bypasses don't work.

### SSRF — The Underestimated Vulnerability

Server-Side Request Forgery is increasingly common as applications integrate
more services. Anywhere your server fetches a URL based on user input is a
potential SSRF vector:

- Webhook registration (user provides callback URL)
- Image/file URL fetching (avatar from URL, link previews)
- PDF generation from user-supplied URLs
- OAuth callback URL validation
- API proxy endpoints

Attackers use SSRF to:
- Access cloud metadata and steal IAM credentials
- Scan internal networks from the server's perspective
- Access internal services (Redis, Elasticsearch, admin panels)
- Read local files via `file://` protocol

**Mitigation:** Validate URLs against an allowlist of domains/protocols, block
private IP ranges (10.x, 172.16-31.x, 192.168.x, 169.254.x, 127.x), and use
a separate network or proxy for outbound requests from user-controlled URLs.

---

## Vulnerability Chains

Individual findings become critical when chained together. Pentesters think in
chains. Here are common ones:

### Information Disclosure → Account Takeover
1. Verbose error message reveals internal user IDs
2. IDOR on password reset endpoint allows resetting any user's password
3. Attacker resets admin password, gains full access

### XSS → Session Hijack → Data Exfiltration
1. Stored XSS in a comment or profile field
2. Payload fires when admin views the content
3. Token stolen from localStorage (or cookie without httpOnly)
4. Attacker uses admin session to export all user data

### SSRF → Credential Theft → Lateral Movement
1. Webhook URL field allows internal requests
2. Attacker points it at cloud metadata endpoint
3. IAM credentials returned, granting access to S3, databases, etc.
4. Attacker pivots to other infrastructure

### Mass Assignment → Privilege Escalation
1. User profile update endpoint accepts arbitrary fields
2. Attacker adds `"role": "admin"` to the update request
3. Backend blindly saves all fields, user is now admin
4. Full system access

### IDOR → PII Breach
1. User document endpoint uses sequential integer IDs
2. No ownership check on the endpoint
3. Attacker scripts a loop from ID 1 to 100,000
4. Downloads every user's documents, PII, financial records

**What this means for your code:** When reviewing security, don't just ask "is
this vulnerability exploitable?" Ask "what can an attacker *combine* this with?"
A low-severity info disclosure can become a critical finding when it enables
exploitation of another weakness.

---

## Common Assessment Findings by Severity

From real-world pentesting engagements, roughly ordered by how often they appear:

### Critical (Immediate Fix Required)
- Hardcoded credentials or API keys with broad permissions
- SQL injection in any parameter
- Unauthenticated access to admin functions
- IDOR on sensitive data (financial, PII, health)
- RCE via template injection, deserialization, or command injection

### High
- Authorization bypass (horizontal or vertical privilege escalation)
- Stored XSS in fields viewed by other users or admins
- SSRF with access to internal services or cloud metadata
- Missing authentication on sensitive endpoints
- Mass assignment allowing role escalation
- Sensitive data in client-side bundles or git history

### Medium
- CSRF on state-changing operations (especially financial)
- Reflected XSS
- Verbose error messages revealing stack traces or internal paths
- Missing rate limiting on authentication endpoints
- Session tokens that don't expire or aren't invalidated on logout
- Username enumeration via login or registration responses

### Low (But Don't Ignore)
- Missing security headers (CSP, HSTS, X-Frame-Options)
- Cookies without Secure or HttpOnly flags
- Information disclosure in HTTP headers (Server, X-Powered-By)
- Directory listing enabled
- Out-of-date dependencies with no known exploitable vulnerabilities

---

## Red Flags in Code Review

When reviewing code from a security perspective, these patterns should
immediately raise concern:

```
# Immediate red flags — stop and fix
f"SELECT ... {user_input}"          # SQL injection
os.system(f"... {user_input}")      # Command injection
subprocess.run(..., shell=True)     # Shell injection risk
eval(user_input)                    # Code execution
pickle.loads(user_data)             # Deserialization RCE
yaml.load(data)                     # Use yaml.safe_load
render_template_string(user_input)  # SSTI
Markup(user_input)                  # XSS via Jinja2
dangerouslySetInnerHTML={{...}}     # XSS via React (check sanitization)
localStorage.setItem('token',...)   # Token theft via XSS

# Needs closer inspection
.query(text(...))                   # Verify bind parameters are used
requests.get(user_url)              # Potential SSRF — validate URL
open(user_path)                     # Path traversal — validate path
**request.json()                    # Mass assignment — validate fields
password in log/print               # Sensitive data in logs
except: pass                        # Swallowed errors hide security issues
verify=False                        # Disabled TLS verification
DEBUG = True                        # Debug mode in production
allow_origins=["*"]                 # Wide-open CORS
```

---

## Questions to Ask Every Endpoint

Run through this list for every API endpoint in a security-sensitive review.
These are the same questions a pentester would ask during an assessment:

### Authentication
- Can I call this endpoint without any authentication at all?
- What happens if I send an expired token?
- What happens if I send a malformed token?

### Authorization
- Can user A access this endpoint and see user B's data?
- Can a regular user access this admin-only endpoint?
- If I change the resource ID in the URL, do I get someone else's data?

### Input
- What happens if I send unexpected fields in the JSON body?
- What happens if I send extremely long strings?
- What happens if I send special characters in every parameter?
- What happens if I send a negative number where a positive is expected?
- Can I inject SQL, template syntax, or shell commands via any parameter?

### Response
- Does the error response reveal internal details?
- Does the success response include fields I shouldn't see?
- Are there timing differences that reveal information (e.g., valid vs invalid usernames)?

### Rate Limiting
- Can I call this endpoint 1,000 times in a minute?
- Does the rate limit actually block me or just log?
- Can I bypass it with different headers or slight URL variations?

### Business Logic
- Can I skip steps in a multi-step process?
- Can I replay this request to double-charge or double-credit?
- Can I tamper with pricing, quantities, or discount codes?
- Can I access functionality that should be time-locked or state-dependent?

These questions are cheap to ask during development and expensive to answer
after a breach.
