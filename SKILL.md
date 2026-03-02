---
name: security-review
description: >
  Use this skill when adding authentication, handling user input, working with secrets,
  creating API endpoints, implementing payment or sensitive features, or storing/transmitting
  sensitive data. Also trigger when reviewing existing code for vulnerabilities, integrating
  third-party APIs, implementing file uploads, setting up CORS, configuring security headers,
  or any time the code touches trust boundaries (user input → backend, backend → database,
  service → service). Includes offensive security perspective — what pentesters actually
  exploit, vulnerability chains, and red flags from real assessments. If the task involves
  credentials, tokens, passwords, PII, or access control in any way, use this skill. When in
  doubt about whether something is security-relevant, it probably is — use the skill.
---

# Security Review Skill

Ensure all code follows security best practices and catch vulnerabilities before they ship.
This skill provides a universal security checklist and routes to stack-specific implementation
patterns.

## Reference Files

After reviewing the universal checklist below, read the relevant reference files:

| Reference | When to Read |
|-----------|-------------|
| `references/offensive-perspective.md` | **Always read this first** for any security review. Covers what pentesters actually exploit, vulnerability chains, red flags in code review, and the questions to ask every endpoint. |
| `references/owasp-top-10.md` | OWASP Top 10 (2021) deep-dives with CWE mappings — read for formal vulnerability classification, compliance reviews, or to cover checklist gaps (Insecure Design, Integrity Failures, Logging/Monitoring) |
| `references/python-fastapi.md` | Python / FastAPI / SQLAlchemy / Postgres implementation patterns |
| `references/typescript-nextjs.md` | TypeScript / Next.js / Supabase implementation patterns |
| `references/go.md` | Go / net/http / Chi / Gin / database/sql / GORM patterns |

If the project uses a stack not listed here, apply the universal principles below and adapt
the patterns from the closest reference file. Always read the offensive perspective
regardless of stack — it's language-agnostic.

## When to Activate

- Implementing authentication or authorization
- Handling user input, form data, or file uploads
- Creating or modifying API endpoints
- Working with secrets, credentials, or tokens
- Implementing payment or billing features
- Storing or transmitting PII or sensitive data
- Integrating third-party APIs or webhooks
- Setting up CORS, CSP, or other security headers
- Reviewing code that crosses trust boundaries
- Configuring database access or row-level permissions

## Think Like an Attacker

Before writing or reviewing security-sensitive code, consider what an attacker would try.
For detailed exploitation patterns and real-world examples, read
`references/offensive-perspective.md`.

1. **What's the attack surface?** Every input the user controls is a potential entry point —
   URL params, headers, cookies, file uploads, JSON bodies, WebSocket messages.
2. **What's the blast radius?** If this component is compromised, what else falls? A leaked
   DB credential is worse than a leaked UI preference.
3. **Where are the trust boundaries?** Data crossing from untrusted → trusted context needs
   validation. This includes: client → server, user input → database query, external API →
   your code, file upload → file system.
4. **What does the attacker gain?** Prioritize protecting high-value targets: auth tokens,
   payment data, PII, admin access, API keys with broad permissions.
5. **What can be chained?** A low-severity info disclosure becomes critical when it enables
   exploitation of another weakness. Think about how findings combine.

## Universal Security Checklist

Work through each category. Check the relevant stack reference file for implementation
examples.

### 1. Secrets Management

**Principle:** Secrets never belong in source code, logs, error messages, or client bundles.

- [ ] No hardcoded API keys, tokens, passwords, or connection strings
- [ ] All secrets loaded from environment variables or a secrets manager
- [ ] Secret presence validated at startup (fail fast if missing)
- [ ] `.env` / `.env.local` in `.gitignore`
- [ ] No secrets in git history (if found, rotate immediately — removing from history isn't enough)
- [ ] Production secrets managed through hosting platform or vault
- [ ] Secrets have minimal scope (least-privilege API keys, read-only DB users where possible)

### 2. Input Validation

**Principle:** Never trust user input. Validate type, format, length, and range. Use
allowlists, not blocklists.

- [ ] All user inputs validated with schemas before processing
- [ ] Validation happens server-side (client-side validation is UX, not security)
- [ ] File uploads restricted by size, MIME type, and extension
- [ ] Filenames sanitized — never use user-provided filenames directly in paths
- [ ] No user input passed directly into shell commands, file paths, or eval/exec
- [ ] Allowlist validation preferred over blocklist
- [ ] Error messages don't leak internal details (schema info, stack traces, file paths)

### 3. Injection Prevention

**Principle:** Never construct queries, commands, or markup by concatenating user input.

- [ ] All database queries use parameterized queries or ORM methods
- [ ] No string concatenation or f-strings in SQL
- [ ] No user input in shell commands (if unavoidable, use allowlists + shlex.quote or equivalent)
- [ ] Template engines used with auto-escaping enabled
- [ ] User-provided HTML sanitized with an allowlist of tags/attributes
- [ ] LDAP, XML, and other injection vectors considered where relevant

### 4. Authentication & Session Management

**Principle:** Verify identity reliably, manage sessions securely, fail closed.

- [ ] Passwords hashed with bcrypt, scrypt, or argon2 (never MD5/SHA for passwords)
- [ ] Tokens stored in httpOnly, Secure, SameSite=Strict cookies (not localStorage)
- [ ] Session tokens have reasonable expiration
- [ ] Session invalidation on logout actually works
- [ ] Password reset tokens are single-use and time-limited
- [ ] Multi-factor authentication available for sensitive operations
- [ ] Failed login attempts rate-limited (prevent brute force)
- [ ] Authentication errors don't reveal whether the account exists

### 5. Authorization

**Principle:** Verify permissions on every request. Never rely on client-side checks alone.

- [ ] Authorization checked server-side before every sensitive operation
- [ ] Object-level authorization — users can only access their own resources (IDOR prevention)
- [ ] Role-based or attribute-based access control implemented
- [ ] Admin endpoints protected and not guessable
- [ ] Row-level security enabled at the database layer where supported
- [ ] Horizontal privilege escalation tested (user A can't access user B's data)
- [ ] Vertical privilege escalation tested (regular user can't reach admin functions)

### 6. XSS Prevention

**Principle:** Never render untrusted content without sanitization.

- [ ] Framework's built-in XSS protection used (React's JSX escaping, Jinja2 autoescaping, etc.)
- [ ] `dangerouslySetInnerHTML` / `|safe` / `Markup()` only used with sanitized content
- [ ] Content Security Policy headers configured
- [ ] User-provided URLs validated (prevent `javascript:` protocol)
- [ ] JSON embedded in HTML properly escaped

### 7. CSRF Protection

**Principle:** State-changing requests must prove they originated from your application.

- [ ] CSRF tokens on all state-changing operations (POST, PUT, DELETE)
- [ ] SameSite=Strict or SameSite=Lax on session cookies
- [ ] Origin/Referer header validation as defense in depth
- [ ] Framework's built-in CSRF protection enabled and not accidentally bypassed

### 8. Rate Limiting

**Principle:** Protect resources from abuse and brute force.

- [ ] Rate limiting on all public API endpoints
- [ ] Stricter limits on expensive operations (search, file processing, AI inference)
- [ ] Stricter limits on auth endpoints (login, password reset, token generation)
- [ ] Rate limiting by IP and by authenticated user
- [ ] Rate limit responses include appropriate `Retry-After` headers
- [ ] Consider progressive backoff for repeated violations

### 9. Data Exposure Prevention

**Principle:** Minimize what you collect, expose, and log.

- [ ] API responses return only necessary fields (no full user objects with password hashes)
- [ ] No passwords, tokens, secrets, or PII in logs
- [ ] Error responses generic for clients, detailed only in server-side logs
- [ ] Stack traces never exposed to end users
- [ ] Sensitive data encrypted at rest where required
- [ ] PII handling compliant with relevant regulations (GDPR, CCPA, etc.)
- [ ] Database backups encrypted and access-controlled

### 10. Transport & Infrastructure

**Principle:** Encrypt in transit, configure securely, minimize attack surface.

- [ ] HTTPS enforced in production (HSTS header set)
- [ ] Security headers configured: CSP, X-Frame-Options, X-Content-Type-Options
- [ ] CORS configured with specific allowed origins (not wildcard in production)
- [ ] Cookies set with Secure flag
- [ ] Unnecessary ports and services disabled
- [ ] Dependencies up to date with no known vulnerabilities
- [ ] Lock files committed for reproducible builds
- [ ] Dependency scanning enabled (Dependabot, Snyk, `pip audit`, `npm audit`)

## Offensive Review Pass

After completing the checklist above, do a second pass from the attacker's perspective.
Read `references/offensive-perspective.md` and specifically:

1. **Run through "Questions to Ask Every Endpoint"** for each API route in scope
2. **Check for red flags** listed in the code review section
3. **Consider vulnerability chains** — how could a low-severity finding combine with
   another to create a critical issue?
4. **Prioritize like a pentester** — focus on exposed secrets, IDOR, missing auth on
   internal endpoints, and injection in search/filter/sort parameters first

## Security Testing Checklist

Before considering the security review complete:

- [ ] Authentication endpoints tested (unauthenticated access returns 401)
- [ ] Authorization tested (wrong role returns 403, IDOR attempts blocked)
- [ ] Invalid input rejected with appropriate error codes
- [ ] Rate limits enforced under load
- [ ] SQL injection attempts in input fields don't alter query behavior
- [ ] XSS payloads in user content are escaped in output
- [ ] CSRF tokens validated on state-changing endpoints
- [ ] Secrets not present in client-side bundles or network responses

## Pre-Deployment Gate

Before ANY production deployment, every item below must be confirmed:

1. **Secrets** — All in env vars or vault, none in code or git history
2. **Input validation** — Schema validation on all endpoints, server-side
3. **Injection** — All queries parameterized, no concatenation
4. **Auth** — Tokens in httpOnly cookies, sessions expire, logout works
5. **Authz** — Server-side checks on every sensitive operation, IDOR tested
6. **XSS** — User content sanitized, CSP headers set
7. **CSRF** — Tokens on state-changing operations, SameSite cookies
8. **Rate limiting** — All endpoints protected, auth endpoints strict
9. **Data exposure** — No secrets in logs/errors, minimal API responses
10. **Transport** — HTTPS enforced, security headers configured, CORS locked down
11. **Dependencies** — Audited, no known vulnerabilities, lock files committed

## Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/) — verification standard for thorough reviews
- [CWE Top 25](https://cwe.mitre.org/top25/) — most dangerous software weaknesses
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/) — practical implementation guidance
