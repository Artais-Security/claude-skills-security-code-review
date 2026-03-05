# Security Core — Non-Obvious Cross-Stack Patterns

Patterns that apply regardless of language or framework. These are the
things that get missed even by developers who know the basics.

## What Gets Exploited First (Pentester Priority Order)

1. **Exposed secrets** — search JS bundles, git history, error messages, `/debug` endpoints
2. **IDOR** — access another user's resources by changing an ID in the URL or body
3. **Missing auth on internal endpoints** — `/api/internal/*`, `/admin/*`, `/health` with data
4. **SQLi in search/filter/sort params** — login forms get tested; filters don't
5. **Parameter tampering for privilege escalation** — `"role": "admin"` in a profile update
6. **SSRF in webhook/integration endpoints** — fetch the cloud metadata endpoint
7. **Default or weak credentials** — admin/admin, unchanged vendor defaults

## Trust Boundary Checklist

Every request crossing a trust boundary needs:
- **Authentication** — who is this?
- **Authorization** — are they allowed to do this to this specific resource?
- **Validation** — is the input well-formed and within expected bounds?

Trust boundaries: client → server, user input → database, external API → your code,
file upload → filesystem, webhook → handler.

## SSRF: Cloud Metadata Endpoint

```
http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

Any server-side URL fetch using user-supplied input is a SSRF candidate.
The cloud metadata endpoint yields IAM credentials, enabling full account
compromise. Validate URLs against an allowlist of protocols, hosts, and
resolved IPs before fetching.

## Vulnerability Chains to Watch For

- **Info disclosure → account takeover:** IDOR on password reset endpoint leaks reset tokens
- **XSS → session hijack:** XSS steals localStorage token (use httpOnly cookies to prevent)
- **SSRF → credential theft:** fetch cloud metadata, get IAM creds, lateral movement
- **Mass assignment → privilege escalation:** `"role":"admin"` accepted by a profile update endpoint
- **Log injection → log forgery:** user-controlled input with newlines writes fake log entries

## Red Flags in Code (Scan for These)

```
eval(  exec(  system(  popen(  pickle.loads(  yaml.load(
shell=True  verify=False  AllowAll()  allow_origins=["*"]
SECRET_KEY = "  API_KEY = "  PASSWORD = "
html_safe(  dangerouslySetInnerHTML  template.HTML(  |safe
fmt.Sprintf(... query  "SELECT * ... " + userInput
os.path.join(  /tmp/  random.  Math.random()
```

## Common Assessment Findings by Severity

**Critical:** Hardcoded secrets, SQLi, unauthenticated admin endpoints, RCE via deserialization

**High:** IDOR without ownership check, broken function-level auth, SSRF to metadata service,
stored XSS in user-visible content

**Medium:** Missing rate limiting on auth, CSRF on state-changing forms, verbose error messages
leaking stack traces, tokens in localStorage

**Low:** Missing security headers, overly broad CORS, dependency with known CVE (no exploit path)
