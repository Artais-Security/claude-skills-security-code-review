# Security Review Skill

A Claude skill for catching security vulnerabilities before they ship, informed by real-world penetration testing experience.

## What It Does

When triggered, Claude performs a two-pass security review:

1. **Defensive pass** — Works through a universal checklist covering secrets management, input validation, injection prevention, authentication, authorization, XSS, CSRF, rate limiting, data exposure, and transport security.
2. **Offensive pass** — Reviews the same code from an attacker's perspective — what a pentester would target first, how findings chain together, and what red flags to look for in code review.

## Structure

```
security-review/
├── SKILL.md                                — Universal checklist and routing logic
└── references/
    ├── offensive-perspective.md            — Attacker methodology, vulnerability chains,
    │                                        code review red flags, per-endpoint questions
    ├── owasp-top-10.md                    — OWASP Top 10 (2021) deep-dives with CWE
    │                                        mappings, attack patterns, checklist gap analysis
    ├── python.md                          — Python stdlib and general security patterns
    ├── python-fastapi.md                  — FastAPI / SQLAlchemy / Pydantic patterns
    ├── typescript-nextjs.md               — Next.js / Supabase patterns
    └── go.md                              — Go / net/http / Chi / Gin / GORM patterns
```

The core skill (SKILL.md + offensive perspective) is entirely language-agnostic. Stack-specific reference files provide concrete code patterns for particular frameworks and are only loaded when relevant.

## How It Triggers

The skill activates when Claude detects work involving:

- Authentication or authorization
- User input, form data, or file uploads
- API endpoint creation or modification
- Secrets, credentials, or tokens
- Payment or billing features
- PII or sensitive data storage/transmission
- Third-party API or webhook integration
- CORS, CSP, or security header configuration
- Code that crosses trust boundaries

## How It Works

1. **SKILL.md** is loaded on every trigger — contains the language-agnostic checklist, activation criteria, and pre-deployment gate
2. **offensive-perspective.md** is always loaded — covers attacker methodology, exploitation priorities, vulnerability chains, and code review red flags. **owasp-top-10.md** can be loaded as a complement for formal vulnerability classification, compliance mapping, or to cover checklist gaps
3. If a **stack-specific reference** exists for the project's technology, it's loaded for concrete implementation patterns

## Adding a New Stack

Create a new file in `references/` following the existing pattern. Each section should map 1:1 to the universal checklist categories in SKILL.md. Then add a row to the reference table in SKILL.md.

## Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
