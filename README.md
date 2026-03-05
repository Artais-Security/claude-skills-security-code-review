# Security Review Skill

A Claude skill for catching security vulnerabilities before they ship, informed by real-world penetration testing experience.

## What It Does

When triggered, Claude performs a two-pass security review:

1. **Defensive pass** — Works through a universal checklist covering secrets management, input validation, injection prevention, authentication, authorization, XSS, CSRF, rate limiting, data exposure, and transport security.
2. **Offensive pass** — Reviews the same code from an attacker's perspective — what a pentester would target first, how findings chain together, and what red flags to look for in code review.

## Structure

```
security-review/
├── SKILL.md                        — Universal checklist and routing logic
├── local/
│   └── claude-chat.md              — Local/chat-specific configuration
└── references/
    ├── auth/                       — Authentication & authorization patterns
    ├── core/                       — Core/general security patterns
    ├── data/                       — Data exposure & storage patterns
    ├── dependencies/               — Dependency & supply chain patterns
    ├── injection/                  — Injection prevention patterns
    ├── input/                      — Input validation patterns
    ├── secrets/                    — Secrets management patterns
    ├── transport/                  — Transport security patterns
    └── web/                        — Web security patterns (XSS, CSRF, headers)
```

Each category directory contains a `general.md` (language-agnostic) plus stack-specific files (`python.md`, `python-fastapi.md`, `nextjs.md`, `go.md`) where applicable. The core skill is entirely language-agnostic; stack-specific files are only loaded when relevant.

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
2. For each relevant security category, the **`general.md`** reference is loaded for language-agnostic patterns
3. If a **stack-specific reference** exists for the project's technology, it's loaded alongside the general file for concrete implementation patterns

## Adding a New Stack

Add a new stack-specific file (e.g., `ruby.md`) inside each relevant category directory under `references/`, following the pattern of existing stack files. Then add a row to the reference table in SKILL.md.

## Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
