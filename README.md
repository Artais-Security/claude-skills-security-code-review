
let's work on this skill: ---
name: security-review
description: Use this skill when adding authentication, handling user input, working with secrets, creating API endpoints, or implementing payment/sensitive features. Provides comprehensive security checklist and patterns.
---
# Security Review Skill
This skill ensures all code follows security best practices and identifies potential vulnerabilities.
## When to Activate
- Implementing authentication or authorization
- Handling user input or file uploads
- Creating new API endpoints
- Working with secrets or credentials
- Implementing payment features
- Storing or transmitting sensitive data
- Integrating third-party APIs
## Security Checklist
### 1. Secrets Management
#### ❌ NEVER Do This
typescript
const apiKey = "sk-proj-xxxxx"  // Hardcoded secret
const dbPassword = "password123" // In source code

#### ✅ ALWAYS Do This
typescript
const apiKey = process.env.OPENAI_API_KEY
const dbUrl = process.env.DATABASE_URL
// Verify secrets exist
if (!apiKey) {
  throw new Error('OPENAI_API_KEY not configured')
}

#### Verification Steps
- [ ] No hardcoded API keys, tokens, or passwords
- [ ] All secrets in environment variables
- [ ] .env.local in .gitignore
- [ ] No secrets in git history
- [ ] Production secrets in hosting platform (Vercel, Railway)
### 2. Input Validation
#### Always Validate User Input
typescript
import { z } from 'zod'
// Define validation schema
const CreateUserSchema = z.object({
  email: z.string().email(),
  name: z.string().min(1).max(100),
  age: z.number().int().min(0).max(150)
})
// Validate before processing
export async function createUser(input: unknown) {
  try {
    const validated = CreateUserSchema.parse(input)
    return await db.users.create(validated)
  } catch (error) {
    if (error instanceof z.ZodError) {
      return { success: false, errors: error.errors }
    }
    throw error
  }
}

#### File Upload Validation
typescript
function validateFileUpload(file: File) {
  // Size check (5MB max)
  const maxSize = 5 * 1024 * 1024
  if (file.size > maxSize) {
    throw new Error('File too large (max 5MB)')
  }
  // Type check
  const allowedTypes = ['image/jpeg', 'image/png', 'image/gif']
  if (!allowedTypes.includes(file.type)) {
    throw new Error('Invalid file type')
  }
  // Extension check
  const allowedExtensions = ['.jpg', '.jpeg', '.png', '.gif']
  const extension = file.name.toLowerCase().match(/\.[^.]+$/)?.[0]
  if (!extension || !allowedExtensions.includes(extension)) {
    throw new Error('Invalid file extension')
  }
  return true
}

#### Verification Steps
- [ ] All user inputs validated with schemas
- [ ] File uploads restricted (size, type, extension)
- [ ] No direct use of user input in queries
- [ ] Whitelist validation (not blacklist)
- [ ] Error messages don't leak sensitive info
### 3. SQL Injection Prevention
#### ❌ NEVER Concatenate SQL
typescript
// DANGEROUS - SQL Injection vulnerability
const query = `SELECT * FROM users WHERE email = '${userEmail}'`
await db.query(query)

#### ✅ ALWAYS Use Parameterized Queries
typescript
// Safe - parameterized query
const { data } = await supabase
  .from('users')
  .select('*')
  .eq('email', userEmail)
// Or with raw SQL
await db.query(
  'SELECT * FROM users WHERE email = $1',
  [userEmail]
)

#### Verification Steps
- [ ] All database queries use parameterized queries
- [ ] No string concatenation in SQL
- [ ] ORM/query builder used correctly
- [ ] Supabase queries properly sanitized
### 4. Authentication & Authorization
#### JWT Token Handling
typescript
// ❌ WRONG: localStorage (vulnerable to XSS)
localStorage.setItem('token', token)
// ✅ CORRECT: httpOnly cookies
res.setHeader('Set-Cookie',
  `token=${token}; HttpOnly; Secure; SameSite=Strict; Max-Age=3600`)

#### Authorization Checks
typescript
export async function deleteUser(userId: string, requesterId: string) {
  // ALWAYS verify authorization first
  const requester = await db.users.findUnique({
    where: { id: requesterId }
  })
  if (requester.role !== 'admin') {
    return NextResponse.json(
      { error: 'Unauthorized' },
      { status: 403 }
    )
  }
  // Proceed with deletion
  await db.users.delete({ where: { id: userId } })
}

#### Row Level Security (Supabase)
sql
-- Enable RLS on all tables
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
-- Users can only view their own data
CREATE POLICY "Users view own data"
  ON users FOR SELECT
  USING (auth.uid() = id);
-- Users can only update their own data
CREATE POLICY "Users update own data"
  ON users FOR UPDATE
  USING (auth.uid() = id);

#### Verification Steps
- [ ] Tokens stored in httpOnly cookies (not localStorage)
- [ ] Authorization checks before sensitive operations
- [ ] Row Level Security enabled in Supabase
- [ ] Role-based access control implemented
- [ ] Session management secure
### 5. XSS Prevention
#### Sanitize HTML
typescript
import DOMPurify from 'isomorphic-dompurify'
// ALWAYS sanitize user-provided HTML
function renderUserContent(html: string) {
  const clean = DOMPurify.sanitize(html, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'p'],
    ALLOWED_ATTR: []
  })
  return <div dangerouslySetInnerHTML={{ __html: clean }} />
}

#### Content Security Policy
typescript
// next.config.js
const securityHeaders = [
  {
    key: 'Content-Security-Policy',
    value: `
      default-src 'self';
      script-src 'self' 'unsafe-eval' 'unsafe-inline';
      style-src 'self' 'unsafe-inline';
      img-src 'self' data: https:;
      font-src 'self';
      connect-src 'self' https://api.example.com;
    `.replace(/\s{2,}/g, ' ').trim()
  }
]

#### Verification Steps
- [ ] User-provided HTML sanitized
- [ ] CSP headers configured
- [ ] No unvalidated dynamic content rendering
- [ ] React's built-in XSS protection used
### 6. CSRF Protection
#### CSRF Tokens
typescript
import { csrf } from '@/lib/csrf'
export async function POST(request: Request) {
  const token = request.headers.get('X-CSRF-Token')
  if (!csrf.verify(token)) {
    return NextResponse.json(
      { error: 'Invalid CSRF token' },
      { status: 403 }
    )
  }
  // Process request
}

#### SameSite Cookies
typescript
res.setHeader('Set-Cookie',
  `session=${sessionId}; HttpOnly; Secure; SameSite=Strict`)

#### Verification Steps
- [ ] CSRF tokens on state-changing operations
- [ ] SameSite=Strict on all cookies
- [ ] Double-submit cookie pattern implemented
### 7. Rate Limiting
#### API Rate Limiting
typescript
import rateLimit from 'express-rate-limit'
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // 100 requests per window
  message: 'Too many requests'
})
// Apply to routes
app.use('/api/', limiter)

#### Expensive Operations
typescript
// Aggressive rate limiting for searches
const searchLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 10, // 10 requests per minute
  message: 'Too many search requests'
})
app.use('/api/search', searchLimiter)

#### Verification Steps
- [ ] Rate limiting on all API endpoints
- [ ] Stricter limits on expensive operations
- [ ] IP-based rate limiting
- [ ] User-based rate limiting (authenticated)
### 8. Sensitive Data Exposure
#### Logging
typescript
// ❌ WRONG: Logging sensitive data
console.log('User login:', { email, password })
console.log('Payment:', { cardNumber, cvv })
// ✅ CORRECT: Redact sensitive data
console.log('User login:', { email, userId })
console.log('Payment:', { last4: card.last4, userId })

#### Error Messages
typescript
// ❌ WRONG: Exposing internal details
catch (error) {
  return NextResponse.json(
    { error: error.message, stack: error.stack },
    { status: 500 }
  )
}
// ✅ CORRECT: Generic error messages
catch (error) {
  console.error('Internal error:', error)
  return NextResponse.json(
    { error: 'An error occurred. Please try again.' },
    { status: 500 }
  )
}

#### Verification Steps
- [ ] No passwords, tokens, or secrets in logs
- [ ] Error messages generic for users
- [ ] Detailed errors only in server logs
- [ ] No stack traces exposed to users
### 9. Blockchain Security (Solana)
#### Wallet Verification
typescript
import { verify } from '@solana/web3.js'
async function verifyWalletOwnership(
  publicKey: string,
  signature: string,
  message: string
) {
  try {
    const isValid = verify(
      Buffer.from(message),
      Buffer.from(signature, 'base64'),
      Buffer.from(publicKey, 'base64')
    )
    return isValid
  } catch (error) {
    return false
  }
}

#### Transaction Verification
typescript
async function verifyTransaction(transaction: Transaction) {
  // Verify recipient
  if (transaction.to !== expectedRecipient) {
    throw new Error('Invalid recipient')
  }
  // Verify amount
  if (transaction.amount > maxAmount) {
    throw new Error('Amount exceeds limit')
  }
  // Verify user has sufficient balance
  const balance = await getBalance(transaction.from)
  if (balance < transaction.amount) {
    throw new Error('Insufficient balance')
  }
  return true
}

#### Verification Steps
- [ ] Wallet signatures verified
- [ ] Transaction details validated
- [ ] Balance checks before transactions
- [ ] No blind transaction signing
### 10. Dependency Security
#### Regular Updates
bash
# Check for vulnerabilities
npm audit
# Fix automatically fixable issues
npm audit fix
# Update dependencies
npm update
# Check for outdated packages
npm outdated

#### Lock Files
bash
# ALWAYS commit lock files
git add package-lock.json
# Use in CI/CD for reproducible builds
npm ci  # Instead of npm install

#### Verification Steps
- [ ] Dependencies up to date
- [ ] No known vulnerabilities (npm audit clean)
- [ ] Lock files committed
- [ ] Dependabot enabled on GitHub
- [ ] Regular security updates
## Security Testing
### Automated Security Tests
typescript
// Test authentication
test('requires authentication', async () => {
  const response = await fetch('/api/protected')
  expect(response.status).toBe(401)
})
// Test authorization
test('requires admin role', async () => {
  const response = await fetch('/api/admin', {
    headers: { Authorization: `Bearer ${userToken}` }
  })
  expect(response.status).toBe(403)
})
// Test input validation
test('rejects invalid input', async () => {
  const response = await fetch('/api/users', {
    method: 'POST',
    body: JSON.stringify({ email: 'not-an-email' })
  })
  expect(response.status).toBe(400)
})
// Test rate limiting
test('enforces rate limits', async () => {
  const requests = Array(101).fill(null).map(() =>
    fetch('/api/endpoint')
  )
  const responses = await Promise.all(requests)
  const tooManyRequests = responses.filter(r => r.status === 429)
  expect(tooManyRequests.length).toBeGreaterThan(0)
})

## Pre-Deployment Security Checklist
Before ANY production deployment:
- [ ] **Secrets**: No hardcoded secrets, all in env vars
- [ ] **Input Validation**: All user inputs validated
- [ ] **SQL Injection**: All queries parameterized
- [ ] **XSS**: User content sanitized
- [ ] **CSRF**: Protection enabled
- [ ] **Authentication**: Proper token handling
- [ ] **Authorization**: Role checks in place
- [ ] **Rate Limiting**: Enabled on all endpoints
- [ ] **HTTPS**: Enforced in production
- [ ] **Security Headers**: CSP, X-Frame-Options configured
- [ ] **Error Handling**: No sensitive data in errors
- [ ] **Logging**: No sensitive data logged
- [ ] **Dependencies**: Up to date, no vulnerabilities
- [ ] **Row Level Security**: Enabled in Supabase
- [ ] **CORS**: Properly configured
- [ ] **File Uploads**: Validated (size, type)
- [ ] **Wallet Signatures**: Verified (if blockchain)
## Resources
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Next.js Security](https://nextjs.org/docs/security)
- [Supabase Security](https://supabase.com/docs/guides/auth)
- [Web Security Academy](https://portswigger.net/web-security)
---
**Remember**: Security is not optional. One vulnerability can compromise the entire platform. When in doubt, err on the side of caution.

Show more
6:04 PM

Identified tech stack mismatches and improvement opportunities for security skill
Identified tech stack mismatches and improvement opportunities for security skill






Good stuff, Mark. I've read through the skill and the skill-creator guide. A few observations before we dive in:

What's working well:

Solid coverage of OWASP-style categories (secrets, injection, XSS, CSRF, rate limiting, etc.)
The ❌/✅ pattern with code examples is effective for quick comprehension
Verification checklists per category are useful for the model to self-check
Pre-deployment checklist ties it all together
Areas I'd want to discuss improving:

Stack mismatch — The examples are almost entirely TypeScript/Next.js/Supabase/Solana. Given your work is primarily Python/FastAPI/Postgres, this feels like it was written for a different audience. Should we retarget it toward your stack, make it multi-language, or keep it generic?
The Solana section — This is pretty niche. Unless you're regularly doing blockchain security assessments for clients, it's taking up real estate that could be better used. Worth keeping?
Length — It's already substantial. The skill-creator guidance suggests keeping SKILL.md under ~500 lines, with overflow going into references/ files. We could restructure so the main SKILL.md has the decision logic and high-level checklist, with language-specific patterns in reference files.
Description could be pushier — Right now it's accurate but passive. Per best practices, we want it to trigger reliably when Claude is doing security-relevant work.
Missing offensive security perspective — Given Artais's focus, this reads more like a defensive developer checklist than something informed by pentesting experience. We could add patterns based on what you actually see exploited in assessments.
Q: What's your primary goal for this skill?
A: Make it language-agnostic with reference files per stack

Q: Should we keep the Solana/blockchain section?
A: No, drop it

6:10 PM

Architected language-agnostic security framework with stack-specific references
Architected language-agnostic security framework with stack-specific references



Great choices. Here's my plan:

Structure:

security-review/
├── SKILL.md          — Core security logic, universal checklist, routes to references
└── references/
    ├── python-fastapi.md    — Python/FastAPI/SQLAlchemy/Postgres patterns
    └── typescript-nextjs.md — TypeScript/Next.js/Supabase patterns
The main SKILL.md stays lean with principles and checklists. Code examples live in the reference files so Claude only loads what's relevant. Let me build it out.


Verified structural integrity and line organization
Verified structural integrity and line organization




Now let me check the structure and line counts:


Verified documentation scope and prepared finalized output
Verified documentation scope and prepared finalized output

Good — SKILL.md is 215 lines (well under 500), and the reference files are loaded only when the relevant stack is detected.


Synthesized key decisions regarding architecture and scope
Synthesized key decisions regarding architecture and scope


Here's what changed from the original:

Structural improvements:

Main SKILL.md is now language-agnostic (215 lines) with checklists and principles only
Code examples moved to stack-specific reference files that Claude loads on demand
Added routing table so Claude picks the right reference file based on the project
Content improvements:

Added "Think Like an Attacker" section — frames security from an offensive perspective (fits your pentesting background)
Dropped the Solana/blockchain section entirely
Expanded authorization section with IDOR prevention guidance (one of the most commonly exploited vulns you'd see in assessments)
Added path traversal prevention in the Python reference
Python reference uses pydantic-settings for secrets validation, python-magic for real MIME detection, slowapi for rate limiting — all idiomatic for your FastAPI stack
Description is pushier — triggers on trust boundaries, credentials, tokens, PII, and includes "when in doubt, use it"
What to look at next: Want to test it against a few prompts, add more stack references (e.g., Go, Django), or refine any of the sections?

Skill
Document · MD 
Python fastapi
Document · MD 
Typescript nextjs
Document · MD 
also Missing offensive security perspective — Given Artais's focus, this reads more like a defensive developer checklist than something informed by pentesting experience. We could add patterns based on what you actually see exploited in assessments.

6:15 PM

Architected offensive security reference file to complement defensive checklist
Architected offensive security reference file to complement defensive checklist





Good call — let me add an offensive perspective reference and wire it into the main SKILL.md. This should read like advice from someone who's broken into these systems, not just someone defending them.


Reconciled documentation updates with offensive security insights
Reconciled documentation updates with offensive security insights

Now let me update the main SKILL.md to reference this and integrate it into the workflow:


Synthesized offensive security insights into documentation workflow
Synthesized offensive security insights into documentation workflow



Now let me add a brief section connecting the offensive perspective to the review workflow:


Recognized need to infuse pentesting expertise into defensive framework
Recognized need to infuse pentesting expertise into defensive framework




Here's what the offensive perspective adds:

references/offensive-perspective.md (340 lines) — loaded first for every security review:

What Gets Exploited First — Priority-ordered list of what pentesters go after: exposed secrets, IDOR, missing auth on internal endpoints, injection in search/filter params, mass assignment, SSRF in integrations
Attacker's Playbook by Category — For each checklist category, how attackers actually exploit weaknesses (not just "don't do this" but "here's what happens when you do")
Vulnerability Chains — Five real-world exploitation chains showing how low/medium findings combine into critical impact (info disclosure → account takeover, XSS → session hijack, SSRF → credential theft, etc.)
Common Findings by Severity — Calibrated from real assessment reports so Claude can properly rate what it finds
Red Flags in Code Review — Pattern-matching list of dangerous code patterns with immediate-stop vs needs-inspection tiers
Questions to Ask Every Endpoint — The exact questions a pentester runs through during assessment: auth, authz, input, response, rate limiting, and business logic
The main SKILL.md also got an Offensive Review Pass section that directs Claude to do a second pass from the attacker's perspective after completing the defensive checklist. The skill description now mentions the offensive angle for better triggering.

Want to test it against some prompts, or refine anything?

Offensive perspective
Document · MD 
Skill
Document · MD 
what is the directory structure

6:22 PM

Determined straightforward response approach
Determined straightforward response approach


security-review/
├── SKILL.md                              (233 lines, 12K) — Universal checklist, routing logic
└── references/
    ├── offensive-perspective.md           (340 lines, 16K) — Always loaded first
    ├── python-fastapi.md                  (568 lines, 16K) — Loaded for Python/FastAPI projects
    └── typescript-nextjs.md              (529 lines, 13K) — Loaded for TS/Next.js projects
Claude reads SKILL.md on every trigger, then loads offensive-perspective.md plus whichever stack reference matches the project.

give me a readme for this repo

6:26 PM

Identified request to document security-review skill repository
Identified request to document security-review skill repository



Clean and to the point — covers what the skill does, how it's structured, trigger conditions, the loading sequence, and how to extend it with new stacks.

Readme
Document · MD 





Claude is AI and can make mistakes. Please double-check responses.
Readme · MD
Copy

# Security Review Skill

A Claude skill that ensures code follows security best practices and identifies potential vulnerabilities — informed by real-world penetration testing experience.

## What It Does

When triggered, Claude works through a universal security checklist covering secrets management, input validation, injection prevention, authentication, authorization, XSS, CSRF, rate limiting, data exposure, and transport security. It then performs a second pass from an offensive security perspective — asking the same questions a pentester would ask during an assessment.

## Structure

```
security-review/
├── SKILL.md                                — Universal checklist and routing logic
└── references/
    ├── offensive-perspective.md            — What pentesters actually exploit, vulnerability
    │                                        chains, red flags, per-endpoint review questions
    ├── python-fastapi.md                   — Python / FastAPI / SQLAlchemy / Postgres patterns
    └── typescript-nextjs.md                — TypeScript / Next.js / Supabase patterns
```

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
2. **offensive-perspective.md** is loaded first for context — covers attacker methodology, exploitation priorities, vulnerability chains, and code review red flags
3. The appropriate **stack reference** is loaded based on the project (Python/FastAPI or TypeScript/Next.js)

## Adding a New Stack

Create a new file in `references/` following the existing pattern. Each section should map 1:1 to the universal checklist categories in SKILL.md. Then add a row to the reference table in SKILL.md.

## Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
