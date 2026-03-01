# Go / net/http / Chi / Gin / database/sql / GORM Security Patterns

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

### Loading secrets from environment with validation

```go
package config

import (
	"fmt"
	"os"
)

type Config struct {
	DatabaseURL  string
	SecretKey    string
	OpenAIAPIKey string
	AllowedOrigin string
}

// MustLoad validates all required secrets at startup.
// Call this from main() — the app won't boot with missing secrets.
func MustLoad() Config {
	cfg := Config{
		DatabaseURL:   mustEnv("DATABASE_URL"),
		SecretKey:     mustEnv("SECRET_KEY"),
		OpenAIAPIKey:  mustEnv("OPENAI_API_KEY"),
		AllowedOrigin: envOr("ALLOWED_ORIGIN", "https://example.com"),
	}
	return cfg
}

func mustEnv(key string) string {
	val := os.Getenv(key)
	if val == "" {
		panic(fmt.Sprintf("required environment variable %s is not set", key))
	}
	return val
}

func envOr(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}
```

For larger projects, use `kelseyhightower/envconfig` for struct-tag-based loading:

```go
import "github.com/kelseyhightower/envconfig"

type Config struct {
	DatabaseURL  string `envconfig:"DATABASE_URL" required:"true"`
	SecretKey    string `envconfig:"SECRET_KEY" required:"true"`
	OpenAIAPIKey string `envconfig:"OPENAI_API_KEY" required:"true"`
}

func MustLoad() Config {
	var cfg Config
	if err := envconfig.Process("", &cfg); err != nil {
		panic(err) // fail fast — missing secrets
	}
	return cfg
}
```

### What not to do

```go
// DANGEROUS — secrets in source code
const apiKey = "sk-proj-xxxxx"
const dbPassword = "password123"

// RISKY — no validation, empty string is silent failure
apiKey := os.Getenv("API_KEY") // Could be "" and fail later
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

### Struct validation with go-playground/validator

```go
import (
	"net/http"
	"encoding/json"

	"github.com/go-playground/validator/v10"
)

var validate = validator.New()

type CreateUserRequest struct {
	Email string `json:"email" validate:"required,email"`
	Name  string `json:"name" validate:"required,min=1,max=100"`
	Age   int    `json:"age" validate:"gte=0,lte=150"`
}

func CreateUserHandler(w http.ResponseWriter, r *http.Request) {
	var req CreateUserRequest

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields() // Reject unexpected fields
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if err := validate.Struct(req); err != nil {
		http.Error(w, "Validation failed", http.StatusBadRequest)
		return
	}

	// req is validated — safe to use
}
```

`DisallowUnknownFields()` prevents mass-assignment style attacks where extra
fields slip through to downstream processing.

### File upload validation

```go
import (
	"net/http"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
)

var (
	allowedMIME = map[string]bool{
		"image/jpeg": true,
		"image/png":  true,
		"image/gif":  true,
	}
	allowedExt = map[string]bool{
		".jpg":  true,
		".jpeg": true,
		".png":  true,
		".gif":  true,
	}
	maxUploadSize int64 = 5 << 20 // 5 MB
)

func UploadHandler(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize)
	if err := r.ParseMultipartForm(maxUploadSize); err != nil {
		http.Error(w, "File too large (max 5MB)", http.StatusRequestEntityTooLarge)
		return
	}

	file, header, err := r.FormFile("upload")
	if err != nil {
		http.Error(w, "Missing file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Detect MIME from content, not the claimed Content-Type
	buf := make([]byte, 512)
	n, _ := file.Read(buf)
	detected := http.DetectContentType(buf[:n])
	if !allowedMIME[detected] {
		http.Error(w, "Invalid file type", http.StatusBadRequest)
		return
	}

	// Check extension
	ext := strings.ToLower(filepath.Ext(header.Filename))
	if !allowedExt[ext] {
		http.Error(w, "Invalid file extension", http.StatusBadRequest)
		return
	}

	// Generate a safe filename — never trust user-provided names
	safeName := uuid.NewString() + ext
	_ = safeName // use for storage
}
```

Key point: use `http.DetectContentType` on the actual bytes, not the
user-supplied `Content-Type` header. Attackers can set any Content-Type.

### Path traversal prevention

```go
import (
	"path/filepath"
	"strings"
)

const uploadDir = "/app/uploads"

func safePath(userFilename string) (string, error) {
	// Use only the base filename, strip directory components
	clean := filepath.Base(userFilename)
	target := filepath.Join(uploadDir, clean)

	// Resolve symlinks and verify we're still inside uploadDir
	resolved, err := filepath.EvalSymlinks(filepath.Dir(target))
	if err != nil {
		return "", fmt.Errorf("invalid path")
	}
	absUpload, _ := filepath.Abs(uploadDir)
	if !strings.HasPrefix(resolved, absUpload) {
		return "", fmt.Errorf("path traversal attempt")
	}
	return filepath.Join(resolved, clean), nil
}
```

---

## 3. Injection Prevention

### SQL injection — database/sql (use placeholders)

```go
import "database/sql"

// Safe — parameterized query
var user User
err := db.QueryRow(
	"SELECT id, email, name FROM users WHERE email = $1",
	userEmail,
).Scan(&user.ID, &user.Email, &user.Name)

// DANGEROUS — string concatenation in SQL
query := fmt.Sprintf("SELECT * FROM users WHERE email = '%s'", userEmail) // SQLi!
```

Placeholder syntax varies by driver: `$1` for Postgres, `?` for MySQL/SQLite.

### SQL injection — GORM (safe and unsafe patterns)

```go
import "gorm.io/gorm"

// Safe — GORM parameterizes Where arguments
var user User
db.Where("email = ?", userEmail).First(&user)

// Safe — struct-based queries
db.Where(&User{Email: userEmail}).First(&user)

// DANGEROUS — raw string in Where
db.Where(fmt.Sprintf("email = '%s'", userEmail)).First(&user) // SQLi!

// DANGEROUS — raw SQL without placeholders
db.Raw(fmt.Sprintf("SELECT * FROM users WHERE email = '%s'", userEmail)) // SQLi!

// Safe — raw SQL with placeholders
db.Raw("SELECT * FROM users WHERE email = ?", userEmail).Scan(&user)
```

### SQL injection — sqlx

```go
import "github.com/jmoiron/sqlx"

// Safe — named parameters
var user User
err := db.Get(&user, "SELECT * FROM users WHERE email = $1", userEmail)

// Safe — named struct binding
query := "INSERT INTO users (email, name) VALUES (:email, :name)"
_, err := db.NamedExec(query, user)
```

### SQL injection — dynamic column/table names

Bind parameters only work for values, not identifiers. When you need dynamic
column names, use an allowlist:

```go
var allowedSortColumns = map[string]bool{
	"name":       true,
	"created_at": true,
	"email":      true,
}

func getUsers(db *sql.DB, sortBy string) ([]User, error) {
	if !allowedSortColumns[sortBy] {
		return nil, fmt.Errorf("invalid sort column")
	}
	// Safe — sortBy is from a known set
	query := fmt.Sprintf("SELECT * FROM users ORDER BY %s", sortBy)
	return queryUsers(db, query)
}
```

### Command injection

```go
import "os/exec"

// Safe — exec.Command takes arguments as separate strings, no shell
cmd := exec.Command("convert", userFilename, "output.png")
output, err := cmd.CombinedOutput()

// DANGEROUS — shell invocation with user input
cmd := exec.Command("bash", "-c", "convert "+userFilename+" output.png") // Injection!
```

`os/exec` does not invoke a shell by default. Each argument is passed directly
to the process. Never use `bash -c` or `sh -c` with user input.

### Template injection

```go
import "html/template"

// Safe — html/template auto-escapes
tmpl := template.Must(template.ParseFiles("page.html"))
tmpl.Execute(w, data)

// DANGEROUS — text/template does NOT escape HTML
import "text/template"
tmpl := template.Must(template.ParseFiles("page.html")) // XSS if data has HTML
```

Always use `html/template` for anything rendered in a browser.

---

## 4. Authentication & Sessions

### Password hashing with bcrypt

```go
import "golang.org/x/crypto/bcrypt"

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func CheckPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
```

### JWT tokens in httpOnly cookies

```go
import (
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var jwtKey = []byte(cfg.SecretKey)

func CreateToken(userID string) (string, error) {
	claims := jwt.MapClaims{
		"sub": userID,
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtKey)
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	user, err := authenticate(r)
	if err != nil {
		// Don't reveal whether the email or password was wrong
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	token, err := CreateToken(user.ID)
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    token,
		HttpOnly: true,             // JS can't read it — mitigates XSS token theft
		Secure:   true,             // HTTPS only
		SameSite: http.SameSiteStrictMode, // Mitigates CSRF
		MaxAge:   3600,
		Path:     "/",
	})
	w.WriteHeader(http.StatusOK)
}
```

### Extracting the current user from context

```go
type contextKey string

const userContextKey contextKey = "user"

func GetCurrentUser(r *http.Request) (*User, error) {
	cookie, err := r.Cookie("access_token")
	if err != nil {
		return nil, fmt.Errorf("not authenticated")
	}

	token, err := jwt.Parse(cookie.Value, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return jwtKey, nil
	})
	if err != nil || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid claims")
	}

	userID, _ := claims["sub"].(string)
	return getUserByID(userID)
}

// AuthMiddleware injects the user into request context
func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, err := GetCurrentUser(r)
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), userContextKey, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// UserFromContext retrieves the user set by AuthMiddleware
func UserFromContext(ctx context.Context) *User {
	user, _ := ctx.Value(userContextKey).(*User)
	return user
}
```

---

## 5. Authorization

### Middleware-based role checks

```go
// RequireRole returns middleware that restricts access to specific roles.
func RequireRole(roles ...string) func(http.Handler) http.Handler {
	allowed := make(map[string]bool, len(roles))
	for _, r := range roles {
		allowed[r] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := UserFromContext(r.Context())
			if user == nil || !allowed[user.Role] {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Usage with Chi router
r := chi.NewRouter()
r.Use(AuthMiddleware)

r.Route("/admin", func(r chi.Router) {
	r.Use(RequireRole("admin"))
	r.Get("/users", AdminListUsersHandler)
	r.Delete("/users/{id}", AdminDeleteUserHandler)
})
```

### Object-level authorization (IDOR prevention)

This is one of the most commonly exploited vulnerabilities. Always verify the
requesting user owns or has access to the resource:

```go
func GetDocumentHandler(w http.ResponseWriter, r *http.Request) {
	docID := chi.URLParam(r, "docID")
	user := UserFromContext(r.Context())

	doc, err := db.GetDocument(docID)
	if err != nil {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	// CRITICAL — verify ownership before returning
	if doc.OwnerID != user.ID && user.Role != "admin" {
		http.Error(w, "Not found", http.StatusNotFound) // 404, not 403 — don't confirm existence
		return
	}

	json.NewEncoder(w).Encode(doc)
}
```

Returning 404 instead of 403 prevents attackers from enumerating which resources
exist.

---

## 6. XSS Prevention

### html/template auto-escaping

```go
import "html/template"

// html/template auto-escapes in HTML, JS, URI, and CSS contexts
tmpl := template.Must(template.ParseFiles("page.html"))

// In page.html:
// <p>{{.UserContent}}</p>   ← auto-escaped, safe
// <a href="{{.URL}}">       ← auto-escaped in URI context
```

### Dangerous: template.HTML bypass

```go
import "html/template"

// DANGEROUS — template.HTML marks content as safe, skipping escaping
data := map[string]interface{}{
	"Content": template.HTML(userContent), // XSS if userContent is unsanitized!
}
tmpl.Execute(w, data)
```

Only use `template.HTML` with content you've explicitly sanitized.

### Sanitizing user HTML with bluemonday

```go
import "github.com/microcosm-cc/bluemonday"

// Strict — strip all HTML
p := bluemonday.StrictPolicy()
clean := p.Sanitize(userHTML)

// Permissive — allow safe formatting tags
p := bluemonday.UGCPolicy() // User Generated Content defaults
clean := p.Sanitize(userHTML)

// Custom policy
p := bluemonday.NewPolicy()
p.AllowElements("b", "i", "em", "strong", "p", "br", "ul", "ol", "li")
clean := p.Sanitize(userHTML)
```

### text/template is NOT safe for HTML

```go
import "text/template" // No auto-escaping!

// DANGEROUS — text/template outputs raw strings
tmpl := template.Must(template.New("page").Parse(`<p>{{.UserContent}}</p>`))
// If UserContent is "<script>alert(1)</script>", it renders as-is → XSS
```

Always use `html/template` for anything rendered in a browser.

---

## 7. CSRF Protection

### gorilla/csrf middleware

```go
import (
	"github.com/gorilla/csrf"
	"github.com/gorilla/mux"
)

func main() {
	r := mux.NewRouter()

	// CSRF protection with a 32-byte auth key
	csrfMiddleware := csrf.Protect(
		[]byte(cfg.CSRFKey),
		csrf.Secure(true),                      // Require HTTPS
		csrf.SameSite(csrf.SameSiteStrictMode),
	)

	r.Use(csrfMiddleware)

	// In templates, include the token:
	// <input type="hidden" name="gorilla.csrf.Token" value="{{.CSRFToken}}">
}

func FormHandler(w http.ResponseWriter, r *http.Request) {
	data := map[string]interface{}{
		"CSRFToken": csrf.Token(r),
	}
	tmpl.Execute(w, data)
}
```

### SameSite cookies

If auth uses httpOnly + SameSite=Strict cookies, most CSRF attacks are
mitigated. For additional protection, validate the Origin header:

```go
func ValidateOrigin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			origin := r.Header.Get("Origin")
			if origin != "" && origin != cfg.AllowedOrigin {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
```

---

## 8. Rate Limiting

### x/time/rate for single-instance rate limiting

```go
import "golang.org/x/time/rate"

// Global limiter — 100 requests/second, burst of 200
var globalLimiter = rate.NewLimiter(100, 200)

func RateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !globalLimiter.Allow() {
			http.Error(w, "Too many requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}
```

### Per-IP rate limiting

```go
import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type IPRateLimiter struct {
	mu       sync.Mutex
	limiters map[string]*rate.Limiter
	rate     rate.Limit
	burst    int
}

func NewIPRateLimiter(r rate.Limit, burst int) *IPRateLimiter {
	return &IPRateLimiter{
		limiters: make(map[string]*rate.Limiter),
		rate:     r,
		burst:    burst,
	}
}

func (l *IPRateLimiter) GetLimiter(ip string) *rate.Limiter {
	l.mu.Lock()
	defer l.mu.Unlock()

	limiter, exists := l.limiters[ip]
	if !exists {
		limiter = rate.NewLimiter(l.rate, l.burst)
		l.limiters[ip] = limiter
	}
	return limiter
}

// Usage — different limits for auth vs general endpoints
var (
	generalLimiter = NewIPRateLimiter(rate.Every(time.Second), 100)
	authLimiter    = NewIPRateLimiter(rate.Every(12*time.Second), 5) // 5 per minute
)

func PerIPRateLimit(limiter *IPRateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := r.RemoteAddr // or parse X-Forwarded-For behind a proxy
			if !limiter.GetLimiter(ip).Allow() {
				w.Header().Set("Retry-After", "60")
				http.Error(w, "Too many requests", http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
```

Note: for multi-instance deployments, use a shared store like Redis
instead of in-memory limiters.

---

## 9. Data Exposure Prevention

### Response structs with json tags

```go
// DB model — has everything
type User struct {
	ID           string `json:"id"`
	Email        string `json:"email"`
	Name         string `json:"name"`
	PasswordHash string `json:"-"`    // Never serialized
	StripeID     string `json:"-"`    // Never serialized
	IsAdmin      bool   `json:"-"`    // Never serialized
}

// Or use a separate response struct for explicit control
type UserResponse struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

func toUserResponse(u *User) UserResponse {
	return UserResponse{ID: u.ID, Email: u.Email, Name: u.Name}
}
```

`json:"-"` ensures the field is never included in JSON output, even if you
accidentally pass the full model to `json.Encode`.

### Safe logging with log/slog

```go
import "log/slog"

// DANGEROUS
slog.Info("login attempt", "email", email, "password", password)
slog.Error("payment failed", "card_number", cardNumber)

// Safe — redact sensitive fields
slog.Info("login attempt", "email", email, "user_id", userID)
slog.Error("payment failed", "last_four", card[len(card)-4:], "user_id", userID)
```

### Safe error handling

```go
func GetItemHandler(w http.ResponseWriter, r *http.Request) {
	item, err := db.GetItem(chi.URLParam(r, "id"))
	if err != nil {
		// Log full details server-side
		slog.Error("failed to get item", "error", err, "path", r.URL.Path)
		// Return generic message to client
		http.Error(w, "An unexpected error occurred", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(item)
}
```

Never return `err.Error()` to clients — it may contain SQL queries, file paths,
or stack traces.

---

## 10. Transport & Infrastructure

### Security headers middleware

```go
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "0") // Disabled — CSP is preferred
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; "+
				"script-src 'self'; "+
				"style-src 'self' 'unsafe-inline'; "+
				"img-src 'self' data: https:; "+
				"connect-src 'self' https://api.example.com")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		next.ServeHTTP(w, r)
	})
}
```

### CORS with rs/cors

```go
import "github.com/rs/cors"

// DANGEROUS — allows everything
c := cors.AllowAll()

// Safe — explicit origins
c := cors.New(cors.Options{
	AllowedOrigins:   []string{cfg.AllowedOrigin}, // "https://myapp.com"
	AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE"},
	AllowedHeaders:   []string{"Authorization", "Content-Type"},
	AllowCredentials: true,
	MaxAge:           86400,
})
handler := c.Handler(router)
```

### http.Server timeouts (slowloris prevention)

A bare `http.ListenAndServe` has no timeouts — a slow client can hold
connections open indefinitely. Always configure timeouts:

```go
srv := &http.Server{
	Addr:         ":8080",
	Handler:      router,
	ReadTimeout:  5 * time.Second,   // Max time to read request headers+body
	WriteTimeout: 10 * time.Second,  // Max time to write response
	IdleTimeout:  120 * time.Second, // Max time for keep-alive connections
}
log.Fatal(srv.ListenAndServe())
```

### TLS configuration

```go
import "crypto/tls"

srv := &http.Server{
	Addr:    ":443",
	Handler: router,
	TLSConfig: &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
	},
}
log.Fatal(srv.ListenAndServeTLS("cert.pem", "key.pem"))
```

---

## 11. Dependency Security

```bash
# Check for known vulnerabilities in dependencies
govulncheck ./...

# Remove unused dependencies
go mod tidy

# Verify module checksums haven't been tampered with
go mod verify

# Always commit lock files
git add go.sum
```

Enable Dependabot or similar on your GitHub repo for automated vulnerability
alerts. Run `govulncheck` in CI to catch vulnerable dependencies before merge.
