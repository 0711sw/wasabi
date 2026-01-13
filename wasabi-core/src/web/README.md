# web

HTTP layer built on the Warp framework.

## Modules

| Module | Purpose |
|--------|---------|
| [warp.rs](warp.rs) | Body parsing filters, response helpers, `run_webserver()` with tracing |
| [error.rs](error.rs) | `ApiError` type, `ResultExt` trait, `client_bail!`/`status_bail!` macros |
| [validation.rs](validation.rs) | Input validation for strings and IDs |
| [favicon_service.rs](favicon_service.rs) | `/favicon.ico` redirect route |
| [info_service.rs](info_service.rs) | `/info/v1` metadata endpoint |
| [auth/](auth/) | JWT authentication (see below) |

## Authentication (`auth/`)

| Module | Purpose |
|--------|---------|
| [mod.rs](auth/mod.rs) | `with_user`, `with_user_with_any_permission` filters |
| [authenticator.rs](auth/authenticator.rs) | JWT validation with HMAC or JWKS strategies |
| [user.rs](auth/user.rs) | `User` struct with typed claim accessors |
| [jwks.rs](auth/jwks.rs) | JWKS fetching and caching (5min TTL) |

## Request Flow

```
Request
   │
   ▼
┌─────────────────┐
│  with_user()    │◄── Extracts JWT from Authorization header or ?jwt= query
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Authenticator  │◄── Validates signature (HMAC or JWKS based on issuer)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│     User        │◄── Provides tenant_id(), user_id(), permissions, etc.
└─────────────────┘
```

## Key Configuration (Environment Variables)

| Variable | Purpose |
|----------|---------|
| `BIND_ADDRESS` | HTTP server address (required) |
| `AUTH_SECRET` | Shared secret for HMAC validation |
| `AUTH_ISSUER` | Comma-separated issuers with optional config |
| `AUTH_AUDIENCE` | Expected audience claim |
| `AUTH_ALGORITHMS` | Allowed JWT algorithms |
| `AUTH_CUSTOM_CLAIM_PREFIX` | Prefix to strip from custom claims |

### Issuer Configuration Examples

```bash
# Single issuer with shared secret
AUTH_ISSUER=https://auth.example.com

# Multiple issuers, mixed strategies
AUTH_ISSUER=https://auth1.example.com=jwks:/.well-known/jwks.json,https://auth2.example.com=secret

# JWKS with absolute URL
AUTH_ISSUER=https://auth.example.com=jwks:https://keys.example.com/jwks.json
```
