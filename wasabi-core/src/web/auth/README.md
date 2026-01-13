# auth

JWT-based authentication for warp filters.

## Modules

| Module | Purpose |
|--------|---------|
| [mod.rs](mod.rs) | Warp filters: `with_user`, `with_user_with_any_permission`, `enforce_user_with_any_permission` |
| [authenticator.rs](authenticator.rs) | JWT validation engine with HMAC and JWKS strategies |
| [user.rs](user.rs) | `User` struct with typed claim accessors |
| [jwks.rs](jwks.rs) | JWKS fetching and caching (internal) |

## Authentication Strategies

The authenticator supports two validation strategies, configurable per issuer:

```
                    ┌─────────────────────────────────────┐
                    │          JWT Token                  │
                    └─────────────┬───────────────────────┘
                                  │
                                  ▼
                    ┌─────────────────────────────────────┐
                    │     Extract issuer ("iss")          │
                    └─────────────┬───────────────────────┘
                                  │
               ┌──────────────────┼──────────────────┐
               ▼                                     ▼
    ┌─────────────────────┐              ┌─────────────────────┐
    │   JWKS Strategy     │              │  Secret Strategy    │
    │  (RS256, RS384...)  │              │  (HS256, HS384...)  │
    └──────────┬──────────┘              └──────────┬──────────┘
               │                                    │
               ▼                                    ▼
    ┌─────────────────────┐              ┌─────────────────────┐
    │  Fetch key from     │              │  Use shared secret  │
    │  JWKS endpoint      │              │  from AUTH_SECRET   │
    │  (cached 5min)      │              │                     │
    └──────────┬──────────┘              └──────────┬──────────┘
               │                                    │
               └──────────────────┬─────────────────┘
                                  │
                                  ▼
                    ┌─────────────────────────────────────┐
                    │       Validate signature            │
                    └─────────────┬───────────────────────┘
                                  │
                                  ▼
                    ┌─────────────────────────────────────┐
                    │       Return User with claims       │
                    └─────────────────────────────────────┘
```

## Configuration

| Environment Variable | Purpose |
|---------------------|---------|
| `AUTH_SECRET` | Shared secret for HMAC validation (required unless all issuers use JWKS) |
| `AUTH_ISSUER` | Comma-separated list of allowed issuers with optional strategy config |
| `AUTH_AUDIENCE` | Expected `aud` claim value |
| `AUTH_ALGORITHMS` | Allowed algorithms (e.g., `HS256,RS256`) |
| `AUTH_CUSTOM_CLAIM_PREFIX` | Prefix stripped from custom claims (e.g., `custom:`) |

### Issuer Configuration Format

```
issuer_url                          # Uses shared secret (default)
issuer_url=secret                   # Explicitly uses shared secret
issuer_url=jwks:/path               # JWKS at issuer_url + path
issuer_url=jwks:https://other/jwks  # JWKS at absolute URL
```

### Examples

```bash
# Single issuer with shared secret
AUTH_SECRET=my-secret
AUTH_ISSUER=https://auth.example.com

# Multiple issuers, mixed strategies
AUTH_SECRET=my-secret
AUTH_ISSUER=https://auth1.example.com=secret,https://auth2.example.com=jwks:/.well-known/jwks.json

# Cognito-style with claim prefix stripping
AUTH_ISSUER=https://cognito-idp.eu-central-1.amazonaws.com/eu-central-1_xxx=jwks:/.well-known/jwks.json
AUTH_CUSTOM_CLAIM_PREFIX=custom:
```

## JWKS Caching

The JWKS fetcher implements a caching strategy to balance freshness with performance:

- **Cache TTL**: 5 minutes
- **Minimum fetch interval**: 10 seconds (prevents hammering on key rotation)
- **Cache invalidation**: Triggered when requested key ID is not found

## Claim Constants

Standard claim names are defined in [mod.rs](mod.rs):

| Constant | Claim | Purpose |
|----------|-------|---------|
| `CLAIM_SUB` | `sub` | User ID |
| `CLAIM_TENANT` | `tenant` | Tenant ID |
| `CLAIM_NAME` | `name` | Full name |
| `CLAIM_EMAIL` | `email` | Email address |
| `CLAIM_PERMISSIONS` | `permissions` | Array of permission strings |
| `CLAIM_LOCALE` | `locale` | BCP47 language tag (defaults to `en-US`) |
| `CLAIM_ACT` | `act` | Delegation chain |
