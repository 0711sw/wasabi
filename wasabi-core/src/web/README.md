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
| [auth/](auth/) | JWT authentication with HMAC and JWKS strategies |

## Key Configuration

| Variable | Purpose |
|----------|---------|
| `BIND_ADDRESS` | HTTP server address (required) |
