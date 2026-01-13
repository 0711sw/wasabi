# tools

Common utilities used across the framework. These are small, focused helpers that don't belong to a specific domain.

## Modules

| Module | Purpose |
|--------|---------|
| [id_generator](id_generator.rs) | Random ID generation with a vowel-free alphabet to avoid offensive strings |
| [i18n_string](i18n_string.rs) | Multi-language string type with flexible JSON serialization |
| [system](system.rs) | Graceful shutdown via Unix signal handling (SIGINT, SIGTERM, SIGHUP) |
| [watch](watch.rs) | Microsecond-precision stopwatch for request timing |

## Types in [mod.rs](mod.rs)

- **`PinnedBytesStream`** - Type alias for streaming HTTP response bodies
- **`not()`** - Predicate negation helper for iterator filtering
