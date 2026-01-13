# events

Event recording system for analytics, audit trails, and operational insights.

## Architecture

Events flow through a trait-based abstraction that decouples event producers from the delivery mechanism:

```
┌─────────────┐     ┌─────────────────┐     ┌──────────────┐
│ Application │────▶│  EventRecorder  │────▶│   Backend    │
│   Code      │     │     (trait)     │     │ (Firehose/   │
│             │     │                 │     │  Noop/...)   │
└─────────────┘     └─────────────────┘     └──────────────┘
```

## Modules

| Module | Purpose |
|--------|---------|
| [mod.rs](mod.rs) | `Event` and `EventRecorder` traits, `NoopEventRecorder` for dev/test |
| [firehose.rs](firehose.rs) | AWS Firehose implementation with batching (feature: `aws_firehose`) |

## Firehose Batching Strategy

The Firehose recorder optimizes for both throughput and latency:

- **Buffer size**: 8192 events (backpressure via channel)
- **Flush trigger**: 64 events OR 15 seconds, whichever comes first
- **Batch limit**: 256 events per API call (Firehose maximum)
- **Shutdown**: Flushes remaining events before exit

## Defining Events

Use the derive macro from `wasabi_macro`:

```rust
#[derive(Debug, Serialize, Event)]
#[event_type = "user_login"]
struct UserLoginEvent {
    user_id: String,
    ip_address: String,
}
```
