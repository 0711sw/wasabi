//! Simple stopwatch for measuring elapsed time.

use std::time::Instant;

/// A lightweight stopwatch that measures elapsed time in microseconds.
///
/// Returns `u32::MAX` if the elapsed time exceeds ~71 minutes, which is
/// acceptable for typical request timing where such durations indicate
/// a problem anyway.
pub struct Watch {
    start: Instant,
}

impl Watch {
    /// Starts a new stopwatch.
    pub fn start() -> Self {
        Self {
            start: Instant::now(),
        }
    }

    /// Returns the elapsed time in microseconds since the watch was started.
    pub fn elapsed_us(&self) -> u32 {
        u32::try_from(self.start.elapsed().as_micros()).unwrap_or(u32::MAX)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn measures_elapsed_time() {
        let watch = Watch::start();
        thread::sleep(Duration::from_millis(10));
        let elapsed = watch.elapsed_us();
        // Should be at least 10ms (10_000 µs), allowing some tolerance
        assert!(elapsed >= 9_000, "elapsed was {elapsed} µs");
    }
}
