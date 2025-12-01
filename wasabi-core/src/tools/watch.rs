use std::time::Instant;

pub struct Watch {
    start: Instant,
}

impl Watch {
    pub fn start() -> Self {
        Self {
            start: Instant::now(),
        }
    }

    pub fn elapsed_us(&self) -> u32 {
        u32::try_from(self.start.elapsed().as_micros()).unwrap_or(u32::MAX)
    }
}
