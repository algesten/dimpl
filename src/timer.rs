use std::ops::Mul;
use std::time::Duration;

use rand::random;

// In seconds.
const JITTER_RANGE: f32 = 0.5;

pub struct ExponentialBackoff {
    start_rto: Duration,
    retries: usize,
    rto: Duration,
    jitter: f32,
    left: usize,
}

impl ExponentialBackoff {
    pub fn new(start_rto: Duration, retries: usize) -> Self {
        Self {
            start_rto,
            retries,
            rto: start_rto,
            jitter: Self::jitter(),
            left: retries,
        }
    }

    pub fn reset(&mut self) {
        self.rto = self.start_rto;
        self.jitter = Self::jitter();
        self.left = self.retries;
    }

    pub fn rto(&self) -> Duration {
        if self.jitter < 0.0 {
            let duration = Duration::from_secs_f32(self.jitter.abs());
            self.rto.saturating_sub(duration)
        } else {
            self.rto + Duration::from_secs_f32(self.jitter)
        }
        .max(Duration::from_millis(50))
    }

    // A value between -0.25s and 0.25s
    fn jitter() -> f32 {
        random::<f32>() * JITTER_RANGE - (JITTER_RANGE / 2.0)
    }

    pub fn attempt(&mut self) {
        let (n, overflow) = self.left.overflowing_sub(1);

        if overflow {
            return;
        }

        self.left = n;
        self.jitter = Self::jitter();
        self.rto = self.rto.mul(2);
    }

    pub fn can_retry(&self) -> bool {
        self.left > 0
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn attempts() {
        let mut exp = ExponentialBackoff::new(Duration::from_secs(1), 5);

        let n1 = dbg!(exp.rto().as_millis());
        assert_eq!(exp.rto().as_millis(), n1);

        exp.attempt();

        let n2 = dbg!(exp.rto().as_millis());
        assert_eq!(exp.rto().as_millis(), n2);
        assert!(n2 > n1);

        exp.attempt();

        let n3 = dbg!(exp.rto().as_millis());
        assert_eq!(exp.rto().as_millis(), n3);
        assert!(n3 > n2);

        exp.attempt();

        let n4 = dbg!(exp.rto().as_millis());
        assert_eq!(exp.rto().as_millis(), n4);
        assert!(n4 > n3);
        assert!(exp.can_retry());

        exp.attempt();

        let n5 = dbg!(exp.rto().as_millis());
        assert_eq!(exp.rto().as_millis(), n5);
        assert!(n5 > n4);
        assert!(exp.can_retry());

        exp.attempt();

        let n6 = dbg!(exp.rto().as_millis());
        assert_eq!(exp.rto().as_millis(), n6);
        assert!(n6 > n5);
        assert!(!exp.can_retry());

        exp.attempt();

        assert_eq!(exp.rto().as_millis(), n6);
        assert!(!exp.can_retry());
    }
}
