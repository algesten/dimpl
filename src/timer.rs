use std::time::{Duration, Instant};

use crate::{Config, SeededRng, TimeoutError};

const JITTER_RANGE: f32 = 0.5;
const DISTANT_FUTURE: Duration = Duration::from_secs(10 * 365 * 24 * 60 * 60);

/// Overall handshake deadline and per-flight retransmission timer.
///
/// Start events (first packet out, or a server's first ClientHello in) only
/// mark a timer [`Timeout::Pending`]. The next `handle_timeout(now)` arms it,
/// so a stale clock never shortens the budget.
pub struct HandshakeTimers {
    handshake_timeout: Duration,
    handshake: Timeout,
    flight: Timeout,
    backoff: ExponentialBackoff,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Timeout {
    Disabled,
    /// Not started.
    Unarmed,
    /// Started; armed with the time of the next `handle_timeout`.
    Pending,
    Armed(Instant),
}

pub struct ExponentialBackoff {
    start_rto: Duration,
    retries: usize,
    rto: Duration,
    jitter: f32,
    left: usize,
}

impl HandshakeTimers {
    pub fn new(config: &Config, rng: &mut SeededRng) -> Self {
        Self {
            handshake_timeout: config.handshake_timeout(),
            handshake: Timeout::Unarmed,
            flight: Timeout::Disabled,
            backoff: ExponentialBackoff::new(
                config.flight_start_rto(),
                config.flight_retries(),
                rng,
            ),
        }
    }

    pub fn start_handshake(&mut self) {
        if self.handshake == Timeout::Unarmed {
            self.handshake = Timeout::Pending;
        }
    }

    pub fn handshake_deadline(&self) -> Timeout {
        self.handshake
    }

    pub fn set_handshake_deadline(&mut self, deadline: Timeout) {
        self.handshake = deadline;
    }

    pub fn begin_flight(&mut self, rng: &mut SeededRng) {
        self.backoff.reset(rng);
        self.flight = Timeout::Unarmed;
    }

    pub fn flight_sent(&mut self) {
        if self.flight == Timeout::Unarmed {
            self.flight = Timeout::Pending;
        }
    }

    pub fn stop_flight(&mut self) {
        self.flight = Timeout::Disabled;
    }

    pub fn finish_handshake(&mut self) {
        self.handshake = Timeout::Disabled;
    }

    pub fn stop(&mut self) {
        self.finish_handshake();
        self.stop_flight();
    }

    pub fn rto(&self) -> Duration {
        self.backoff.rto()
    }

    /// Reserve a retry from the current sent flight's shared budget.
    pub fn request_resend(&mut self, rng: &mut SeededRng) -> bool {
        if self.flight == Timeout::Unarmed || !self.backoff.can_retry() {
            return false;
        }
        self.backoff.attempt(rng);
        if self.flight != Timeout::Disabled {
            self.flight = Timeout::Unarmed;
        }
        true
    }

    /// Returns `Ok(true)` when the current flight must be resent.
    pub fn handle_timeout(
        &mut self,
        now: Instant,
        rng: &mut SeededRng,
    ) -> Result<bool, TimeoutError> {
        if self.handshake == Timeout::Pending {
            self.handshake = deadline(now, self.handshake_timeout);
        }
        if self.flight == Timeout::Pending {
            self.flight = deadline(now, self.backoff.rto());
        }
        if let Timeout::Armed(timeout) = self.handshake {
            if now >= timeout {
                return Err(TimeoutError::Connect);
            }
        }
        if let Timeout::Armed(timeout) = self.flight {
            if now >= timeout {
                if !self.request_resend(rng) {
                    return Err(TimeoutError::Handshake);
                }
                self.flight = deadline(now, self.backoff.rto());
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub fn poll_timeout(&self, now: Instant) -> Instant {
        match (self.handshake, self.flight) {
            (Timeout::Pending, _) | (_, Timeout::Pending) => now,
            (Timeout::Armed(connect), Timeout::Armed(flight)) => connect.min(flight),
            (Timeout::Armed(timeout), _) | (_, Timeout::Armed(timeout)) => timeout,
            _ => now + DISTANT_FUTURE,
        }
    }
}

impl ExponentialBackoff {
    pub fn new(start_rto: Duration, retries: usize, rng: &mut SeededRng) -> Self {
        Self {
            start_rto,
            retries,
            rto: start_rto,
            jitter: Self::jitter(rng),
            left: retries,
        }
    }

    pub fn reset(&mut self, rng: &mut SeededRng) {
        self.rto = self.start_rto;
        self.jitter = Self::jitter(rng);
        self.left = self.retries;
    }

    pub fn rto(&self) -> Duration {
        let jitter = self.rto.mul_f64(f64::from(self.jitter.abs()));
        if self.jitter < 0.0 {
            self.rto.saturating_sub(jitter)
        } else {
            self.rto.saturating_add(jitter)
        }
        .max(Duration::from_nanos(1))
    }

    // A fraction between -0.25 and 0.25 of the RTO.
    fn jitter(rng: &mut SeededRng) -> f32 {
        rng.random::<f32>() * JITTER_RANGE - (JITTER_RANGE / 2.0)
    }

    pub fn attempt(&mut self, rng: &mut SeededRng) {
        let (n, overflow) = self.left.overflowing_sub(1);

        if overflow {
            return;
        }

        self.left = n;
        self.jitter = Self::jitter(rng);
        self.rto = self.rto.saturating_mul(2);
    }

    pub fn can_retry(&self) -> bool {
        self.left > 0
    }
}

/// Arm a timeout, disabling it if the deadline is not representable.
pub fn deadline(now: Instant, delay: Duration) -> Timeout {
    now.checked_add(delay)
        .map_or(Timeout::Disabled, Timeout::Armed)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn unrepresentable_deadline_is_disabled() {
        let now = Instant::now();
        assert_eq!(deadline(now, Duration::ZERO), Timeout::Armed(now));
        assert_eq!(deadline(now, Duration::MAX), Timeout::Disabled);
    }

    #[test]
    fn proportional_jitter() {
        let mut rng = SeededRng::new(Some(42));
        for rto in [
            Duration::from_nanos(4),
            Duration::from_millis(20),
            Duration::from_secs(100),
        ] {
            let mut exp = ExponentialBackoff::new(rto, 1, &mut rng);
            exp.jitter = -0.25;
            assert_eq!(exp.rto(), rto - rto / 4);
            exp.jitter = 0.25;
            assert_eq!(exp.rto(), rto + rto / 4);
        }
        let mut exp = ExponentialBackoff::new(Duration::ZERO, 1, &mut rng);
        assert_eq!(exp.rto(), Duration::from_nanos(1));
        exp.rto = Duration::MAX;
        exp.attempt(&mut rng);
        assert_eq!(exp.rto, Duration::MAX);
    }

    #[test]
    fn attempts() {
        let mut rng = SeededRng::new(Some(42));
        let mut exp = ExponentialBackoff::new(Duration::from_secs(1), 5, &mut rng);

        let n1 = dbg!(exp.rto().as_millis());
        assert_eq!(exp.rto().as_millis(), n1);

        exp.attempt(&mut rng);

        let n2 = dbg!(exp.rto().as_millis());
        assert_eq!(exp.rto().as_millis(), n2);
        assert!(n2 > n1);

        exp.attempt(&mut rng);

        let n3 = dbg!(exp.rto().as_millis());
        assert_eq!(exp.rto().as_millis(), n3);
        assert!(n3 > n2);

        exp.attempt(&mut rng);

        let n4 = dbg!(exp.rto().as_millis());
        assert_eq!(exp.rto().as_millis(), n4);
        assert!(n4 > n3);
        assert!(exp.can_retry());

        exp.attempt(&mut rng);

        let n5 = dbg!(exp.rto().as_millis());
        assert_eq!(exp.rto().as_millis(), n5);
        assert!(n5 > n4);
        assert!(exp.can_retry());

        exp.attempt(&mut rng);

        let n6 = dbg!(exp.rto().as_millis());
        assert_eq!(exp.rto().as_millis(), n6);
        assert!(n6 > n5);
        assert!(!exp.can_retry());

        exp.attempt(&mut rng);

        assert_eq!(exp.rto().as_millis(), n6);
        assert!(!exp.can_retry());
    }
}
