/// Sliding replay window for DTLS record sequence numbers.
///
/// Maintains the latest accepted sequence number and a 64-bit bitmap of the
/// last 64 seen sequence numbers to reject duplicates and old records.
///
/// Each epoch should have its own `ReplayWindow` instance. The caller is
/// responsible for routing records to the correct per-epoch window.
#[derive(Debug, Default)]
pub struct ReplayWindow {
    max_seq: u64,
    window: u64,
}

impl ReplayWindow {
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if the given sequence number is acceptable and update the window state.
    /// Returns true if fresh/acceptable, false if duplicate/too old.
    pub fn check_and_update(&mut self, seqno: u64) -> bool {
        if seqno > self.max_seq {
            let delta = seqno - self.max_seq;
            if delta > 63 {
                // Jump exceeds window size: clear entirely, only newest is seen
                self.window = 1;
            } else {
                self.window <<= delta;
                self.window |= 1; // mark newest as seen
            }
            self.max_seq = seqno;
            true
        } else {
            let offset = self.max_seq - seqno;
            if offset >= 64 {
                return false; // too old
            }
            let mask = 1u64 << offset;
            if (self.window & mask) != 0 {
                return false; // duplicate
            }
            self.window |= mask;
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_fresh_and_rejects_duplicate() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_update(1));
        assert!(!w.check_and_update(1)); // duplicate
        assert!(w.check_and_update(2)); // next fresh
    }

    #[test]
    fn accepts_out_of_order_within_window() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_update(10)); // establish max=10
        assert!(w.check_and_update(8)); // unseen within 64
        assert!(!w.check_and_update(8)); // duplicate now
        assert!(w.check_and_update(9)); // unseen within 64
    }

    #[test]
    fn rejects_too_old() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_update(100));
        // offset = 64 -> too old
        assert!(!w.check_and_update(36));
        // offset = 63 -> allowed once
        assert!(w.check_and_update(37));
    }

    #[test]
    fn handles_large_jump_and_window_shift() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_update(1));
        // Large forward jump clears the window entirely
        assert!(w.check_and_update(80));
        // Within window of new max and unseen
        assert!(w.check_and_update(79));
        // Too old relative to new max
        assert!(!w.check_and_update(15));
    }

    #[test]
    fn large_jump_does_not_leave_stale_bits() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_update(0));
        // Jump of 200 exceeds window size (64). The window must be fully
        // cleared so no stale bits from seq 0 remain.
        assert!(w.check_and_update(200));
        // seq 137 is within the window (offset = 200 - 137 = 63) and was
        // never seen, so it must be accepted.
        assert!(w.check_and_update(137));
    }
}
