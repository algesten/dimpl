use crate::message::Sequence;

/// Sliding replay window for DTLS records (per current epoch).
///
/// Maintains the latest accepted sequence number and a 64-bit bitmap of the
/// last 64 seen sequence numbers to reject duplicates and old records.
#[derive(Debug, Default)]
pub struct ReplayWindow {
    epoch: u16,
    max_seq: u64,
    window: u64,
}

impl ReplayWindow {
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if the given sequence is acceptable and update the window state.
    /// Returns true if fresh/acceptable, false if duplicate/too old/old epoch.
    pub fn check_and_update(&mut self, seq: Sequence) -> bool {
        // Epoch handling
        if seq.epoch != self.epoch {
            if seq.epoch < self.epoch {
                // Old epoch: reject
                return false;
            }
            // New epoch: reset window
            self.epoch = seq.epoch;
            self.max_seq = 0;
            self.window = 0;
        }

        let seqno = seq.sequence_number;
        if seqno > self.max_seq {
            let delta = seqno - self.max_seq;
            let shift = core::cmp::min(delta, 63);
            self.window <<= shift;
            self.window |= 1; // mark newest as seen
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
    use crate::message::Sequence;

    fn seq(epoch: u16, n: u64) -> Sequence {
        Sequence {
            epoch,
            sequence_number: n,
        }
    }

    #[test]
    fn accepts_fresh_and_rejects_duplicate() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_update(seq(1, 1)));
        assert!(!w.check_and_update(seq(1, 1))); // duplicate
        assert!(w.check_and_update(seq(1, 2))); // next fresh
    }

    #[test]
    fn accepts_out_of_order_within_window() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_update(seq(1, 10))); // establish max=10
        assert!(w.check_and_update(seq(1, 8))); // unseen within 64
        assert!(!w.check_and_update(seq(1, 8))); // duplicate now
        assert!(w.check_and_update(seq(1, 9))); // unseen within 64
    }

    #[test]
    fn rejects_too_old() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_update(seq(1, 100)));
        // offset = 64 -> too old
        assert!(!w.check_and_update(seq(1, 36)));
        // offset = 63 -> allowed once
        assert!(w.check_and_update(seq(1, 37)));
    }

    #[test]
    fn handles_large_jump_and_window_shift() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_update(seq(1, 1)));
        // Large forward jump; shifting is capped at 63, but semantics remain correct
        assert!(w.check_and_update(seq(1, 80)));
        // Within window of new max and unseen
        assert!(w.check_and_update(seq(1, 79)));
        // Too old relative to new max
        assert!(!w.check_and_update(seq(1, 15)));
    }

    #[test]
    fn handles_epoch_changes() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_update(seq(0, 5)));
        // Move to next epoch resets window
        assert!(w.check_and_update(seq(1, 1)));
        // Regression in epoch must be rejected
        assert!(!w.check_and_update(seq(0, 6)));
        // Forward epoch continues to work
        assert!(w.check_and_update(seq(2, 1)));
    }
}
