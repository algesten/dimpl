# Outstanding Allocation Issues

Remaining heap allocations in DTLS 1.3 source code (non-test) that could be eliminated.

## 1. `pop_buffer_internal` bypasses pool — engine.rs:2091

`pop_buffer_internal(&self)` returns `Buf::new()` (fresh allocation) because it takes
`&self` not `&mut self`, so it can't reach the buffer pool. Called from
`derive_early_secret()` which chains into `derive_handshake_secrets()`. The key schedule
creates multiple fresh `Buf`s this way when pool buffers are sitting right there.

**Fix**: Restructure derivation functions to capture `hkdf()`/`hash_algorithm()` references
first, then use `&mut self` for pool access. Moderate refactor — methods chain through each
other and interleave `&self` borrows with buffer creation. High payoff: ~5-6 allocs per
handshake.

**Difficulty**: Moderate

## 2. Certificate extraction triple-copy — client.rs:743-756, server.rs:817-835

The flow is: `defragment_buffer` slice → `.to_vec()` into a `Vec<u8>` inside an
`ArrayVec<_, 32>` → copy into `Buf::new()` + `extend_from_slice` → push into
`server_certificates`. Three allocations per certificate.

Root cause: `certificate` borrows `defragment_buffer`, so you can't push to
`server_certificates` (also on `client`) until you drop the borrow.

**Fix**: Store just the `Range<usize>` offsets in the ArrayVec (no alloc), drop the borrow,
then copy from `defragment_buffer` using the ranges directly into `server_certificates`.
Or temporarily `mem::take` the `defragment_buffer`.

**Difficulty**: Medium (borrow restructure)

## 3. `local_events: VecDeque<LocalEvent>` — client.rs:102, server.rs:104

At most 2-3 events queued. VecDeque's initial allocation is small but nonzero. One
allocation per connection lifetime.

**Fix**: `ArrayVec<LocalEvent, 4>` with pop-from-front semantics. Low priority — VecDeque
is a natural fit for the FIFO pattern and the cost is negligible.

**Difficulty**: Low priority
