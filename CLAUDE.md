# CLAUDE.md

Code style guide for Claude sessions working on dimpl.

## File Ordering

1. Imports
2. Constants
3. Primary type (matches module name: `foo.rs` → `struct Foo`)
4. Related types, ordered by first appearance in primary type's fields/variants
5. `impl` block for primary type
6. Helper types and functions
7. Standard trait impls (`Display`, `Debug`, `From`)
8. Tests (`#[cfg(test)] mod tests`)

Example: `struct Foo { bar: Bar, baz: Baz }` → define `Bar` before `Baz`.

## State Machine Files (client.rs, server.rs)

Protocol flow dictates ordering throughout:

1. Module-level comment documenting the protocol flow
2. Imports
3. Primary struct (`Client` / `Server`)
4. `State` enum (variants in protocol order)
5. `impl PrimaryType` (public API: `new`, `handle_*`, `poll_*`)
6. `impl State` (`name()`, `make_progress()`, then handlers in enum order)
7. Free helper functions (ordered by first use in protocol flow)

## Imports

Group: std → external → crate. Alphabetical within groups.

```rust
use std::collections::VecDeque;
use std::time::Instant;

use arrayvec::ArrayVec;

use crate::buffer::Buf;
use crate::engine::Engine;
```

Use short paths: `std::Vec` not `std::vec::Vec`.

## Modules

Private modules with selective re-exports:

```rust
mod certificate;
pub use certificate::Certificate;
```

## Visibility

Prefer `pub` over `pub(crate)`. Only use `pub(crate)` when explicitly preventing
items from becoming part of the public API. Internal modules that are kept private
by their parent don't need `pub(crate)` on their items.

```rust
// Good: parent module is private, so pub here won't leak
mod internal {
    pub struct Helper;  // Not in public API because `internal` is private
}

// Bad: unnecessary restriction
mod internal {
    pub(crate) struct Helper;  // Redundant - parent already private
}
```

## Fields and Methods

Fields are private. Expose via getter methods.

## Documentation

Doc examples must compile and run as tests. Never use `ignore`. Use `no_run` only
when hardware/network required.

## Unwrap

Comment `unwrap()` calls explaining why they're safe:

```rust
// unwrap: is ok because we set the random in handle_timeout
let random = self.random.unwrap();
```

## Sans-IO API Contract

dimpl is Sans-IO: no sockets, no threads, no async. The caller drives I/O.

**Poll-to-Timeout Rule**: Every mutation (`handle_packet`, `handle_timeout`) must
be followed by polling until `Output::Timeout`:

```rust
client.handle_timeout(now);
loop {
    match client.poll_output(&mut buf) {
        Output::Packet(data) => { /* send to peer */ }
        Output::Connected => { /* handshake complete */ }
        Output::Timeout(when) => break,
    }
}
```

Never stop polling early. Internal state is only consistent after reaching `Timeout`.

## Memory

**Summary**: Allocation-conscious design - pool reuse, single-copy, in-place
mutation, boxing for ABI, bounded stack collections.

**Buffer Pooling**
- Reuse allocations instead of malloc/free per packet
- Clear contents but retain capacity

**Single-Copy Parsing**
- One copy from network into working buffer
- Parse and decrypt in-place on that buffer

**ABI Optimization**
- Box large inner data so outer structs fit in registers
- Avoids memmove on function calls

**Bounded Stack Collections**
- Fixed-capacity arrays for small, known-bounded collections
- Fail explicitly if bounds exceeded
