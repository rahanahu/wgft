# WireGuard handshake source storage

[日本語](wireguard-sources.ja.md)

Each userspace WireGuard Device uses an admission threshold of 1024 source IP keys.
The guard applies the same admission and recovery policy to userspace servers and agents on Linux, Windows and macOS, without modifying wireguard-go.

## Admission and recovery

An outer single-datagram bind checks only exact initiation packets of 148 bytes and response packets of 92 bytes.
It reads the pinned wireguard-go limiter's one combined IPv4/IPv6 map under its actual `sync.RWMutex`.
The exact `StdNetEndpoint.DstIP()` key is used without normalization.
An existing key passes the capacity check; an unseen key is dropped when the map contains at least 1024 keys.
A busy table lock or unsupported candidate endpoint also drops only that candidate.
The `TryRLock` check does not wait for the limiter lock, so lock contention does not hold up the receive path.
Cookie replies, transport data, malformed packets and receive errors retain the dependency's handling.
The guard does not authenticate packets or replace WireGuard's cryptography or token bucket.
It retains no source-keyed ledger or diagnostic history.

At exhaustion, a new agent or an agent whose public IP changed can lose handshake attempts.
Existing-source handshakes can retain occupancy when they reach the limiter under load.
After candidate traffic stops and bounded pending handshakes finish, the dependency's existing garbage collector removes idle entries and admission recovers without recreating the Device.
Recovery depends on scheduler and queue progress; no fixed recovery deadline or fairness guarantee is promised.

## Count and practical allowance

Let `C=1024`, `Q=1024` queued handshakes, `W=runtime.NumCPU()` handshake workers at construction, and `R<=2` active receive functions.
The union of table keys and already admitted pending source keys has at most `H=C+Q+W+R` members.
Existing-source admission adds no member; unseen-source admission sees fewer than C table keys, and other absent admitted keys fit the bounded pending work.
Later limiter insertion only promotes a pending key into the table.
Deletion and recreation by garbage collection do not add another overshoot term.
The live table therefore contains at most H keys, with at most `H+W+1` entry objects including worker and collector locals.

A proposed planning allowance is `64 KiB + 256*(H+W+1)` bytes.
For C1024 and R2 this is `64 KiB + 256*(2051+2W)`: about 609 KiB at W64, 705 KiB at W256 and 833 KiB at W512.
The coefficient is a deliberately loose engineering allowance, not an allocator theorem.
Map backing, previous growth allocations and Go garbage collection headroom remain ordinary operational residuals.
This result bounds source/entry counts; it is not a universal 1 MiB limit or a strict process RSS guarantee.
Raw datagrams held inside BatchOne remain part of its separately bounded receive storage.

## Pinned observation and lifecycle

The read-only shim validates the exact limiter, mutex and map types before allowing the inner bind to open.
Typed address reflection reaches the actual mutex; it never copies a mutex or writes private dependency fields.
Map length and membership are read during one successful `TryRLock` interval.
Unsupported layouts fail construction rather than admitting unobserved traffic.
Every Open validates the single-item batch contract and one or two nonnil receive functions.

Construction publishes a readiness result after NewDevice returns, since an early queued TUN event can call Open before attachment.
Open waits for that result before opening the inner bind.
Ordinary bind Close does not cancel attachment; BindUpdate calls Close even before its first Open.
Attachment errors wake waiting Open calls before Device.Close.
Managed Close permanently detaches the observer after Device.Close joins receive routines.
Device.Close does not join handshake workers: bounded pending work in a retired Device remains a separate lifetime term.
This guard does not establish that dependency shutdown cannot panic.

Benign unit fixtures cover exact packet and key boundaries, the real limiter lock, exhaustion and garbage collection recovery, early attachment, reopen and permanent detach.
Allocator coefficient sufficiency remains unmeasured.
Platform checks do not establish the coefficient's sufficiency or a universal memory limit.

[Userspace specification](README.md)
