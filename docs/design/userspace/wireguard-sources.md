# WireGuard handshake source storage

[日本語](wireguard-sources.ja.md)

Each userspace WireGuard Device keys wireguard-go's handshake rate limiter by one of `K=1024` bucket addresses instead of by the source IP.
The limiter table therefore holds at most K keys, whatever the number of sources and however late the dependency collects idle entries.
The same mechanism applies to userspace servers and agents on Linux, Windows and macOS.
It uses only wireguard-go's public API and does not modify the dependency.

## Bucket keys

The outer bind wraps the endpoint of each received initiation of 148 bytes and response of 92 bytes.
wireguard-go's receive path puts only these packets into the handshake queue, and only the handshake workers call the limiter.
The wrapper's `DstIP()` returns one of K synthetic addresses in `240.0.0.0/4`.
A keyed hash of the source chooses the address: `hash/maphash` with a random seed per Device.
An IPv6 source is hashed by its /64 prefix, the same granularity as the kernel WireGuard limiter, because one host commonly holds a whole /64.
IPv4 and IPv4-mapped IPv6 addresses are hashed by the full address, as different inputs; an IPv6 zone is not used.
Every other endpoint method passes through to the received endpoint.
These include `DstToBytes()`, which the MAC2 check and cookie replies use, `DstToString()`, which UAPI and logs use, and `ClearSrc()`.

The bind's `Send` unwraps the endpoint before calling the inner bind.
The standard bind requires `*conn.StdNetEndpoint` and chooses the IPv4 or IPv6 socket from `DstIP()`.
After a handshake a peer stores the wrapper as its endpoint, so every send to that peer goes through this unwrap.
The synthetic addresses are reserved and are never used as a destination.

In the pinned wireguard-go version the Device uses a received endpoint's `DstIP()` only as the limiter key.
The Linux route listener also reads it, but it starts only when the bind is `*conn.StdNetBind`, and wgft's bind never is.
A unit test fails when `go.mod` requires a different wireguard-go version, so an update must recheck these uses before changing the pin.

The bind drops no packet and keeps no per-source state.
Transport data, cookie replies, malformed packets and receive errors keep the dependency's handling.
The wrapper does not authenticate packets or replace WireGuard's cryptography.

## Protection and trade-off

While the Device is not under load, the dependency does not consult the limiter, and handshakes are unaffected.
Under load, a handshake still reaches the limiter only with a valid MAC1 and a valid MAC2.
The MAC2 cookie is bound to the real source address and port, so the sender must receive cookie replies at that address.
In this section a source is an IPv4 address or an IPv6 /64.
Sources that hash to the same bucket share one token bucket of 20 handshakes per second with a burst of up to 5.

A sender that floods MAC2-valid handshakes from a source therefore throttles, under load, the peers that hash to the same bucket.
With S flooding sources, a given peer shares a flooded bucket with probability `1-(1-1/K)^S`, about `S/K` for small S.
The per-Device seed hides the mapping, so a sender cannot aim at a chosen peer except by adding sources.
Covering every bucket needs on the order of `K*ln(K)`, about 7,100, distinct non-blind IPv4 addresses or IPv6 /64s, together sending over 20 handshakes per second into each bucket.
A peer in an unflooded bucket keeps handshaking without delay.
No admission state exists, so nothing needs to recover after a flood stops.
The limiter passes at most about 20 handshakes per second per bucket, so under load the handshakes that pass it are also bounded to about `20*K` per second plus bursts.

## Count and practical allowance

Let `Q=1024` queued handshakes, `W=runtime.NumCPU()` handshake workers at construction, and `R<=2` active receive functions.
The limiter table holds at most K keys.
Counting an entry that each worker can hold outside the table and the collector's local, at most `K+W+1` entry objects are live.
Each wrapper is one 48-byte allocation, measured as bytes per operation on Linux amd64.
At most `Q+W+R` wrappers belong to pending handshake work; a wrapper that a peer stores as its endpoint replaces the peer's previous endpoint.

The planning allowance is `64 KiB + 256*(K+W+1) + 48*(Q+W+R)` bytes.
For K1024 and R2 this is `64 KiB + 256*(1025+W) + 48*(1026+W)`: about 387 KiB at W64, 444 KiB at W256 and 520 KiB at W512.
The coefficient 256 is a deliberately loose engineering allowance, not an allocator theorem.
Map backing, previous growth allocations and Go garbage collection headroom remain ordinary operational residuals.
This result bounds key, entry and wrapper counts; it is not a strict process RSS guarantee.
Raw datagrams held inside BatchOne remain part of its separately bounded receive storage.
Device.Close does not join handshake workers, so pending work in a retired Device remains a separate lifetime term.
This design does not establish that dependency shutdown cannot panic.
Device.Close closes the limiter while handshakes can still be queued, and a later `Allow` that inserts the first key into an empty table sends on the closed channel and panics.

## Alternatives not adopted

Reading the limiter table through reflection depends on unexported dependency fields; an update that kept their types but changed their meaning would go undetected.
An outer set of admitted sources with an expiry cannot observe the table through the public API.
Its bound would then depend on the limiter's collection finishing within the expiry.
A token probe cannot detect a longer retention, because a new entry and a refilled idle entry give the same `Allow` results and the limiter's clock cannot be replaced.
Such a set also cannot verify MAC2, so a blind spoofer could occupy it.
Counting only MAC1-valid packets would not close this, since MAC1 does not bind the source address and a captured handshake replayed from spoofed sources passes it.
That check would also run on the receive goroutines, at most two, so a flood of initiation-shaped packets would slow data-plane receive.
Inferring MAC2 by tracking outgoing cookie replies needs bounded tracking that a flood can saturate.
Exempting peers' current endpoints from the set would add the peer count to the bound.

## Verification

Unit tests cover the exact packet boundaries, the passthrough methods, unwrapping on send, the K-key bound under churn of 200,000 sources, the per-Device keying, and the IPv6 /64 grouping.
With a real limiter, a peer outside the flooded buckets passes while a peer sharing one is throttled.
A concurrent test runs two receive functions and sends under the race detector.
Tests with two real Devices on IPv4 and IPv6 loopback cover a handshake, the UAPI endpoint and a listen-port change.
A flood of MAC1-valid initiations puts a real Device under load.
The test then checks that the cookie reply reaches the real source.
It sends 20 initiations carrying that cookie's MAC2 at once and requires between 1 and 10 of them to reach the handshake consumer, so the rest were dropped by the limiter.
Before closing the Device, it waits for the handshake workers to go idle, because of the shutdown race above.
Under the race detector the flood sometimes cannot keep the Device under load until the initiations are processed, and the test then skips instead of failing.
On the development machine the receive path adds about 34 ns per handshake datagram; other datagrams take no allocation.
The allocator coefficient's sufficiency remains unmeasured.

[Userspace specification](README.md)
