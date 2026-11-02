//! One end of the tunnel: a socket and the device layer on it. These adapters are what the data
//! plane's own socket calls would replace; keep the workload unchanged when they change.

use std::net::{SocketAddr, UdpSocket};
use std::os::fd::AsRawFd;
use std::time::Instant;

use wgft_udp_batch::crypto::Crypto;
use wgft_udp_batch::{MAX_SLOTS, RX_SLOT, RxBatch, TxBatch, sys};
use wgft_wireguard::{Device, Outgoing, PublicKey, Transmit};

use super::cpu::wait;

/// System calls the data path made, counted by the tool itself.
#[derive(Debug, Default, Clone, Copy)]
pub(super) struct Syscalls {
    /// `sendto`, `recvfrom`, `sendmmsg` and `recvmmsg`, the final `WouldBlock` read included.
    pub(super) data: u64,
    /// The readiness check once per burst, standing in for the data plane's `epoll_wait`.
    pub(super) wake: u64,
}

/// Sends one datagram, waiting while the socket is full.
fn send_datagram(
    socket: &UdpSocket,
    to: SocketAddr,
    payload: &[u8],
    calls: &mut Syscalls,
) -> std::io::Result<()> {
    loop {
        match socket.send_to(payload, to) {
            Ok(_) => {
                calls.data += 1;
                return Ok(());
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                wait(socket, libc::POLLOUT, 100)?;
            }
            Err(e) => return Err(e),
        }
    }
}

/// One end: a socket and the device layer on it.
pub(super) struct Link {
    pub(super) socket: UdpSocket,
    pub(super) device: Device,
    /// Decrypted packets handed up so far.
    pub(super) delivered: u64,
    buf: Vec<u8>,
    /// The device layer decrypts into this buffer.
    plain: Vec<u8>,
    /// The device layer encrypts into this buffer; `direct` names the datagram it holds.
    sealed: Vec<u8>,
    direct: Option<Outgoing>,
    /// The data plane's batch store, when batching: the packets of a burst are sealed into its send
    /// slots and sent with `sendmmsg`, UDP GSO joining runs of one length, and datagrams are read
    /// with `recvmmsg` and UDP GRO.
    batch: Option<Batch>,
}

struct Batch {
    rx: RxBatch,
    tx: TxBatch,
    gso: bool,
    /// The crypto workers and their lanes, with `--crypto-workers`: the split device calls of the data
    /// plane's parallel path. Packets wait in the packet slots until the batch is sealed.
    crypto: Option<Crypto>,
    /// Packets written into the packet slots and not sealed yet, with `crypto`.
    pending: usize,
}

/// How the measured end runs its crypto: on the data plane's crypto workers (`lanes - 1` of them),
/// a round of fewer than `min_bytes` bytes on the measured thread alone.
#[derive(Clone, Copy, Debug)]
pub(super) struct Lanes {
    pub(super) lanes: usize,
    pub(super) min_bytes: usize,
}

impl Link {
    /// One end. With `lanes`, make it on the thread that measures it: the crypto workers' owner.
    pub(super) fn new(
        socket: UdpSocket,
        device: Device,
        batching: bool,
        lanes: Option<Lanes>,
    ) -> Self {
        let buf = vec![0; device.max_transmit_len() + 64];
        let sealed = vec![0; device.max_transmit_len()];
        let batch = batching.then(|| {
            let fd = socket.as_raw_fd();
            // データプレーンと同じく、GRO を有効にし、GSO の有無を調べる
            let _ = sys::enable_gro(fd);
            let n = lanes.map_or(1, |l| l.lanes);
            let rx = RxBatch::new(MAX_SLOTS, true, device.max_transmit_len(), n);
            Batch {
                crypto: lanes.map(|l| Crypto::new(rx.plain.len(), l.min_bytes)),
                rx,
                tx: TxBatch::new(MAX_SLOTS, true, device.mtu(), device.max_transmit_len(), n),
                gso: sys::has_gso(fd),
                pending: 0,
            }
        });
        Self {
            socket,
            device,
            delivered: 0,
            buf,
            plain: vec![0; usize::from(u16::MAX)],
            sealed,
            direct: None,
            batch,
        }
    }

    /// The adapter to the device layer's encrypt side: one inner packet in. When batching, the
    /// packet goes through a send slot as the data plane's core writes it, into the next sealed
    /// slot.
    pub(super) fn encrypt(&mut self, now: Instant, packet: &[u8]) {
        if let Some(b) = &mut self.batch {
            if b.crypto.is_some() {
                let mut slots = b.tx.packet_slots();
                slots.slot(b.pending)[..packet.len()].copy_from_slice(packet);
                slots.set_len(b.pending, packet.len());
                b.pending += 1;
                return;
            }
            let i = b.tx.n_sealed;
            let mut slots = b.tx.packet_slots();
            slots.slot(i)[..packet.len()].copy_from_slice(packet);
            slots.set_len(i, packet.len());
            let (p, out) = b.tx.seal_slot(i);
            if let Some(o) = self.device.handle_packet(now, p, out) {
                b.tx.push_sealed(o.to, o.len);
            }
            return;
        }
        self.direct = self.device.handle_packet(now, packet, &mut self.sealed);
    }

    /// The adapter to the device layer's decrypt side: one datagram in, decrypted packets counted.
    fn decrypt(&mut self, now: Instant, from: SocketAddr, n: usize) {
        if self
            .device
            .handle_datagram(now, from, &self.buf[..n], &mut self.plain)
            .is_some()
        {
            self.delivered += 1;
        }
    }

    /// Sends every datagram the device layer has, one `sendto` each, then the sealed batch with
    /// `sendmmsg`, or the one sealed datagram with `sendto`.
    pub(super) fn send_pending(&mut self, calls: &mut Syscalls) -> std::io::Result<()> {
        while let Some(Transmit { to, payload }) = self.device.poll_transmit() {
            send_datagram(&self.socket, to, &payload, calls)?;
        }
        if let Some(b) = &mut self.batch {
            if let Some(c) = &mut b.crypto
                && b.pending > 0
            {
                c.seal(&mut b.tx, &mut self.device, Instant::now(), b.pending)
                    .map_err(std::io::Error::other)?;
                b.pending = 0;
            }
            if b.tx.n_sealed == 0 {
                return Ok(());
            }
            b.tx.lay_out(0, b.gso);
            while b.tx.is_pending() {
                calls.data += 1;
                match b.tx.send(self.socket.as_raw_fd()) {
                    Ok(n) => b.tx.next += n.max(1),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        wait(&self.socket, libc::POLLOUT, 100)?;
                    }
                    Err(e) => return Err(e),
                }
            }
            b.tx.clear();
            return Ok(());
        }
        if let Some(out) = self.direct.take() {
            send_datagram(&self.socket, out.to, &self.sealed[..out.len], calls)?;
        }
        Ok(())
    }

    /// Whether to send after this packet: always without batching, and when the send slots are
    /// full with it.
    pub(super) fn send_each(&self) -> bool {
        self.batch.as_ref().is_none_or(|b| {
            if b.crypto.is_some() {
                b.pending == b.tx.slots()
            } else {
                b.tx.n_sealed == b.tx.slots()
            }
        })
    }

    /// Reads until the socket is empty, one `recvfrom` or `recvmmsg` each and one for the
    /// `WouldBlock`. Returns the datagrams read, a GRO buffer's segments each.
    pub(super) fn receive_all(
        &mut self,
        now: Instant,
        calls: &mut Syscalls,
    ) -> std::io::Result<u64> {
        if self.batch.is_some() {
            return self.receive_batches(now, calls);
        }
        let mut read = 0;
        loop {
            calls.data += 1;
            match self.socket.recv_from(&mut self.buf) {
                Ok((n, from)) => {
                    self.decrypt(now, from, n);
                    read += 1;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(read),
                Err(e) => return Err(e),
            }
        }
    }

    /// [`Link::receive_all`] with `recvmmsg` into the batch store, decrypting into its plaintext
    /// area as the data plane does.
    fn receive_batches(&mut self, now: Instant, calls: &mut Syscalls) -> std::io::Result<u64> {
        let fd = self.socket.as_raw_fd();
        let Some(b) = &mut self.batch else {
            return Ok(0);
        };
        let mut read = 0;
        loop {
            calls.data += 1;
            let n = match b.rx.recv(fd, MAX_SLOTS) {
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(read),
                Err(e) => return Err(e),
            };
            if let Some(c) = &mut b.crypto {
                read += datagrams(&b.rx, n);
                c.start_open(&b.rx, n);
                while c
                    .open_round(&mut b.rx, &mut self.device, now)
                    .map_err(std::io::Error::other)?
                {
                    let (u, o) = c.each_packet(&b.rx, true, |_| {});
                    self.delivered += (u + o) as u64;
                }
                continue;
            }
            let device = &mut self.device;
            let mut delivered = 0;
            b.rx.decrypt_each(n, |from, datagram, out| {
                read += 1;
                match device.handle_datagram(now, from, datagram, out) {
                    Some(got) => {
                        delivered += 1;
                        got
                    }
                    None => 0,
                }
            });
            self.delivered += delivered;
        }
    }

    /// Runs the device's timer if it is due.
    pub(super) fn tick(&mut self, now: Instant) {
        if self.device.poll_timeout().is_some_and(|t| t <= now) {
            self.device.handle_timeout(now);
        }
    }
}

/// The datagrams in the first `n` filled slots, a GRO buffer's segments each.
fn datagrams(rx: &RxBatch, n: usize) -> u64 {
    rx.meta[..n]
        .iter()
        .filter(|m| m.from.is_some())
        .map(|m| {
            let len = (m.len as usize).min(RX_SLOT);
            let seg = if m.seg == 0 {
                len.max(1)
            } else {
                m.seg as usize
            };
            len.div_ceil(seg) as u64
        })
        .sum()
}

impl Link {
    /// The crypto workers that started, with `--crypto-workers`.
    pub(super) fn workers(&self) -> Option<usize> {
        self.batch
            .as_ref()
            .and_then(|b| b.crypto.as_ref())
            .map(Crypto::workers)
    }

    /// The server's public key as the agent knows it.
    pub(super) fn server_key(&self) -> PublicKey {
        self.device
            .peers()
            .next()
            .expect("the agent has its server as a peer")
    }
}
