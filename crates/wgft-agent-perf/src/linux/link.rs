//! One end of the tunnel: a socket and the device layer on it. These adapters are what the data
//! plane's own socket calls would replace; keep the workload unchanged when they change.

use std::net::{SocketAddr, UdpSocket};
use std::time::Instant;

use wgft_wireguard::{Device, Outgoing, PublicKey, Transmit};

use super::cpu::wait;

/// System calls the data path made, counted by the tool itself.
#[derive(Debug, Default, Clone, Copy)]
pub(super) struct Syscalls {
    /// `sendto` and `recvfrom`, the final `WouldBlock` read included.
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
}

impl Link {
    pub(super) fn new(socket: UdpSocket, device: Device) -> Self {
        let buf = vec![0; device.max_transmit_len() + 64];
        let sealed = vec![0; device.max_transmit_len()];
        Self {
            socket,
            device,
            delivered: 0,
            buf,
            plain: vec![0; usize::from(u16::MAX)],
            sealed,
            direct: None,
        }
    }

    /// The adapter to the device layer's encrypt side: one inner packet in.
    pub(super) fn encrypt(&mut self, now: Instant, packet: &[u8]) {
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

    /// Sends every datagram the device layer has, one `sendto` each.
    pub(super) fn send_pending(&mut self, calls: &mut Syscalls) -> std::io::Result<()> {
        while let Some(Transmit { to, payload }) = self.device.poll_transmit() {
            send_datagram(&self.socket, to, &payload, calls)?;
        }
        if let Some(out) = self.direct.take() {
            send_datagram(&self.socket, out.to, &self.sealed[..out.len], calls)?;
        }
        Ok(())
    }

    /// Reads until the socket is empty, one `recvfrom` each and one for the `WouldBlock`.
    /// Returns the datagrams read.
    pub(super) fn receive_all(
        &mut self,
        now: Instant,
        calls: &mut Syscalls,
    ) -> std::io::Result<u64> {
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

    /// Runs the device's timer if it is due.
    pub(super) fn tick(&mut self, now: Instant) {
        if self.device.poll_timeout().is_some_and(|t| t <= now) {
            self.device.handle_timeout(now);
        }
    }
}

impl Link {
    /// The server's public key as the agent knows it.
    pub(super) fn server_key(&self) -> PublicKey {
        self.device
            .peers()
            .next()
            .expect("the agent has its server as a peer")
    }
}
