//! The crypto's own cost on the measured CPU, to read the crypto share of a run: a pair of devices
//! connected in memory, and the encryption and decryption of one packet timed alone.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use wgft_wireguard::{DEFAULT_KEEPALIVE, Device, DeviceConfig, PrivateKey};

use super::cpu::Cpu;
use super::error::Error;
use super::{SERVER_IP, server_config};

/// Packets timed per direction.
const ROUNDS: u32 = 4000;

/// The thread CPU time of one encryption and one decryption of `packet`.
pub(super) fn crypto_cost(packet: &[u8]) -> Result<(Duration, Duration), Error> {
    let agent_key = PrivateKey::generate(&[0xc1; 32]);
    let server_key = PrivateKey::generate(&[0xd2; 32]);
    let agent_addr: SocketAddr = "198.51.100.2:40000"
        .parse()
        .map_err(|_| Error::failed("address"))?;
    let server_addr: SocketAddr = "203.0.113.1:51820"
        .parse()
        .map_err(|_| Error::failed("address"))?;
    let now = Instant::now();
    let fail = |e: wgft_wireguard::ConfigError| Error::failed(format!("{e:?}"));
    let mut agent = Device::new(
        DeviceConfig::agent(
            agent_key.clone(),
            server_key.public_key(),
            Some(server_addr),
            SERVER_IP,
            DEFAULT_KEEPALIVE,
        ),
        now,
        Duration::ZERO,
    )
    .map_err(fail)?;
    let mut server = Device::new(
        server_config(server_key, agent_key.public_key()),
        now,
        Duration::ZERO,
    )
    .map_err(fail)?;
    agent.handle_timeout(now);
    let mut buf = vec![0; usize::from(u16::MAX)];
    for _ in 0..4 {
        while let Some(t) = agent.poll_transmit() {
            server.handle_datagram(now, agent_addr, &t.payload, &mut buf);
        }
        while let Some(t) = server.poll_transmit() {
            agent.handle_datagram(now, server_addr, &t.payload, &mut buf);
        }
    }
    let n = ROUNDS as usize;
    let len = agent.max_transmit_len();
    let mut sealed = vec![0u8; n * len];
    // 時計は loop の全体で 1 回ずつ読み、1 回の読みの費用を暗号の時間に入れない
    let mut jobs = Vec::with_capacity(n);
    for _ in 0..n {
        jobs.push(
            agent
                .begin_packet(now, packet, len)
                .ok_or_else(|| Error::failed("no session for the calibration"))?,
        );
    }
    let start = Cpu::now();
    let lens: Vec<usize> = jobs
        .into_iter()
        .zip(sealed.chunks_mut(len))
        .map(|(job, out)| job.seal(packet, out).map_or(0, |o| o.len))
        .collect();
    let seal = Cpu::now().since(start).total;
    let datagrams: Vec<&[u8]> = sealed
        .chunks(len)
        .zip(&lens)
        .map(|(d, &l)| &d[..l])
        .collect();
    let mut jobs = Vec::with_capacity(n);
    for d in &datagrams {
        jobs.push(
            server
                .begin_datagram(now, agent_addr, d)
                .ok_or_else(|| Error::failed("the calibration datagram was dropped"))?,
        );
    }
    let mut plain = vec![0u8; n * len];
    let start = Cpu::now();
    let opened: Vec<_> = jobs
        .into_iter()
        .zip(&datagrams)
        .zip(plain.chunks_mut(len))
        .map(|((job, d), out)| job.open(d, out))
        .collect();
    let open = Cpu::now().since(start).total;
    for ((o, d), out) in opened.into_iter().zip(&datagrams).zip(plain.chunks(len)) {
        if server
            .finish_datagram(now, agent_addr, d.len(), o, out)
            .is_none()
        {
            return Err(Error::failed("the calibration packet was not delivered"));
        }
    }
    Ok((seal / ROUNDS, open / ROUNDS))
}
