//! 核の誤りを `io::Error` にします。核の誤りは中に置くので、呼び手は `io::Error::get_ref` と `downcast_ref`
//! で [`wgft_wgstack::Error`] を取り出せます。

use std::io;

use wgft_wgstack::Error;

/// 核の誤り `e` の `io::Error` です。`WouldBlock` は handle の層が待ちにするので、ここには来ません。
pub(crate) fn io_error(e: Error) -> io::Error {
    let kind = match e {
        Error::WouldBlock => io::ErrorKind::WouldBlock,
        Error::Closed => io::ErrorKind::NotConnected,
        Error::Reset => io::ErrorKind::ConnectionReset,
        Error::BrokenPipe => io::ErrorKind::BrokenPipe,
        Error::TimedOut => io::ErrorKind::TimedOut,
        Error::Accounting => io::ErrorKind::ConnectionAborted,
        Error::NoMemory => io::ErrorKind::OutOfMemory,
        Error::AddrNotLocal => io::ErrorKind::AddrNotAvailable,
        Error::AddrInUse => io::ErrorKind::AddrInUse,
        Error::PortZero | Error::InvalidAddress | Error::MessageTooLong | Error::InvalidMessage => {
            io::ErrorKind::InvalidInput
        }
        Error::TableFull => io::ErrorKind::QuotaExceeded,
        _ => io::ErrorKind::Other,
    };
    io::Error::new(kind, e)
}

/// 核の中の panic で世代が終わった後の誤りです。
pub(crate) fn poisoned() -> io::Error {
    io::Error::other("a panic inside the TCP/IP core ended this tunnel generation")
}
