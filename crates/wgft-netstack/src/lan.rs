//! hook の LAN 側のソケットの表 (wgstack-rs.md の「boost の hook」)。
//!
//! 中継は、トンネルの側の接続と組にした LAN 側のソケットを、この表に接続の handle で登録します。
//! 核は boost の変化と floor への戻りの問い合わせを hook で伝え、hook は表を引いて組のソケットに渡します。
//! Go の `netpipe.FollowBoost` が LAN 側のソケットの受信のバッファを接続の boost の枠に合わせ、floor を超える
//! 受信のデータを持つ間は枠を返させないのと同じ役です。
//!
//! 表は核の外に置き、核と同じスレッドの `Rc` で hook と中継が分け合います。hook は核の借用の中で呼ばれるので、
//! 表を核と同じ借用に置くと二重の借用になるためです。表は作成の時に接続の枠の数だけ確保し、伸びません。

use std::cell::{Cell, RefCell};
use std::fmt;
use std::rc::Rc;

use wgft_wgstack::{ConnId, Hook};

/// The LAN side of a relayed connection, as the boost hook sees it.
///
/// The methods run inside the core's borrow: they must not use the handles or the
/// [`LanSockets`] table. They are meant for socket options and reading the socket's queue.
pub trait LanSocket {
    /// The tunnel side's connection got a boost slot.
    fn boost_granted(&mut self) {}

    /// The core asks before returning the tunnel side's connection to the floor. Returning
    /// `false`, for example while the LAN socket holds more received data than the floor allows,
    /// keeps the boost.
    fn may_return(&mut self) -> bool {
        true
    }

    /// The tunnel side's connection went back to the floor.
    fn boost_returned(&mut self) {}
}

/// The fixed table from tunnel connections to their LAN sockets, shared by the hook and the
/// relay tasks on the data plane thread.
///
/// The hook reports changes only. With [`BoostPolicy::AtAccept`](wgft_wgstack::BoostPolicy),
/// which tests and measurements use, the first boost is granted inside `accept`, before the
/// relay can register the LAN socket, so that socket never hears of it. The product's on-demand
/// policy grants a boost only after reads and writes, so registering right after `accept` comes
/// first.
pub struct LanSockets<T> {
    slots: RefCell<Box<[Option<Row<T>>]>>,
    /// 次の登録の番号です。同じ接続の登録を 2 回した時に、古い登録を落としても新しい組を外さないためです。
    next: Cell<u64>,
}

/// 接続の枠 1 つの行です。登録した接続の handle、登録の番号、ソケットです。
struct Row<T> {
    conn: ConnId,
    token: u64,
    socket: T,
}

impl<T> fmt::Debug for LanSockets<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LanSockets")
            .field("slots", &self.slots.borrow().len())
            .finish_non_exhaustive()
    }
}

impl<T> LanSockets<T> {
    /// A table for a core with `conns` connection slots ([`Limits::conns`](wgft_wgstack::Limits::conns)).
    pub fn new(conns: usize) -> Rc<Self> {
        Rc::new(Self {
            slots: RefCell::new(std::iter::repeat_with(|| None).take(conns).collect()),
            next: Cell::new(0),
        })
    }

    /// Pairs `socket` with the tunnel connection `conn` until the returned registration is
    /// dropped. A registration of the same slot that is still alive, for this connection or an
    /// older one, is replaced; dropping the replaced registration later leaves the new pairing
    /// alone.
    ///
    /// # Panics
    ///
    /// Panics when `conn` is not a connection of a core of this table's size.
    pub fn register(self: &Rc<Self>, conn: ConnId, socket: T) -> LanRegistration<T> {
        // 置き換えた古いソケットは借用を返した後に落とします。
        let token = self.next.get();
        self.next.set(token.wrapping_add(1));
        let old = self.slots.borrow_mut()[conn.index()].replace(Row {
            conn,
            token,
            socket,
        });
        drop(old);
        LanRegistration {
            table: Rc::clone(self),
            conn,
            token,
        }
    }

    /// Calls `f` with the socket paired with `conn`, if any. The hook uses it; it returns `None`
    /// also when the table is borrowed, which only a [`LanSocket`] method that breaks its rule
    /// can cause.
    fn call<R>(&self, conn: ConnId, f: impl FnOnce(&mut T) -> R) -> Option<R> {
        let mut slots = self.slots.try_borrow_mut().ok()?;
        match slots.get_mut(conn.index())? {
            Some(row) if row.conn == conn => Some(f(&mut row.socket)),
            _ => None,
        }
    }

    /// 登録 `token` を外し、ソケットを返します。同じ枠を後の登録が置き換えていれば何もしません。
    fn remove(&self, conn: ConnId, token: u64) -> Option<T> {
        let mut slots = self.slots.borrow_mut();
        let slot = slots.get_mut(conn.index())?;
        if slot.as_ref().is_some_and(|row| row.token == token) {
            slot.take().map(|row| row.socket)
        } else {
            None
        }
    }
}

/// The pairing of a tunnel connection with its LAN socket. Dropping it unpairs them; the relay
/// keeps it until it closes the LAN socket.
pub struct LanRegistration<T> {
    table: Rc<LanSockets<T>>,
    conn: ConnId,
    token: u64,
}

impl<T> fmt::Debug for LanRegistration<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LanRegistration")
            .field("conn", &self.conn)
            .finish_non_exhaustive()
    }
}

impl<T> LanRegistration<T> {
    /// Unpairs them and gives the socket back.
    pub fn into_socket(self) -> Option<T> {
        self.table.remove(self.conn, self.token)
    }
}

impl<T> Drop for LanRegistration<T> {
    fn drop(&mut self) {
        self.table.remove(self.conn, self.token);
    }
}

/// The core's hook that passes the boost changes to the paired LAN sockets.
pub struct LanHook<T> {
    table: Rc<LanSockets<T>>,
}

impl<T> fmt::Debug for LanHook<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LanHook").finish_non_exhaustive()
    }
}

impl<T> LanHook<T> {
    /// A hook over `table`.
    pub fn new(table: Rc<LanSockets<T>>) -> Self {
        Self { table }
    }

    /// The table, for the relay tasks to register their sockets.
    pub fn sockets(&self) -> &Rc<LanSockets<T>> {
        &self.table
    }
}

impl<T: LanSocket> Hook for LanHook<T> {
    fn boost_granted(&mut self, conn: ConnId) {
        self.table.call(conn, LanSocket::boost_granted);
    }

    fn may_return(&mut self, conn: ConnId) -> bool {
        self.table.call(conn, LanSocket::may_return).unwrap_or(true)
    }

    fn boost_returned(&mut self, conn: ConnId) {
        self.table.call(conn, LanSocket::boost_returned);
    }
}
