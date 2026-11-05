//! loom の模型 (notes の common-design.md の「loom の最小の模型」のうち Hash S に当てるもの)。
//!
//! `RUSTFLAGS="--cfg loom" cargo test -p wgft-hashs-sync --lib --release` で流す。模型は製品の型 ([`Ring`]、
//! [`Bell`]、[`Demand`]、[`Ending`]) そのものを loom の同期の型で組んだものを使い、写しの模型は使わない。
//!
//! - L2 輪と眠りの印:書き手は公開と印の読み、読み手は印の書きと輪の読み直しを両側で SeqCst の順にした時、項が
//!   残ったまま読み手が眠り続けない。順は FIFO。容量 2 の輪と項 3 つ、タイマーは「来た」の印
//! - L6 停止と panic:1 スレッドが終わりの印を立て、ほかが眠っている時、全員が終わり、各 unit が 1 回だけ落ち、
//!   次の世代は全員の join の後に始まる。unit 2 つ、executor 3 つ
//! - L7 在庫の補充の求め:在庫の尽きた区画が求めの印を立て、front が眠っていても補充され、求めが失われない
//!
//! L3 (予約つきの 1 本の輪) と L4 (credit と回収) は Hash S に当たらない。Hash S は front と区画の間に捨てない
//! 知らせを持たず (4 つ組の表が無い)、全体の予算 G の credit も持たない。boost の枠の集まりは別の決定的な試験で
//! 確かめる。

use super::*;
use loom::sync::Arc;
use loom::thread;

/// loom の park と unpark の形の知らせ。許可を残す。
#[derive(Default)]
struct LoomNotify(loom::sync::Notify);

impl Notifier for LoomNotify {
    fn notify_one(&self) {
        self.0.notify();
    }
}

impl LoomNotify {
    fn wait(&self) {
        self.0.wait();
    }
}

/// 読み手が眠る規則:印を立て、仕事を読み直し、無ければ待つ。仕事があれば印を外して戻る。
fn sleep_unless(bell: &Bell<LoomNotify>, work: impl Fn() -> bool) {
    bell.sleep();
    if work() {
        bell.awake();
        return;
    }
    bell.notifier().wait();
    bell.awake();
}

#[test]
fn l2_ring_and_sleep_flag() {
    loom::model(|| {
        let ring = Arc::new(Ring::new(2));
        let bell = Arc::new(Bell::<LoomNotify>::default());
        let timer = Arc::new(AtomicBool::new(false));

        let producer = {
            let (ring, bell) = (Arc::clone(&ring), Arc::clone(&bell));
            thread::spawn(move || {
                for v in 0..3u32 {
                    let mut v = v;
                    loop {
                        match ring.push(v) {
                            Ok(()) => break,
                            Err(back) => {
                                v = back;
                                thread::yield_now();
                            }
                        }
                    }
                    bell.ring();
                }
            })
        };
        let timer_thread = {
            let (timer, bell) = (Arc::clone(&timer), Arc::clone(&bell));
            thread::spawn(move || {
                timer.store(true, Ordering::SeqCst);
                bell.ring();
            })
        };

        let mut next = 0u32;
        let mut fired = false;
        loop {
            while let Some(v) = ring.pop() {
                assert_eq!(v, next, "FIFO");
                next += 1;
            }
            fired |= timer.load(Ordering::SeqCst);
            if next == 3 && fired {
                break;
            }
            sleep_unless(&bell, || ring.has_items() || (!fired && timer.load(Ordering::SeqCst)));
        }
        producer.join().unwrap();
        timer_thread.join().unwrap();
    });
}

#[test]
fn l6_end_and_panic() {
    loom::model(|| {
        let ending = Arc::new(Ending::default());
        let bells: Arc<[Bell<LoomNotify>; 3]> = Arc::new(Default::default());
        let dropped = Arc::new(AtomicUsize::new(0));

        /// 落ちた回数を数える区画の unit。
        struct Unit(Arc<AtomicUsize>);
        impl Drop for Unit {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        // 区画 1 と 2 は眠って待つ。印を見たら unit を落として終わる
        let sleepers: Vec<_> = (1..3)
            .map(|k| {
                let (ending, bells, dropped) =
                    (Arc::clone(&ending), Arc::clone(&bells), Arc::clone(&dropped));
                thread::spawn(move || {
                    let unit = Unit(dropped);
                    while !ending.is_ended() {
                        sleep_unless(&bells[k], || ending.is_ended());
                    }
                    drop(unit);
                })
            })
            .collect();
        // front (bells[0]) が panic で終わる:印を立てて全員を起こす
        {
            let (ending, bells) = (Arc::clone(&ending), Arc::clone(&bells));
            thread::spawn(move || ending.end(bells.iter())).join().unwrap();
        }
        for s in sleepers {
            s.join().unwrap();
        }
        // 次の世代は全員の join の後に始まる。その時点で各 unit はちょうど 1 回落ちている
        assert_eq!(dropped.load(Ordering::SeqCst), 2);
    });
}

#[test]
fn l7_stock_request() {
    loom::model(|| {
        let demand = Arc::new(Demand::default());
        let front_bell = Arc::new(Bell::<LoomNotify>::default());
        let part_bell = Arc::new(Bell::<LoomNotify>::default());
        let lane = Arc::new(Ring::<u32>::new(2));

        // front:求めを読み、補充を輪で渡して区画を起こす。求めが無ければ眠る
        let front = {
            let (demand, front_bell, part_bell, lane) = (
                Arc::clone(&demand),
                Arc::clone(&front_bell),
                Arc::clone(&part_bell),
                Arc::clone(&lane),
            );
            thread::spawn(move || {
                loop {
                    let n = demand.take();
                    if n > 0 {
                        lane.push(n).unwrap();
                        part_bell.ring();
                        return;
                    }
                    sleep_unless(&front_bell, || demand.pending());
                }
            })
        };
        // 区画:在庫が尽きたので 1 つ求め、届くまで眠る
        demand.ask(1, &front_bell);
        let got = loop {
            if let Some(n) = lane.pop() {
                break n;
            }
            sleep_unless(&part_bell, || lane.has_items());
        };
        assert_eq!(got, 1);
        front.join().unwrap();
    });
}
