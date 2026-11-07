//! loom の模型。`RUSTFLAGS="--cfg loom" cargo test -p wgft-handoff --release --lib` で流す。
//! 模型は製品の型 ([`Handoff`]) そのものを loom の同期の型で組んだものを使う。
//!
//! - order:持ち主が counter を予約して束を 3 つ渡す (束は 2 つが回る)。手伝いが送った counter は狭義に
//!   増え、各 counter は 1 回だけで、欠けも無い。眠りの印と待ちの印のどちらでも永久に眠らない
//!   (起こし損ないは loom が行き詰まりとして見つける)
//! - switch:束を渡した後に門が閉じ、持ち主は渡した束がすべて返るのを見てから自分で送る。送った列は
//!   狭義に増える
//! - stop:渡した束がある時も、眠っている手伝いも、止める印で必ず終わり、渡した束は送られる
//! - death:手伝いが死ぬと、待っている持ち主は必ず起こされる

use super::*;
use loom::sync::Arc;
use loom::thread;

/// loom の park と unpark の形の知らせ。許可を残す。
#[derive(Default)]
struct LoomNotify(loom::sync::Notify);

impl Signal for LoomNotify {
    fn signal(&self) {
        self.0.notify();
    }
}

type H = Handoff<[u64; 2], LoomNotify, LoomNotify>;

fn model(f: impl Fn() + Sync + Send + 'static) {
    let mut b = loom::model::Builder::new();
    b.preemption_bound = Some(3);
    b.check(f);
}

/// 手伝い:束を受け、counter を記録し、返す。
fn spawn_helper(h: &Arc<H>, log: &Arc<Mutex<Vec<u64>>>) -> thread::JoinHandle<()> {
    let (h, log) = (Arc::clone(h), Arc::clone(log));
    thread::spawn(move || {
        while let Next::Job(job) = h.next(|| h.helper_signal().0.wait()) {
            log.lock().unwrap().extend(job);
            h.give_back(job);
        }
    })
}

/// 持ち主:返った束が無ければ待ちの印を立てて眠る。
fn wait_for_job(h: &H) {
    loop {
        if h.want().is_some() {
            return;
        }
        h.owner_signal().0.wait();
    }
}

#[test]
fn order_and_unique_counters() {
    model(|| {
        let h = Arc::new(H::new(2, LoomNotify::default(), LoomNotify::default()));
        let log = Arc::new(Mutex::new(Vec::new()));
        let helper = spawn_helper(&h, &log);
        let mut counter = 0u64;
        let mut free = 2;
        for _ in 0..3 {
            if free == 0 {
                wait_for_job(&h);
                free += 1;
            }
            while h.collect().is_some() {
                free += 1;
            }
            // 予約は持ち主だけが行う
            let job = [counter, counter + 1];
            counter += 2;
            h.submit(job).unwrap();
            free -= 1;
        }
        h.stop();
        helper.join().unwrap();
        assert_eq!(*log.lock().unwrap(), (0..6).collect::<Vec<_>>());
    });
}

#[test]
fn switch_keeps_the_order() {
    model(|| {
        let h = Arc::new(H::new(2, LoomNotify::default(), LoomNotify::default()));
        let log = Arc::new(Mutex::new(Vec::new()));
        let helper = spawn_helper(&h, &log);
        h.submit([0, 1]).unwrap();
        // 門が閉じた。手伝いにある束がすべて返るまで、持ち主は自分で送らない
        let mut outstanding = 1;
        while outstanding > 0 {
            wait_for_job(&h);
            outstanding -= 1;
        }
        log.lock().unwrap().push(2);
        h.stop();
        helper.join().unwrap();
        assert_eq!(*log.lock().unwrap(), vec![0, 1, 2]);
    });
}

#[test]
fn stop_ends_a_sleeping_or_busy_helper() {
    model(|| {
        let h = Arc::new(H::new(2, LoomNotify::default(), LoomNotify::default()));
        let log = Arc::new(Mutex::new(Vec::new()));
        let helper = spawn_helper(&h, &log);
        h.submit([0, 1]).unwrap();
        h.stop();
        helper.join().unwrap();
        assert_eq!(*log.lock().unwrap(), vec![0, 1]);
    });
}

#[test]
fn a_dead_helper_wakes_a_waiting_owner() {
    model(|| {
        let h = Arc::new(H::new(2, LoomNotify::default(), LoomNotify::default()));
        let helper = {
            let h = Arc::clone(&h);
            thread::spawn(move || h.mark_dead())
        };
        while !h.is_dead() {
            if h.want().is_none() {
                h.owner_signal().0.wait();
            }
        }
        helper.join().unwrap();
    });
}
