//! タイマーだけの遅れ (他の task が CPU を使わない時)。
use std::cell::Cell;
use std::rc::Rc;
use std::time::{Duration, Instant};

fn main() {
    let mut e = a0_mio_exec::Exec::new(32).unwrap();
    let (early, late, sum) = e
        .block_on(async {
            let early = Rc::new(Cell::new(0u32));
            let late = Rc::new(Cell::new(Duration::ZERO));
            let sum = Rc::new(Cell::new(Duration::ZERO));
            let mut hs = Vec::new();
            for i in 0..1000u64 {
                let (early, late, sum) = (Rc::clone(&early), Rc::clone(&late), Rc::clone(&sum));
                hs.push(a0_mio_exec::spawn(async move {
                    let at = Instant::now() + Duration::from_micros(1000 + (i * 7919) % 49_000);
                    a0_mio_exec::sleep_until(at).await;
                    let now = Instant::now();
                    if now < at {
                        early.set(early.get() + 1);
                    }
                    late.set(late.get().max(now - at));
                    sum.set(sum.get() + (now - at));
                }));
            }
            for h in hs {
                h.await.unwrap();
            }
            (early.get(), late.get(), sum.get())
        })
        .unwrap();
    println!(
        "1000 timers alone: early {early}, max late {late:?}, mean late {:?}",
        sum / 1000
    );
}
