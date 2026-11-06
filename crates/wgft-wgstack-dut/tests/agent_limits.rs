//! wgft の agent が核に渡す表の大きさ (`wgft_agent::memory::core_limits`) が、凍結した Go の本番の値
//! (`Limits::go_reference`) と同じであることを確かめます。上界の表 (`docs/design/v2/wgstack-bound.md`) と Go の
//! 記録の再生は後者を、agent の上界の表 (`docs/design/v2/agent-bound.md`) と agent は前者を使うので、片方だけを
//! 変えると表と挙動が黙ってずれるためです。

use wgft_wgstack::Limits;

#[test]
fn the_agent_passes_the_go_reference_tables() {
    for k in [0, 1, 16, 256, 1024, 2048, 8192] {
        assert_eq!(
            wgft_agent::memory::core_limits(k),
            Limits::go_reference(k),
            "K = {k}"
        );
    }
}
