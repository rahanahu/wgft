#!/usr/bin/env bash
# Packages the wgstack core (crates/wgft-wgstack) with `cargo package` and runs its tests from the
# package alone, outside the wgft workspace. This checks that the crate builds and tests without the
# workspace's files, lints and profiles: the tests may not read outside the package, and the release
# run has the default release profile, so overflow checks are off as in a user's release build.
#
# Usage: scripts/wgstack-package-test.sh [extra cargo test arguments]
# The work directory is under TMPDIR and is removed on exit.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/wgstack-package.XXXXXX")
trap 'rm -rf "$work"' EXIT

cd "$root"
cargo package -p wgft-wgstack --no-verify --allow-dirty --locked --target-dir "$work/target" >/dev/null
tar -xzf "$work"/target/package/wgft-wgstack-*.crate -C "$work"
cd "$work"/wgft-wgstack-*/

export CARGO_TARGET_DIR=$work/target-pkg
# The unpacked crate is outside the repository, so rust-toolchain.toml no longer applies; pin the same
# toolchain so the run is reproducible.
toolchain=$(sed -n 's/^channel = "\(.*\)"/\1/p' "$root/rust-toolchain.toml")
export RUSTUP_TOOLCHAIN=${RUSTUP_TOOLCHAIN:-$toolchain}
echo "wgstack-package-test: toolchain $RUSTUP_TOOLCHAIN"
echo "wgstack-package-test: debug profile, overflow checks on"
cargo test --locked "$@"
echo "wgstack-package-test: release profile, overflow checks off"
cargo test --locked --release "$@"
