#!/usr/bin/env bash
# screenshot-ui retakes the two dashboard screenshots used by README.md and
# README.ja.md: docs/images/dashboard.png (English) and
# docs/images/dashboard.ja.png (Japanese).
#
# It builds tools/uidemo, a throwaway program that serves the admin Web UI on
# 127.0.0.1:8686 with fixed sample data (three agents, five rules, one warning;
# see tools/uidemo/main.go for the exact values), waits for the port to accept
# connections, captures each locale with headless Firefox using a fresh
# throwaway profile, then stops the demo server.
#
# Usage:
#   bash scripts/screenshot-ui.sh
#
# Requirements: Go (to build tools/uidemo) and Firefox at /usr/bin/firefox.
#
# --window-size takes width[,height] (see `firefox --help`). Passing only a
# width makes --screenshot capture the full page height (verified against
# Firefox 155: width,height crops to exactly that box, e.g. 1400x600 stays
# 1400x600 even though the page is taller; width alone yields a screenshot
# sized to the page's actual content height, e.g. 1400x1276). So this script
# passes only a width, to avoid ever cutting the dashboard off at the bottom.
#
# Re-run this after any change to the Web UI's templates, styles, or sample
# data shape, so the screenshots keep matching the current UI text.
#
# Firefox writes --screenshot output under its own sandbox's allowed
# directories only (writes into a repo checkout can silently no-op, exit 0,
# and leave the target file untouched); this script has Firefox write into a
# scratch directory under /tmp and then copies the result into docs/images.
set -euo pipefail
cd "$(dirname "$0")/.."

firefox_bin="/usr/bin/firefox"
addr="127.0.0.1:8686"
out_dir="docs/images"
bin_dir="$(mktemp -d)"
demo_bin="$bin_dir/uidemo"

if [ ! -x "$firefox_bin" ]; then
    echo "screenshot-ui: $firefox_bin not found; install Firefox to take screenshots" >&2
    exit 1
fi

echo "building tools/uidemo..."
go build -o "$demo_bin" ./tools/uidemo

"$demo_bin" &
demo_pid=$!

cleanup() {
    kill "$demo_pid" 2>/dev/null || true
    wait "$demo_pid" 2>/dev/null || true
    rm -rf "$bin_dir"
}
trap cleanup EXIT

echo "waiting for $addr..."
for _ in $(seq 1 50); do
    if (exec 3<>"/dev/tcp/127.0.0.1/8686") 2>/dev/null; then
        exec 3<&- 3>&-
        break
    fi
    sleep 0.2
done
if ! (exec 3<>"/dev/tcp/127.0.0.1/8686") 2>/dev/null; then
    echo "screenshot-ui: uidemo did not come up on $addr" >&2
    exit 1
fi
exec 3<&- 3>&-

mkdir -p "$out_dir"

shoot() {
    lang="$1"
    out="$2"
    profile="$(mktemp -d)"
    shot_dir="$(mktemp -d)"
    shot="$shot_dir/shot.png"
    "$firefox_bin" --headless --no-remote --profile "$profile" \
        --window-size=1400 --screenshot "$shot" \
        "http://$addr/?lang=$lang"
    if [ ! -s "$shot" ]; then
        echo "screenshot-ui: firefox did not produce $shot" >&2
        exit 1
    fi
    cp "$shot" "$out"
    rm -rf "$profile" "$shot_dir"
    echo "wrote $out"
}

shoot en "$out_dir/dashboard.png"
shoot ja "$out_dir/dashboard.ja.png"

echo "done."
