#!/usr/bin/env bash
# 静的な単一バイナリを linux/amd64 と linux/arm64 に向けて作る。CGO 無し。
# modernc.org/sqlite が cgo-free なので、どの Linux にもそのまま置ける。
#
#   scripts/build-release.sh            # dist/ に両アーキテクチャを出す
#   scripts/build-release.sh amd64      # 片方だけ
#
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="$(git describe --tags --always --dirty 2>/dev/null || echo dev)"
OUT="dist"
mkdir -p "$OUT"

# 引数でアーキテクチャを指定できる。無指定なら amd64 と arm64 の両方。
read -r -a ARCHES <<<"${*:-amd64 arm64}"

for arch in "${ARCHES[@]}"; do
  bin="$OUT/wgft-linux-$arch"
  echo "building $bin ($VERSION)"
  CGO_ENABLED=0 GOOS=linux GOARCH="$arch" \
    go build -trimpath -ldflags "-s -w -X github.com/rahanahu/wgft/internal/buildinfo.Version=$VERSION" \
    -o "$bin" ./cmd/wgft
  ( cd "$OUT" && sha256sum "$(basename "$bin")" > "$(basename "$bin").sha256" )
done

echo "done:"
ls -la "$OUT"
