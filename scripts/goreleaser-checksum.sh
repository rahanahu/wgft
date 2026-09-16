#!/usr/bin/env bash
# GoReleaser の build post-hook から呼ぶ。checksum.split: true の出力は
# ハッシュだけの 1 行で `sha256sum -c` と互換が無い(GoReleaser 側の仕様。
# internal/pipe/checksums/checksums.go の refreshOne はファイル名を書かない)。
# そのため checksum パイプは disable にし、ビルド直後の生バイナリから
# 自前で "<hash>  <name>\n" 形式を作る。README の取得コマンドと同じ名前
# (wgft-linux-amd64 など)を付け、.goreleaser.yaml の archives の
# name_template と揃える。
#
# archives の format: binary は、GitHub Releases にアップロードする際は
# この名前を使うが、dist/ の実体は <target>/wgft のまま(リネームは
# アップロード時だけ)。手元の --snapshot 確認で
# `cd dist && sha256sum -c wgft-linux-amd64.sha256` がそのまま通るよう、
# dist/ 直下にも同じ名前でコピーしておく(release 時に二重アップロードは
# されない。GoReleaser は ctx.Artifacts に登録した実体だけを送る)。
#
#   scripts/goreleaser-checksum.sh <built-binary-path> <os> <arch>
set -euo pipefail

path="$1"
os="$2"
arch="$3"
name="wgft-$os-$arch"

mkdir -p dist
cp "$path" "dist/$name"
hash="$(sha256sum "dist/$name" | cut -d' ' -f1)"
printf '%s  %s\n' "$hash" "$name" >"dist/$name.sha256"
