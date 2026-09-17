// Package buildinfo は、ビルド時に埋め込む値を持つ。server と agent のどちらからも参照でき、
// OS に依存しない(エージェントと CLI だけの Windows、macOS のビルドでも使う)。
package buildinfo

// Version はビルド時に -X で埋める(.goreleaser.yaml、deploy の Dockerfile、scripts/build-release.sh)。
var Version = "dev"
