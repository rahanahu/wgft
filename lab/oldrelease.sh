# oldrelease.sh is sourced (not run) by lab scripts that need a previous release's linux-amd64
# binary: today lab/version-skew.sh (B7, design 7a.6) and lab/upgrade.sh (D4, docs/testing.md).
# It defines one function, fetch_release, factored out so both scripts download and verify a
# tagged release binary the same way instead of keeping two copies of the same ~35 lines in sync.
#
# The sourcing script must set GH_REPO (owner/repo on GitHub) before sourcing this file; the cache
# directory and version number are passed as arguments to fetch_release itself, so this file has
# no other dependency on the caller's variable names.
#
# fetch_release <version> <out-path>: downloads the linux-amd64 release binary for a tagged
# version into <out-path>, verified against the published .sha256. A cached, already-verified
# <out-path> (from an earlier run in the same VM, or a file pre-staged with `incus file push`;
# see lab/version-skew.sh's header comment on the "VM has no outbound IPv4" case) is reused
# without touching the network. Retries for a few minutes, so a slow or momentarily flaky network
# (or a pre-stage that lands a little late) does not fail the whole script on one bad round trip.
#
# The temp files are suffixed with this process's PID, not a fixed ".tmp" name: two sandboxes on
# the same VM sharing one $out (a cache directory is deliberately not scoped per sandbox, so a
# binary downloaded by one is reused by the other) must not overwrite each other's in-progress
# download. already_cached() re-checks the shared final path each round regardless of which
# process's temp file finished first, so whichever caller wins the race, every caller still ends
# up verifying and reusing the same $out.
fetch_release() {
  local ver=$1 out=$2 url tmp=$2.tmp.$$ stmp=$2.sha256.tmp.$$
  url="https://github.com/$GH_REPO/releases/download/v$ver/wgft-linux-amd64"
  already_cached() {
    [ -s "$out" ] && [ -s "$out.sha256" ] || return 1
    [ "$(awk '{print $1}' "$out.sha256")" = "$(sha256sum "$out" | awk '{print $1}')" ]
  }
  if already_cached; then
    chmod +x "$out"
    return 0
  fi
  local i
  for ((i = 0; i < 40; i++)); do
    if curl -fsSL --connect-timeout 5 --max-time 30 -o "$tmp" "$url" \
      && curl -fsSL --connect-timeout 5 --max-time 30 -o "$stmp" "$url.sha256"; then
      local want got
      want=$(awk '{print $1}' "$stmp")
      got=$(sha256sum "$tmp" | awk '{print $1}')
      if [ -n "$want" ] && [ "$want" = "$got" ]; then
        mv "$tmp" "$out"; mv "$stmp" "$out.sha256"; chmod +x "$out"
        return 0
      fi
      echo "fetch_release: sha256 mismatch for v$ver (want $want got $got)" >&2
      rm -f "$tmp" "$stmp"
      return 1
    fi
    # covers both a transient network hiccup and the "pre-staged by incus file push while this
    # loop is already running" race; already_cached() below re-checks the same path each round.
    rm -f "$tmp" "$stmp"
    already_cached && { chmod +x "$out"; return 0; }
    sleep 5
  done
  return 1
}
