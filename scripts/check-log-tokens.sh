#!/usr/bin/env bash
# check-log-tokens is a machine check for the "no token values in logs" rule:
# tokens are 128-bit secrets, and a log line that formats a token *value* (for example
# log.Printf("token=%s", tok)) would leak it into the server's logs. The existing
# convention (see agentapi/server.go's certificate fingerprint log) is to log at most a
# hash prefix, never the value itself.
#
# grep -rnE 'log\..*(tok|Token|JOIN)' --include='*.go' cmd internal finds every line that
# plausibly logs something token-related, but it cannot tell a fixed string like
# "...permanent token" (safe) from log.Printf("token=%s", tok) (a leak): both contain
# "log." and "token" on the same line. So this script is allowlist-based: every current
# match has been reviewed by hand and recorded in check-log-tokens-allowlist.txt,
# normalized as "path:trimmed line" (no line number, so unrelated edits elsewhere in the
# file do not cause drift). A match that is not on the allowlist fails the build.
#
# To clear a failure: read the reported line. If it only logs a fixed string, a hash, or
# a hash prefix, add its normalized form (see below) to the allowlist. If it formats a
# token value, fix the code instead (log a hash prefix, or drop the value) and do not
# allowlist it.
set -euo pipefail
cd "$(dirname "$0")/.."

allowlist="scripts/check-log-tokens-allowlist.txt"

matches="$(grep -rnE 'log\..*(tok|Token|JOIN)' --include='*.go' cmd internal || true)"

status=0
if [ -n "$matches" ]; then
    while IFS= read -r line; do
        normalized="$(printf '%s\n' "$line" | sed -E 's/^([^:]+):[0-9]+:[[:space:]]*/\1:/')"
        if ! grep -qxF "$normalized" "$allowlist"; then
            echo "not on the allowlist, review by hand: $line"
            status=1
        fi
    done <<<"$matches"
fi

if [ "$status" -ne 0 ]; then
    echo "new log statement(s) mention a token/join string; see scripts/check-log-tokens.sh for the rule" >&2
    exit 1
fi
echo "OK: no unreviewed log statements mention a token/join string"
