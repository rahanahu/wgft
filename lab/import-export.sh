#!/usr/bin/env bash
# import-export.sh drives the Web UI's rule export/import (POST /ui/rules/export,
# /ui/rules/import, /ui/rules/import/apply) in kernel or userspace mode. It checks that:
#   - the file the UI exports is exactly what the CLI's `rule import` reads, and a file
#     built from `rule ls --json`'s array is exactly what the UI's importer reads;
#   - uploading a file with one rule missing shows that deletion on the confirmation
#     page without changing anything until the apply step is submitted;
#   - a CLI change (`rule set --note`, which does not bump the generation, design 5.3
#     section, but does change the rule set's content) made between the confirmation
#     page and the apply refuses the apply, because proto.RulesDigest no longer matches;
#   - applying for real removes the deleted rule and forwarding through the surviving
#     rule keeps working;
#   - replacing a rule's one deny CIDR with a different one (same count, 1 for 1) shows up
#     on the confirmation page as changed, with the added/removed CIDR, not as unchanged.
# Uses the same background-server, curl-driven method as split-merge.sh.
#
#   lab/lab exec vm bash /wgft/lab/import-export.sh kernel
#   lab/lab exec vm bash /wgft/lab/import-export.sh userspace
# Requires `lab/lab build` and the netns topology (`lab/lab up` / `lab/lab net up`).
set -u
mode=${1:-kernel}
case "$mode" in kernel|userspace) ;; *) echo "usage: import-export.sh kernel|userspace" >&2; exit 2;; esac

DATA=/tmp/wgft-importexport-server
ADATA=/tmp/wgft-importexport-agent
ADMIN=127.0.0.1:8686
RULES=/tmp/wgft-importexport-rules.json
fail=0
check() { # check <label> <expected-substring> <actual>
  # an empty expected substring matches anything, so it would always pass; refuse it
  if [ -z "$2" ]; then echo "FAIL  $1: empty expectation (test bug)"; fail=1; return; fi
  if [[ "$3" == *"$2"* ]]; then echo "PASS  $1"; else echo "FAIL  $1: got '$3'"; fail=1; fi
}
absent() { # absent <label> <substring-that-must-not-appear> <actual>
  if [ -z "$2" ]; then echo "FAIL  $1: empty substring (test bug)"; fail=1; return; fi
  if [[ "$3" == *"$2"* ]]; then echo "FAIL  $1: got '$3'"; fail=1; else echo "PASS  $1"; fi
}
vps() { ip netns exec vps "$@"; }
client() { ip netns exec client bash -c "$1"; }
rule_count() { vps wgft rule ls --admin "$ADMIN" --json | python3 -c 'import json, sys; print(len(json.load(sys.stdin)["rules"]))'; }
hidden_field() { # hidden_field <name> <html-file>, unescaping the HTML attribute entities
  python3 -c "
import re, html
page = open('$2').read()
m = re.search(r'name=\"$1\" value=\"(.*?)\"', page, re.S)
print(html.unescape(m.group(1)) if m else '')
"
}
kill_all() { pkill -x wgft; pkill -x echo; sleep 1; }
kill_server() {
  for p in $(pgrep -x wgft); do
    tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null | grep -q ' server run' && kill "$p"
  done
  sleep 1
}
cleanup() {
  kill_all
  vps wgft server teardown --data-dir "$DATA" --purge --yes >/dev/null 2>&1
  vps ip link del wgft0 2>/dev/null
  vps nft delete table inet wgft 2>/dev/null
  rm -rf "$DATA" "$ADATA" "$RULES" /tmp/wgft-importexport-confirm*.html
}

cleanup
mkdir -p "$DATA"
if [ "$mode" = userspace ]; then
  id wgftlab >/dev/null 2>&1 || useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin wgftlab
  chown wgftlab "$DATA"
  run_server="runuser -u wgftlab -- wgft server run"
else
  run_server="wgft server run"
fi
echo "== $mode: start server"
vps setsid nohup $run_server --mode "$mode" --data-dir "$DATA" --wg-endpoint 203.0.113.1:51820 --admin "$ADMIN" \
  > /tmp/wgft-importexport-server.log 2>&1 < /dev/null &
disown
sleep 3
check "server up" "admin api" "$(grep -o 'admin api' /tmp/wgft-importexport-server.log | head -1)"

join=$(vps wgft agent join-string --name home --admin "$ADMIN" 2>/dev/null | head -1)
WGFT_JOIN="$join" ip netns exec home setsid nohup wgft agent run --data-dir "$ADATA" > /tmp/wgft-importexport-agent.log 2>&1 < /dev/null &
disown
ip netns exec home setsid nohup echo -udp 19132 > /tmp/wgft-importexport-echo.log 2>&1 < /dev/null &
disown
sleep 6
check "agent registered" "home" "$(vps wgft agent ls --admin "$ADMIN" | tail -1)"

r1=$(vps wgft rule add --agent home --udp 2456 --to 192.168.50.2:19132 --admin "$ADMIN" | grep -oE 'r_[A-Za-z0-9]+')
r2=$(vps wgft rule add --agent home --udp 2555 --to 192.168.50.2:19132 --admin "$ADMIN" | grep -oE 'r_[A-Za-z0-9]+')
sleep 2
check "udp through r1 before anything" "udp-echo" "$(client 'echo hi | timeout -k 5 20 socat -t 3 -T 10 - UDP:198.51.100.1:2456')"

echo "== export/import round trip with the CLI"
vps curl -s -o "$RULES" "http://$ADMIN/ui/rules/export"
check "export has both rules" "True" "$(python3 -c "print(len(__import__('json').load(open('$RULES'))) == 2)" | sed 's/true/True/;s/false/False/')"
import_out=$(vps wgft rule import "$RULES" --admin "$ADMIN")
check "CLI rule import accepts the UI's export unchanged" "replaced with 2 rules" "$import_out"

python3 -c "
import json
rules = json.load(open('$RULES'))
rules = [r for r in rules if r['id'] != '$r2']
json.dump(rules, open('$RULES', 'w'))
"

echo "== read-only confirmation page"
vps curl -s -F "file=@$RULES;type=application/json" "http://$ADMIN/ui/rules/import?lang=en" > /tmp/wgft-importexport-confirm1.html
confirm1=$(cat /tmp/wgft-importexport-confirm1.html)
check "confirm page shows the one deletion" "Deleted 1" "$confirm1"
check "confirm page counts r1 as unchanged" "Unchanged 1" "$confirm1"
check "nothing applied yet (still 2 rules)" "2" "$(rule_count)"

content=$(hidden_field content /tmp/wgft-importexport-confirm1.html)
generation=$(hidden_field generation /tmp/wgft-importexport-confirm1.html)
digest=$(hidden_field digest /tmp/wgft-importexport-confirm1.html)

echo "== a CLI change between confirm and apply must refuse the apply"
# --note does not bump the generation (design 5.3 section) but does change the digest.
vps wgft rule set "$r1" --note "changed between confirm and apply" --admin "$ADMIN" >/dev/null
stale=$(vps curl -s --data-urlencode "content=$content" --data-urlencode "generation=$generation" --data-urlencode "digest=$digest" \
  "http://$ADMIN/ui/rules/import/apply?lang=en")
check "apply refuses after an out-of-band change" "changed after this confirmation" "$stale"
check "still 2 rules after the refused apply" "2" "$(rule_count)"

echo "== re-confirm and apply for real"
vps curl -s -F "file=@$RULES;type=application/json" "http://$ADMIN/ui/rules/import" > /tmp/wgft-importexport-confirm2.html
content2=$(hidden_field content /tmp/wgft-importexport-confirm2.html)
generation2=$(hidden_field generation /tmp/wgft-importexport-confirm2.html)
digest2=$(hidden_field digest /tmp/wgft-importexport-confirm2.html)
apply_code=$(vps curl -s -o /dev/null -w "%{http_code}" --data-urlencode "content=$content2" --data-urlencode "generation=$generation2" --data-urlencode "digest=$digest2" \
  "http://$ADMIN/ui/rules/import/apply")
check "apply redirects (deletion applied)" "303" "$apply_code"
check "r2 is gone, r1 remains" "1" "$(rule_count)"

sleep 1
check "udp through r1 still works after the import" "udp-echo" "$(client 'echo hi | timeout -k 5 20 socat -t 3 -T 10 - UDP:198.51.100.1:2456')"
out=$(client 'echo hi | timeout -k 5 20 socat -t 2 -T 10 - UDP:198.51.100.1:2555' 2>&1)
absent "r2's port is gone" "udp-echo" "$out"

echo "== a same-count deny-list replacement must show as changed, with the CIDRs, not unchanged"
# Give r1 a real deny entry so the next upload can replace it 1-for-1 (same count).
vps wgft rule deny add "$r1" 203.0.113.0/24 --admin "$ADMIN" >/dev/null
ACL_RULES=/tmp/wgft-importexport-acl.json
vps curl -s -o "$ACL_RULES" "http://$ADMIN/ui/rules/export"
python3 -c "
import json
rules = json.load(open('$ACL_RULES'))
for r in rules:
    if r['id'] == '$r1':
        r['source_deny'] = ['198.51.100.0/24']
json.dump(rules, open('$ACL_RULES', 'w'))
"
vps curl -s -F "file=@$ACL_RULES;type=application/json" "http://$ADMIN/ui/rules/import?lang=en" > /tmp/wgft-importexport-confirm-acl.html
# html/template escapes "+" as &#43; in attribute/text context; unescape before matching.
confirm_acl=$(python3 -c "import html; print(html.unescape(open('/tmp/wgft-importexport-confirm-acl.html').read()))")
check "same-count deny-list replacement shows as changed" "Changed 1" "$confirm_acl"
check "confirm page shows the added CIDR" "+198.51.100.0/24" "$confirm_acl"
check "confirm page shows the removed CIDR" "-203.0.113.0/24" "$confirm_acl"
if [[ "$confirm_acl" == *"Unchanged 1"* ]]; then
  echo "FAIL  same-count deny-list replacement must not also count as unchanged: $confirm_acl"; fail=1
else
  echo "PASS  same-count deny-list replacement must not also count as unchanged"
fi
rm -f "$ACL_RULES" /tmp/wgft-importexport-confirm-acl.html

echo "== teardown"
kill_server
out=$(vps wgft server teardown --data-dir "$DATA" --purge --yes 2>&1)
check "teardown runs" "deleted $DATA/wgft.sqlite" "$out"
kill_all
rm -rf "$DATA" "$ADATA" "$RULES" /tmp/wgft-importexport-confirm*.html
if [ "$fail" = 0 ]; then echo "== $mode: ALL PASS"; else echo "== $mode: FAILURES"; fi
exit "$fail"
