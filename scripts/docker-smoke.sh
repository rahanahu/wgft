#!/usr/bin/env bash
# docker-smoke builds the wgft-server and wgft-agent container images from this repository
# (deploy/Dockerfile.server, deploy/Dockerfile.agent) and checks that they actually forward
# traffic: a server and an agent join over a throwaway Docker network, one TCP rule and one UDP
# rule aimed at a disposable echo target, and a check from the host that traffic sent to the
# server's published rule ports comes back. This is B10 in docs/testing.md; nothing else starts
# the published images (the lab scripts run the wgft binary directly, and the release workflow
# only builds and pushes the images).
#
#   scripts/docker-smoke.sh
#
# Runs on the host, no Incus lab VM: both images are userspace mode only (no kernel nftables, no
# kernel WireGuard; see the header of deploy/Dockerfile.server), which is the one case
# lab/README.md already allows Docker for ("Docker is not for the dev environment; it is only for
# checking the agent's distribution image", equally true of the server image here). Server, agent
# and the echo target all sit on one throwaway bridge network and reach each other by container
# name over Docker's embedded DNS, so the test does not publish or depend on WGFT_WG_ENDPOINT's or
# the agent API's host ports, or on the host's own firewall: wgft resolves that hostname itself
# before configuring wireguard-go (internal/dataplane/userspace/tunnel/tunnel.go), and the relay
# resolves a rule's --to target the same way (proto/rule.go). Only the two forwarding-rule ports
# are published to the host, since docs/setup.md documents those as the ones that must be
# reachable from outside the container.
#
# Requires Docker (or Podman: WGFT_SMOKE_DOCKER=podman; the bind mount is labelled with :Z for SELinux), a Go toolchain to build the disposable
# echo target (tools/echo; the server and agent images are always built by their own Dockerfile,
# never on the host), and socat for the traffic check (already a lab/ dependency, see
# lab/e2e.sh). Cleans up every container, volume, network and temp file it creates, including
# leftovers from an earlier interrupted run of this script.
set -u
cd "$(dirname "$0")/.."

DOCKER=${WGFT_SMOKE_DOCKER:-docker}
fail=0

need() { command -v "$1" >/dev/null 2>&1 || { echo "docker-smoke: '$1' not found" >&2; exit 2; }; }
need "$DOCKER"
need go
need socat
"$DOCKER" info >/dev/null 2>&1 || { echo "docker-smoke: '$DOCKER' daemon not reachable" >&2; exit 2; }

id=$$
net=wgft-smoke-$id-net
server=wgft-smoke-$id-server
agent=wgft-smoke-$id-agent
echosvc=wgft-smoke-$id-echo
server_vol=wgft-smoke-$id-server-data
agent_vol=wgft-smoke-$id-agent-data
server_img=wgft-docker-smoke-server:local
agent_img=wgft-docker-smoke-agent:local
tmp=$(mktemp -d)
buildlog="$tmp/build.log"

check() { # check <label> <expected-substring> <actual>
  if [[ "$3" == *"$2"* ]]; then echo "PASS  $1"; else echo "FAIL  $1: got '$3'"; fail=1; fi
}

retry() { # retry <timeout-seconds> <command...>
  local timeout=$1 i=0
  shift
  until "$@" >/dev/null 2>&1; do
    i=$((i + 1))
    [ "$i" -ge "$timeout" ] && return 1
    sleep 1
  done
  return 0
}

container_uid() { # container_uid <container> -> the container's numeric uid, empty on error
  # Both images are distroless (no shell, no ps, no id), so the uid has to come from outside
  # the container. docker top reads the host's view of the process and needs a PID field
  # present in its output, but otherwise accepts plain ps(1) format options. podman top instead
  # takes its own format descriptors directly (no "-o"); "-o"/"-eo" tell it to run ps(1) inside
  # the container instead, which would fail here. A bare "uid" descriptor also differs from
  # podman's default columns, which show USER as a resolved name (for example "nonroot" from
  # the image's /etc/passwd) rather than the numeric id.
  if [[ "$(basename "$DOCKER")" == podman ]]; then
    "$DOCKER" top "$1" uid 2>/dev/null | awk 'NR==2{print $NF}'
  else
    "$DOCKER" top "$1" -o pid,uid 2>/dev/null | awk 'NR==2{print $NF}'
  fi
}

# leftovers from an earlier interrupted run (a different pid, same wgft-smoke- prefix)
sweep_leftovers() {
  local c v n
  for c in $("$DOCKER" ps -aq --filter "name=^wgft-smoke-" 2>/dev/null); do "$DOCKER" rm -f "$c" >/dev/null 2>&1; done
  for v in $("$DOCKER" volume ls -q --filter "name=^wgft-smoke-" 2>/dev/null); do "$DOCKER" volume rm "$v" >/dev/null 2>&1; done
  for n in $("$DOCKER" network ls -q --filter "name=^wgft-smoke-" 2>/dev/null); do "$DOCKER" network rm "$n" >/dev/null 2>&1; done
}

cleanup() {
  "$DOCKER" rm -f "$server" "$agent" "$echosvc" >/dev/null 2>&1
  "$DOCKER" volume rm "$server_vol" "$agent_vol" >/dev/null 2>&1
  "$DOCKER" network rm "$net" >/dev/null 2>&1
  rm -rf "$tmp"
}
trap cleanup EXIT

sweep_leftovers

echo "== build images and echo target"
if ! "$DOCKER" build -f deploy/Dockerfile.server -t "$server_img" . >"$buildlog" 2>&1; then
  tail -n 40 "$buildlog" >&2
  echo "FAIL  build server image"
  exit 1
fi
if ! "$DOCKER" build -f deploy/Dockerfile.agent -t "$agent_img" . >>"$buildlog" 2>&1; then
  tail -n 40 "$buildlog" >&2
  echo "FAIL  build agent image"
  exit 1
fi
if ! CGO_ENABLED=0 GOOS=linux go build -o "$tmp/echo" ./tools/echo 2>"$tmp/echo-build.log"; then
  cat "$tmp/echo-build.log" >&2
  echo "FAIL  build echo target"
  exit 1
fi
echo "PASS  build server, agent and echo target"

"$DOCKER" network create "$net" >/dev/null

"$DOCKER" run -d --name "$echosvc" --network "$net" --network-alias echo \
  -v "$tmp/echo":/echo:ro,Z --entrypoint /echo \
  gcr.io/distroless/static-debian12:latest -tcp 25565 -udp 25566 >/dev/null

if retry 15 bash -c "'$DOCKER' logs '$echosvc' 2>&1 | grep -q 'udp .*25566'"; then
  echo "PASS  echo target up"
else
  "$DOCKER" logs "$echosvc" 2>&1 | tail -n 20 >&2
  echo "FAIL  echo target up: timed out"
  fail=1
fi

"$DOCKER" volume create "$server_vol" >/dev/null
# 公開するのは転送するポートだけで、127.0.0.1 に限る(既定では全部のインタフェースに公開される)
"$DOCKER" run -d --name "$server" --network "$net" --network-alias server \
  --cap-drop ALL --security-opt no-new-privileges --read-only \
  -e WGFT_WG_ENDPOINT="$server:51820" \
  -p 127.0.0.1::39971/tcp -p 127.0.0.1::27015/udp \
  -v "$server_vol":/var/lib/wgft \
  "$server_img" >/dev/null

if retry 20 bash -c "'$DOCKER' logs '$server' 2>&1 | grep -q 'server started'"; then
  echo "PASS  server container started"
else
  "$DOCKER" logs "$server" 2>&1 | tail -n 20 >&2
  echo "FAIL  server container started: timed out"
  fail=1
fi
check "server runs as uid 65532" "65532" "$(container_uid "$server")"

join=$("$DOCKER" exec "$server" wgft agent join-string --name smoke 2>/dev/null | head -1)
check "join string issued" "wgft://" "$join"

"$DOCKER" volume create "$agent_vol" >/dev/null
"$DOCKER" run -d --name "$agent" --network "$net" --network-alias agent \
  --cap-drop ALL --security-opt no-new-privileges --read-only \
  -e WGFT_JOIN="$join" \
  -v "$agent_vol":/var/lib/wgft \
  "$agent_img" >/dev/null

if retry 20 bash -c "'$DOCKER' exec '$server' wgft agent ls 2>/dev/null | awk '\$1==\"smoke\" && \$3!=\"-\"{f=1} END{exit !f}'"; then
  echo "PASS  agent registered and connected"
else
  "$DOCKER" exec "$server" wgft agent ls 2>&1 >&2
  "$DOCKER" logs "$agent" 2>&1 | tail -n 20 >&2
  echo "FAIL  agent registered and connected: timed out"
  fail=1
fi
check "agent runs as uid 65532" "65532" "$(container_uid "$agent")"

t=$("$DOCKER" exec "$server" wgft rule add --agent smoke --tcp 39971 --to echo:25565 2>/dev/null | grep -oE 'r_[A-Z0-9]+')
u=$("$DOCKER" exec "$server" wgft rule add --agent smoke --udp 27015 --to echo:25566 2>/dev/null | grep -oE 'r_[A-Z0-9]+')
check "tcp rule added" "r_" "$t"
check "udp rule added" "r_" "$u"

tcp_port=$("$DOCKER" port "$server" 39971/tcp 2>/dev/null | head -1 | sed -E 's/.*:([0-9]+)$/\1/')
udp_port=$("$DOCKER" port "$server" 27015/udp 2>/dev/null | head -1 | sed -E 's/.*:([0-9]+)$/\1/')

tcp_out=""
for _ in $(seq 1 15); do
  tcp_out=$(echo hi | socat -t 3 -T 10 - TCP:127.0.0.1:"$tcp_port" 2>/dev/null)
  [[ "$tcp_out" == *tcp-echo* ]] && break
  sleep 1
done
check "tcp through the published port" "tcp-echo" "$tcp_out"

udp_out=""
for _ in $(seq 1 15); do
  udp_out=$(echo hi | socat -t 3 -T 10 - UDP:127.0.0.1:"$udp_port" 2>/dev/null)
  [[ "$udp_out" == *udp-echo* ]] && break
  sleep 1
done
check "udp through the published port" "udp-echo" "$udp_out"

if [ "$fail" = 0 ]; then echo "== ALL PASS"; else echo "== FAILURES"; fi
exit "$fail"
