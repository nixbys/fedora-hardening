#!/usr/bin/env bash
# tests/wireguard-test.sh - Section 17 end to end: a real WireGuard peer in one
# container, the hardened client (systemd + firewalld, the suite's full image) in
# another, on a private Podman network.
#
# Checks: the tunnel comes up and carries traffic; DNS is routed through it; the
# kill switch blocks traffic outside the tunnel while it is up and everything while
# it is down (the endpoint stays reachable); split-tunnel and incomplete configs are
# refused; --rollback removes the tunnel and the kill switch and outbound traffic
# works again. Prints PASS:/FAIL: lines; exits 1 if any check fails.
#
# Usage: tests/wireguard-test.sh <fedora-release> <artifacts-dir>

# Single-quoted bash -c bodies expand inside the containers.
# shellcheck disable=SC2016
set -uo pipefail

REL="${1:?usage: wireguard-test.sh <release> <artifacts-dir>}"
OUT="${2:?usage: wireguard-test.sh <release> <artifacts-dir>}"
ROOT="$(cd -- "$(dirname -- "$0")/.." && pwd -P)"
IMG_FULL="localhost/fedora-harden:test-f$REL"
NET="fh-wg-net-$$" PEER="fh-wg-peer-$$" CLIENT="fh-wg-client-$$"
mkdir -p "$OUT"

# shellcheck disable=SC2329  # called by the EXIT trap
cleanup() {
    podman rm -f -t 3 "$PEER" "$CLIENT" >/dev/null 2>&1
    podman network rm -f "$NET" >/dev/null 2>&1
}
trap cleanup EXIT

fail=0
# tunnel_check <description> <command...> — a check that needs the tunnel to run;
# reported as SKIP (with the reason) where this environment cannot run nft.
tunnel_check() {
    if ((!NFT_OK)); then
        echo "SKIP: $1 — nft cannot run in this container ($NFT_WHY)"
        return 0
    fi
    check "$@"
}
check() { # check <description> <command...>
    if "${@:2}"; then
        echo "PASS: $1"
    else
        echo "FAIL: $1"
        fail=1
    fi
}
pe() { podman exec "$PEER" "$@" </dev/null; }
ce() { podman exec "$CLIENT" "$@" </dev/null; }
# reach <ip> <port> — can the client open a TCP connection (3 s limit)?
reach() { ce timeout 3 bash -c "exec 3<>/dev/tcp/$1/$2" 2>/dev/null; }

podman network create "$NET" >/dev/null || {
    echo "FAIL: create network"
    exit 1
}

# ── Peer: WireGuard server, a web server inside the tunnel and one outside ──────
# apparmor=unconfined: on hosts with AppArmor (GitHub's Ubuntu runners) Podman's
# default profile stopped wg-quick from running nft; a no-op elsewhere.
podman run -d --name "$PEER" --network "$NET" --cap-add NET_ADMIN --security-opt apparmor=unconfined \
    "registry.fedoraproject.org/fedora:$REL" sleep infinity >/dev/null
pe dnf -y -q install --setopt=install_weak_deps=False wireguard-tools iproute python3 >"$OUT/peer-dnf.log" 2>&1
PEER_IP="$(podman inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$PEER")"
pe bash -c 'umask 077; wg genkey | tee /root/s.key | wg pubkey >/root/s.pub'
pe bash -c 'python3 -m http.server 8080 --bind 0.0.0.0 >/dev/null 2>&1 &'

# ── Client: systemd + firewalld (the suite's full image) ─────────────────────────
# Privileged: in a rootless container systemd can then start firewalld and
# systemd-resolved with their usual sandboxing, as on a booted host.
podman run -d --name "$CLIENT" --network "$NET" --systemd=always --privileged --security-opt apparmor=unconfined \
    --memory 3g -v "$ROOT/fedora-harden.sh:/opt/fh/fedora-harden.sh:ro,z" "$IMG_FULL" >/dev/null
for _ in $(seq 1 60); do
    s="$(ce systemctl is-system-running 2>/dev/null || true)"
    [[ "$s" == running || "$s" == degraded ]] && break
    sleep 1
done
ce dnf -y -q install --setopt=install_weak_deps=False wireguard-tools >"$OUT/client-dnf.log" 2>&1
ce bash -c 'umask 077; wg genkey | tee /root/c.key | wg pubkey >/root/c.pub'
SERVER_PUB="$(pe cat /root/s.pub)" CLIENT_PUB="$(ce cat /root/c.pub)"
pe bash -c "ip link add wg0 type wireguard && ip addr add 10.99.0.1/24 dev wg0 &&
    wg set wg0 listen-port 51820 private-key /root/s.key peer '$CLIENT_PUB' allowed-ips 10.99.0.2/32 &&
    ip link set wg0 up"
ce bash -c "printf '[Interface]\nPrivateKey = %s\nAddress = 10.99.0.2/24\nDNS = 10.99.0.1\n\n[Peer]\nPublicKey = %s\nEndpoint = %s:51820\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 5\n' \
    \"\$(cat /root/c.key)\" '$SERVER_PUB' '$PEER_IP' >/root/provider.conf"

check "before hardening: the peer's web server is reachable directly" reach "$PEER_IP" 8080

# wg-quick needs nft, run from a systemd service. On GitHub's runners the host
# denies that exec ("Permission denied", exit 126) while a direct exec works, so
# probe it the way wg-quick@ runs it; record why, and skip only the checks that
# need a running tunnel.
NFT_OK=1 NFT_WHY=""
if ! ce systemd-run --quiet --wait --pipe --collect nft --version >"$OUT/nft-probe.txt" 2>&1; then
    NFT_OK=0
    NFT_WHY="$(tail -1 "$OUT/nft-probe.txt")"
    ce bash -c 'ls -lZ "$(command -v nft)"; getcap "$(command -v nft)"; findmnt -no OPTIONS /; cat /proc/1/attr/current 2>&1; nft --version' >>"$OUT/nft-probe.txt" 2>&1
fi

# ── Refused configs ─────────────────────────────────────────────────────────────
ce bash -c "sed 's|AllowedIPs = .*|AllowedIPs = 10.99.0.0/24|' /root/provider.conf >/root/split.conf
    grep -v '^PublicKey' /root/provider.conf >/root/broken.conf"
rc=0
ce /opt/fh/fedora-harden.sh --yes --only 17 --wireguard-config /root/split.conf >"$OUT/split.log" 2>&1 || rc=$?
check "split-tunnel config is refused, nothing installed (exit $rc)" \
    bash -c '[[ $1 == 0 ]] && grep -q "split tunnel\|routes only part" "$2" && ! podman exec "$3" test -e /etc/wireguard/wg0.conf' _ "$rc" "$OUT/split.log" "$CLIENT"
rc=0
ce /opt/fh/fedora-harden.sh --yes --only 17 --wireguard-config /root/broken.conf >"$OUT/broken.log" 2>&1 || rc=$?
check "config without PublicKey is refused (exit $rc)" \
    bash -c '[[ $1 == 0 ]] && grep -q "has no PublicKey" "$2"' _ "$rc" "$OUT/broken.log"

# ── Install the tunnel (sections 5 and 17) ──────────────────────────────────────
rc=0
ce /opt/fh/fedora-harden.sh --yes --only 5,17 --wireguard-config /root/provider.conf >"$OUT/run.log" 2>&1 || rc=$?
check "run exits 0 (got $rc)" test "$rc" -eq 0
check "no [FAIL] lines in the run" bash -c '! grep -q "^\[FAIL\]" "$1"' _ "$OUT/run.log"
ce journalctl -u wg-quick@wg0 -b --no-pager >"$OUT/wg-quick.journal" 2>&1
check "tunnel config installed with mode 600" bash -c '[[ "$(podman exec "$1" stat -c %a /etc/wireguard/wg0.conf)" == 600 ]]' _ "$CLIENT"
sleep 6
hs="$(ce wg show wg0 latest-handshakes 2>/dev/null | awk '{print $2}')"
tunnel_check "handshake with the peer" test "${hs:-0}" -gt 0
tunnel_check "traffic flows through the tunnel (10.99.0.1:8080)" reach 10.99.0.1 8080
ce resolvectl domain wg0 >"$OUT/resolvectl.txt" 2>&1
tunnel_check "DNS is routed through the tunnel (~. on wg0)" grep -q '~\.' "$OUT/resolvectl.txt"

# The client's route to the peer's network address goes through the tunnel when it
# is up; the kill switch must block it when the tunnel is down.
ce systemctl stop wg-quick@wg0 >/dev/null 2>&1
if reach "$PEER_IP" 8080; then leaked=1; else leaked=0; fi
check "tunnel down: no traffic outside the tunnel (peer:8080 blocked)" test "$leaked" -eq 0
check "tunnel down: the endpoint stays allowed (UDP 51820 rule present)" \
    bash -c 'podman exec "$1" firewall-cmd --info-policy=fedora-harden-killswitch | grep -q "port=\"51820\""' _ "$CLIENT"
ce systemctl start wg-quick@wg0 >/dev/null 2>&1
sleep 6
tunnel_check "tunnel back up: traffic flows again" reach 10.99.0.1 8080

# ── Rollback ─────────────────────────────────────────────────────────────────────
rc=0
ce /opt/fh/fedora-harden.sh --yes --rollback all >"$OUT/rollback.log" 2>&1 || rc=$?
check "--rollback all exits 0 (got $rc)" test "$rc" -eq 0
check "rollback stops the tunnel" bash -c '! podman exec "$1" ip link show wg0 >/dev/null 2>&1' _ "$CLIENT"
check "rollback removes the tunnel config" bash -c '! podman exec "$1" test -e /etc/wireguard/wg0.conf' _ "$CLIENT"
pol="$(ce firewall-cmd --get-policies 2>&1)"
check "rollback removes the kill switch (firewalld answers: $pol)" \
    bash -c '[[ "$1" != *"not running"* && "$1" != *killswitch* ]]' _ "$pol"
check "after rollback the peer is reachable directly again" reach "$PEER_IP" 8080

exit "$fail"
