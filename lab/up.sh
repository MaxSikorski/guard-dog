#!/usr/bin/env bash
# Start Guard Dog's regtest lab from cold, mine 101 blocks, fund LND and Core
# Lightning, open one channel between them, prove the least-privileged logins
# work (and are refused for anything else), and write lab/.data/manifest.toml
# with each service's version as the service itself reports it.
#
# Regtest only. One lab at a time (lab/.lock, shared with lab/down.sh).
# Remove everything with lab/down.sh. If anything goes wrong before all three
# chain checks pass, or you press Ctrl-C then, the lab removes itself.
# Works with macOS's bash 3.2: no associative arrays, no mapfile.
set -euo pipefail
# A GD_LAB_* value already in your shell would override lab/.data/lab.env.
unset GD_LAB_RPC_PASSWORD GD_LAB_RPCAUTH GD_LAB_WATCH_PASSWORD GD_LAB_WATCH_RPCAUTH GD_LAB_MINT_KEY
export LC_ALL=C

LAB_DIR="$(cd "$(dirname "$0")" && pwd)"
DATA="$LAB_DIR/.data"
PROJECT=gd-lab
# shellcheck source=lab/lib.sh
. "$LAB_DIR/lib.sh"
MAX_SECONDS="${GD_LAB_MAX_SECONDS:-300}"
CHANNEL_SATS=1000000

dc() { docker compose -p "$PROJECT" -f "$LAB_DIR/compose.yml" --env-file "$DATA/lab.env" "$@"; }
bcli() { dc exec -T bitcoind bitcoin-cli -chain=regtest -datadir=/data "$@"; }
# gdwatch's password goes in on stdin, never on a command line.
bwatch() { printf '%s\n' "$WATCH_PASSWORD" | bcli -rpcuser=gdwatch -stdinrpcpass "$@"; }
lncli() { dc exec -T lnd lncli --lnddir=/data --network=regtest "$@"; }
clncli() { dc exec -T cln lightning-cli --lightning-dir=/data --network=regtest "$@"; }

# State for the exit trap: was the lock taken, were credentials made, were
# containers started, and have all three chain checks passed.
LOCK_OWNED=0 DATA_MADE=0 STARTED=0 CHAINS_OK=0
cleanup() {
  local rc=$?
  trap - EXIT
  if [ "$STARTED" = 1 ] && [ "$CHAINS_OK" = 0 ]; then
    echo "lab/up.sh: removing the lab: no node may stay up before all three chain checks pass" >&2
    lab_teardown >/dev/null 2>&1 || echo "lab/up.sh: the lab was not fully removed; run lab/down.sh" >&2
  elif [ "$DATA_MADE" = 1 ] && [ "$STARTED" = 0 ]; then
    rm -rf "$DATA"
  fi
  if [ "$LOCK_OWNED" = 1 ]; then lab_unlock; fi
  exit "$rc"
}
trap cleanup EXIT
# An interrupt becomes a normal exit, so the EXIT trap above runs.
trap 'exit 130' INT TERM HUP

fail() {
  echo "lab/up.sh: FAILED: $*" >&2
  if [ "$STARTED" = 1 ] && [ "$CHAINS_OK" = 1 ]; then
    echo "The lab is left running so you can look; lab/down.sh removes it." >&2
  fi
  exit 1
}
step() { echo "[$(( $(date +%s) - T0 ))s] $*"; }
# waitfor <seconds> <description> <command...>: retry once a second.
waitfor() {
  local n=$1 what=$2 i=1
  shift 2
  while [ "$i" -le "$n" ]; do
    if "$@" >/dev/null 2>&1; then return 0; fi
    sleep 1
    i=$((i + 1))
  done
  fail "timed out after ${n}s waiting for: $what"
}
# Text read back from a service is checked as a whole string (C locale, so no
# multi-line or control characters) before it is printed or written anywhere.
plain() {
  local v=$1 re='^[0-9A-Za-z.+_:/-]{1,64}$'
  [[ $v =~ $re ]] || fail "unexpected text from a service: refusing to use it"
  printf '%s' "$v"
}
# n random bytes as hex, checked: exactly 2n lowercase hex digits or the run fails.
hexrand() {
  local n=$1 out re='^[0-9a-f]+$'
  out="$(openssl rand -hex "$n")" || fail "openssl could not make random bytes"
  [ "${#out}" -eq $((n * 2)) ] && [[ $out =~ $re ]] || fail "openssl gave unexpected random output"
  printf '%s' "$out"
}
# A credential made here: a canary prefix (so any leak is easy to grep for) plus 32 random bytes.
secret() {
  local h
  h="$(hexrand 32)" || return $?
  printf 'gdlabcanary-%s' "$h"
}
# Bitcoin Core's rpcauth line, the same HMAC-SHA256 as share/rpcauth/rpcauth.py.
rpcauth() {
  local user=$1 pw=$2 salt digest re='^[0-9a-f]{64}$'
  salt="$(hexrand 16)" || return $?
  digest="$(printf '%s' "$pw" | openssl dgst -sha256 -hmac "$salt" | awk '{print $NF}')" || fail "openssl could not hash a password"
  [[ $digest =~ $re ]] || fail "openssl gave an unexpected password hash"
  printf '%s:%s$%s' "$user" "$salt" "$digest"
}

T0=$(date +%s)

# 1. One lab at a time: an atomic lock (shared with down.sh), then the preconditions.
lab_lock || fail "could not take the lab lock"
LOCK_OWNED=1
for tool in docker jq openssl; do command -v "$tool" >/dev/null || fail "$tool is not installed"; done
docker compose version >/dev/null 2>&1 || fail "docker compose (v2) is not available"
[ -z "$(docker ps -aq --filter "label=com.docker.compose.project=$PROJECT")" ] || fail "a gd-lab is already running; run lab/down.sh first"
[ -z "$(docker ps -q --filter label=org.guard-dog.lab.service)" ] || fail "another Guard Dog lab container is running; only one lab at a time"

# 2. Fresh throwaway regtest credentials, never committed (lab/.data is in .gitignore).
rm -rf "$DATA"
umask 077
mkdir -p "$DATA/creds"
DATA_MADE=1
chmod 700 "$DATA" "$DATA/creds"
RPC_PASSWORD="$(secret)" || fail "could not make a password"
WATCH_PASSWORD="$(secret)" || fail "could not make a password"
MINT_KEY="$(secret)" || fail "could not make a mint key"
RPCAUTH_LINE="$(rpcauth gdlab "$RPC_PASSWORD")" || fail "could not make an rpcauth line"
WATCH_RPCAUTH_LINE="$(rpcauth gdwatch "$WATCH_PASSWORD")" || fail "could not make an rpcauth line"
# Belt and braces: every credential has exactly the expected shape.
re_secret='^gdlabcanary-[0-9a-f]{64}$'
re_auth='^gd(lab|watch):[0-9a-f]{32}[$][0-9a-f]{64}$'
for v in "$RPC_PASSWORD" "$WATCH_PASSWORD" "$MINT_KEY"; do [[ $v =~ $re_secret ]] || fail "a generated credential has the wrong shape"; done
for v in "$RPCAUTH_LINE" "$WATCH_RPCAUTH_LINE"; do [[ $v =~ $re_auth ]] || fail "a generated rpcauth line has the wrong shape"; done
# Single quotes: compose reads unquoted and double-quoted values as templates, and the '$' in rpcauth would vanish.
{
  printf "GD_LAB_RPC_PASSWORD='%s'\n" "$RPC_PASSWORD"
  printf "GD_LAB_RPCAUTH='%s'\n" "$RPCAUTH_LINE"
  printf "GD_LAB_WATCH_PASSWORD='%s'\n" "$WATCH_PASSWORD"
  printf "GD_LAB_WATCH_RPCAUTH='%s'\n" "$WATCH_RPCAUTH_LINE"
  printf "GD_LAB_MINT_KEY='%s'\n" "$MINT_KEY"
} > "$DATA/lab.env"

# 3. Start everything and wait until every health check passes.
step "starting the five services (pulls the pinned images the first time)"
dc config -q
STARTED=1
dc up -d --wait --wait-timeout 240 >/dev/null || fail "a service did not become healthy (docker compose -p gd-lab ps)"

# 4. Chain guard: every node must say regtest, or the lab removes itself and refuses.
# refuse exits 3, and the exit trap removes the lab.
refuse() { echo "lab/up.sh: REFUSED: $* is not on regtest. Removing the lab." >&2; exit 3; }
[ "$(bcli getblockchaininfo | jq -r .chain)" = regtest ] || refuse bitcoind
[ "$(lncli getinfo | jq -r '.chains[0].network')" = regtest ] || refuse lnd
[ "$(clncli getinfo | jq -r .network)" = regtest ] || refuse cln
CHAINS_OK=1
step "chain check: bitcoind, lnd and cln all on regtest"

# 5. Mine 101 blocks to a throwaway regtest wallet, so the first coinbase can be spent.
bcli createwallet gdlab >/dev/null
MINE_ADDR="$(bcli -rpcwallet=gdlab getnewaddress)"
bcli generatetoaddress 101 "$MINE_ADDR" >/dev/null
step "mined 101 blocks"

# 6. Fund LND and Core Lightning with 1 BTC each, then confirm.
LND_ADDR="$(lncli newaddress p2tr | jq -er .address)"
CLN_ADDR="$(clncli newaddr | jq -er '.bech32 // .p2tr')"
bcli -rpcwallet=gdlab sendtoaddress "$LND_ADDR" 1 >/dev/null
bcli -rpcwallet=gdlab sendtoaddress "$CLN_ADDR" 1 >/dev/null
bcli generatetoaddress 6 "$MINE_ADDR" >/dev/null
lnd_funded() { [ "$(lncli getinfo | jq -r .synced_to_chain)" = true ] && [ "$(lncli walletbalance | jq -r .confirmed_balance)" -ge 100000000 ]; }
cln_funded() { [ "$(clncli listfunds | jq '[.outputs[] | select(.status == "confirmed")] | length')" -ge 1 ]; }
waitfor 120 "LND to see its 1 BTC" lnd_funded
waitfor 120 "Core Lightning to see its 1 BTC" cln_funded
step "funded LND and Core Lightning"

# 7. Open one LND -> Core Lightning channel and wait until both sides call it active.
CLN_ID="$(clncli getinfo | jq -er .id)"
lncli connect "$CLN_ID@cln:9735" >/dev/null
lncli openchannel --node_key "$CLN_ID" --local_amt "$CHANNEL_SATS" >/dev/null
bcli generatetoaddress 6 "$MINE_ADDR" >/dev/null
channel_active() {
  [ "$(lncli listchannels | jq '[.channels[] | select(.active)] | length')" = 1 ] &&
    [ "$(clncli listpeerchannels | jq -r '.channels[0].state')" = CHANNELD_NORMAL ]
}
waitfor 180 "the channel to be active on both sides" channel_active
step "channel open: LND -> Core Lightning, $CHANNEL_SATS sats"

# 8. Least-privileged logins (spike b): each reads the version and is refused anything else.
bwatch getnetworkinfo >/dev/null || fail "gdwatch could not read getnetworkinfo"
if bwatch getblockcount >/dev/null 2>&1; then fail "gdwatch was allowed getblockcount; the whitelist is not working"; fi
lncli bakemacaroon --save_to=/data/gd-info.macaroon info:read >/dev/null
lncli --macaroonpath=/data/gd-info.macaroon getinfo >/dev/null || fail "the info:read macaroon could not read getinfo"
if lncli --macaroonpath=/data/gd-info.macaroon walletbalance >/dev/null 2>&1; then fail "the info:read macaroon was allowed walletbalance"; fi
dc exec -T lnd cat /data/gd-info.macaroon | od -An -tx1 | tr -d ' \n' > "$DATA/creds/lnd-info-read.macaroon.hex"
RUNE="$(clncli createrune restrictions='[["method=getinfo"],["pnum=0"]]' | jq -er .rune)"
[ "$(clncli checkrune rune="$RUNE" method=getinfo | jq -r .valid)" = true ] || fail "the getinfo rune was not valid for getinfo"
if clncli checkrune rune="$RUNE" method=listfunds >/dev/null 2>&1; then fail "the getinfo rune was allowed listfunds"; fi
printf '%s' "$RUNE" > "$DATA/creds/cln-getinfo.rune"
step "least-privileged logins: bitcoind gdwatch, LND info:read, CLN getinfo rune (each refused a wider call)"

# 9. Versions, read from the services themselves, must match the pinned images' labels.
# Versions are written as upstream names them: no leading "v", and Bitcoin Core's
# "32.1.0" is its release "32.1".
label() { dc config --format json | jq -er --arg s "$1" --arg k "$2" '.services[$s].labels["org.guard-dog.lab." + $k]'; }
image_of() { dc config --format json | jq -er --arg s "$1" '.services[$s].image'; }
BTC_RAW="$(plain "$(bcli getnetworkinfo | jq -er .subversion)")"
BTC_VER="$(printf '%s' "$BTC_RAW" | sed -E 's#^/Satoshi:([0-9]+[.][0-9]+)[.]0/$#\1#; s#^/Satoshi:([0-9]+[.][0-9]+[.][0-9]+)/$#\1#')"
LND_RAW="$(plain "$(lncli version | jq -er .lnd.version)")"
LND_VER="$LND_RAW"
CLN_RAW="$(plain "$(clncli getinfo | jq -er .version)")"
CLN_VER="${CLN_RAW#v}"
STRFRY_RAW="$(plain "$(dc exec -T strfry wget -qO- --header 'Accept: application/nostr+json' http://127.0.0.1:7777/ | jq -er .version)")"
STRFRY_VER="$STRFRY_RAW"
NUT_RAW="$(plain "$(dc exec -T nutshell curl -fsS http://127.0.0.1:3338/v1/info | jq -er .version)")"
NUT_VER="${NUT_RAW#Nutshell/}"
for pair in "bitcoind:$BTC_VER" "lnd:$LND_VER" "cln:$CLN_VER" "strfry:$STRFRY_VER" "nutshell:$NUT_VER"; do
  svc="${pair%%:*}" got="${pair#*:}"
  want="$(label "$svc" expected-version)"
  [ "$got" = "$want" ] || fail "$svc reports version '$got' but its pinned image is labelled '$want'"
done
step "versions match the pinned images"

# 10. The manifest, in Judge A's format (design 0.4, section 2.2): the live lab's truth.
# Sorted by id, no timestamps, no node ids, no secrets. Step 3 of design 0.4 copies
# this into fixtures/setups/ and fills in recorded, reviewed_by and evidence there.
entry() { # compose-service reported-text how-it-was-read version
  local img lid
  img="$(image_of "$1")"
  lid="$(label "$1" id)"
  printf '\n# %s reported "%s" (%s)\n# image %s\n[[service]]\nid = "%s"\nversion = "%s"\n' \
    "$1" "$2" "$3" "$img" "$lid" "$4"
}
{
  printf '# Written by lab/up.sh. Every version was read from the running service itself,\n'
  printf '# never from an image tag.\n'
  printf 'format = 1\nplatform = "docker"\nsource = "lab"\nrecorder = "lab/up.sh format 1"\n'
  printf 'description = "Guard Dog regtest lab (lab/compose.yml): bitcoind, LND, Core Lightning, strfry and a Nutshell mint."\n'
  entry bitcoind "$BTC_RAW" "bitcoin-cli getnetworkinfo .subversion" "$BTC_VER"
  entry cln "$CLN_RAW" "lightning-cli getinfo .version" "$CLN_VER"
  entry lnd "$LND_RAW" "lncli version .lnd.version" "$LND_VER"
  entry nutshell "$NUT_RAW" "NUT-06 GET /v1/info .version" "$NUT_VER"
  entry strfry "$STRFRY_RAW" "NIP-11 GET / .version" "$STRFRY_VER"
} > "$DATA/manifest.toml"
chmod 644 "$DATA/manifest.toml"

# 11. Health summary. Never prints a credential.
ELAPSED=$(( $(date +%s) - T0 ))
HEIGHT="$(bcli getblockcount)"
echo
echo "gd-lab is up (regtest), cold start to funded channel in ${ELAPSED}s"
printf '  %-9s %-20s %s\n' service version status
printf '  %-9s %-20s %s\n' bitcoind "$BTC_VER" "height $HEIGHT"
printf '  %-9s %-20s %s\n' lnd "$LND_VER" "1 active channel, $CHANNEL_SATS sats"
printf '  %-9s %-20s %s\n' cln "$CLN_VER" "CHANNELD_NORMAL"
printf '  %-9s %-20s %s\n' strfry "$STRFRY_VER" "NIP-11 answers"
printf '  %-9s %-20s %s\n' nutshell "$NUT_VER" "NUT-06 answers"
echo "  manifest: lab/.data/manifest.toml   narrow logins: lab/.data/creds/"
[ "$ELAPSED" -le "$MAX_SECONDS" ] || { echo "lab/up.sh: FAILED: took ${ELAPSED}s, over the ${MAX_SECONDS}s budget" >&2; exit 4; }
