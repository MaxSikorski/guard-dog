#!/usr/bin/env bash
# Start Guard Dog's regtest lab from cold, mine 101 blocks, fund LND and Core
# Lightning, open one channel between them, prove the least-privileged logins
# work (and are refused for anything else), and write lab/.data/manifest.toml
# with each service's version as the service itself reports it.
#
# Regtest only. One lab at a time. Remove everything with lab/down.sh.
# Works with macOS's bash 3.2: no associative arrays, no mapfile.
set -euo pipefail

LAB_DIR="$(cd "$(dirname "$0")" && pwd)"
DATA="$LAB_DIR/.data"
PROJECT=gd-lab
MAX_SECONDS="${GD_LAB_MAX_SECONDS:-300}"
CHANNEL_SATS=1000000

dc() { docker compose -p "$PROJECT" -f "$LAB_DIR/compose.yml" --env-file "$DATA/lab.env" "$@"; }
bcli() { dc exec -T bitcoind bitcoin-cli -chain=regtest -datadir=/data "$@"; }
lncli() { dc exec -T lnd lncli --lnddir=/data --network=regtest "$@"; }
clncli() { dc exec -T cln lightning-cli --lightning-dir=/data --network=regtest "$@"; }

fail() { echo "lab/up.sh: FAILED: $*" >&2; echo "The lab is left running so you can look; lab/down.sh removes it." >&2; exit 1; }
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
# Text read from a service goes into the manifest only if it is short and plain.
plain() { printf '%s' "$1" | grep -Eq '^[A-Za-z0-9 ._:/+()-]{1,80}$' || fail "unexpected text from a service: refusing to write it"; printf '%s' "$1"; }
# A credential made here: a canary prefix (so any leak is easy to grep for) plus 32 random bytes.
secret() { printf 'gdlabcanary-%s' "$(openssl rand -hex 32)"; }
# Bitcoin Core's rpcauth line, the same HMAC-SHA256 as share/rpcauth/rpcauth.py.
rpcauth() {
  local user=$1 pw=$2 salt
  salt="$(openssl rand -hex 16)"
  printf '%s:%s$%s' "$user" "$salt" "$(printf '%s' "$pw" | openssl dgst -sha256 -hmac "$salt" | awk '{print $NF}')"
}

T0=$(date +%s)

# 1. Preconditions: tools present, and no lab already running (one at a time).
for tool in docker jq openssl; do command -v "$tool" >/dev/null || fail "$tool is not installed"; done
docker compose version >/dev/null 2>&1 || fail "docker compose (v2) is not available"
[ -z "$(docker ps -aq --filter "label=com.docker.compose.project=$PROJECT")" ] || fail "a gd-lab is already running; run lab/down.sh first"
[ -z "$(docker ps -q --filter label=org.guard-dog.lab.service)" ] || fail "another Guard Dog lab container is running; only one lab at a time"

# 2. Fresh throwaway regtest credentials, never committed (lab/.data is in .gitignore).
rm -rf "$DATA"
mkdir -p "$DATA/creds"
chmod 700 "$DATA" "$DATA/creds"
umask 077
RPC_PASSWORD="$(secret)"
WATCH_PASSWORD="$(secret)"
# Single quotes: compose reads unquoted and double-quoted values as templates, and the '$' in rpcauth would vanish.
{
  printf "GD_LAB_RPC_PASSWORD='%s'\n" "$RPC_PASSWORD"
  printf "GD_LAB_RPCAUTH='%s'\n" "$(rpcauth gdlab "$RPC_PASSWORD")"
  printf "GD_LAB_WATCH_PASSWORD='%s'\n" "$WATCH_PASSWORD"
  printf "GD_LAB_WATCH_RPCAUTH='%s'\n" "$(rpcauth gdwatch "$WATCH_PASSWORD")"
  printf "GD_LAB_MINT_KEY='%s'\n" "$(secret)"
} > "$DATA/lab.env"

# 3. Start everything and wait until every health check passes.
step "starting the five services (pulls the pinned images the first time)"
dc config -q
dc up -d --wait --wait-timeout 240 >/dev/null || fail "a service did not become healthy (docker compose -p gd-lab ps)"

# 4. Chain guard: every node must say regtest, or the lab removes itself and refuses.
refuse() { echo "lab/up.sh: REFUSED: $* is not on regtest. Removing the lab." >&2; "$LAB_DIR/down.sh" >/dev/null 2>&1 || true; exit 3; }
[ "$(bcli getblockchaininfo | jq -r .chain)" = regtest ] || refuse bitcoind
[ "$(lncli getinfo | jq -r '.chains[0].network')" = regtest ] || refuse lnd
[ "$(clncli getinfo | jq -r .network)" = regtest ] || refuse cln
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
WATCH="-rpcuser=gdwatch -rpcpassword=$WATCH_PASSWORD"
# shellcheck disable=SC2086
bcli $WATCH getnetworkinfo >/dev/null || fail "gdwatch could not read getnetworkinfo"
# shellcheck disable=SC2086
if bcli $WATCH getblockcount >/dev/null 2>&1; then fail "gdwatch was allowed getblockcount; the whitelist is not working"; fi
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
# Sorted by id, no timestamps, no node ids, no secrets. Judge A's recording step
# adds recorded, reviewed_by and evidence when it copies this into fixtures/.
entry() { # compose-service reported-text how-it-was-read version
  printf '\n# %s reported "%s" (%s)\n# image %s\n[[service]]\nid = "%s"\nversion = "%s"\n' \
    "$1" "$2" "$3" "$(image_of "$1")" "$(label "$1" id)" "$4"
}
{
  printf '# Written by lab/up.sh. Every version was read from the running service itself,\n'
  printf '# never from an image tag.\n'
  printf 'format = 1\nplatform = "docker"\nsource = "lab"\n'
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
