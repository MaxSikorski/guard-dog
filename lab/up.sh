#!/usr/bin/env bash
# Start Guard Dog's regtest lab from cold, mine 101 blocks, fund LND and Core
# Lightning, open one channel between them, prove the least-privileged logins
# work (and are refused for anything else), prove each service can be told apart
# without a credential, record the raw version replies in lab/.data/replies/
# <service>/<call>.json, and write lab/.data/manifest.toml with each service's
# version as the service itself reports it, plus the containers' arch, block
# storage and exposure as docker inspect shows them.
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
label() { dc config --format json | jq -er --arg s "$1" --arg k "$2" '.services[$s].labels["org.guard-dog.lab." + $k]'; }
image_of() { dc config --format json | jq -er --arg s "$1" '.services[$s].image'; }

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
for tool in docker jq openssl xxd; do command -v "$tool" >/dev/null || fail "$tool is not installed"; done
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
# The macaroon is read into a variable first, so a failed read leaves no half-written file.
MAC_HEX="$(dc exec -T lnd cat /data/gd-info.macaroon | od -An -tx1 | tr -d ' \n')" || fail "could not read the info:read macaroon from LND"
re_hex='^[0-9a-f]{20,}$'
[[ $MAC_HEX =~ $re_hex ]] || fail "the saved macaroon is not hex"
printf '%s' "$MAC_HEX" > "$DATA/creds/lnd-info-read.macaroon.hex"
RUNE="$(clncli createrune restrictions='[["method=getinfo"],["pnum=0"]]' | jq -er .rune)" || fail "could not make the getinfo rune"
# The rune goes into Core Lightning's own tmpfs on stdin, and the container's shell
# reads it from there; it is never on a command line of this script.
printf '%s' "$RUNE" | dc exec -T cln sh -c 'umask 077; cat > /tmp/gd-rune' || fail "could not hand the rune to the cln container"
# shellcheck disable=SC2016
clnrune() { dc exec -T cln sh -c 'exec lightning-cli --lightning-dir=/data --network=regtest checkrune rune="$(cat /tmp/gd-rune)" method="$1"' sh "$1"; }
valid="$(clnrune getinfo | jq -r .valid)" || fail "the getinfo rune could not be checked"
[ "$valid" = true ] || fail "the getinfo rune was not valid for getinfo"
if clnrune listfunds >/dev/null 2>&1; then fail "the getinfo rune was allowed listfunds"; fi
dc exec -T cln rm -f /tmp/gd-rune || fail "could not remove the rune file from the cln container"
printf '%s' "$RUNE" > "$DATA/creds/cln-getinfo.rune"
step "least-privileged logins: bitcoind gdwatch, LND info:read, CLN getinfo rune (each refused a wider call)"

# 8b. Identification over the lab network, with the probe tool (curl in the pinned
# probe container). No credential appears on a command line anywhere in this
# script (lab_compose.rs checks the text): headers go to curl on stdin (`-H @-`),
# read from a pipe, and the only credentials written to disk are the two files
# in lab/.data/creds. TLS: the two REST servers use their own
# self-signed certificates, so the certificate is pinned by its public key
# (taken from the certificate copied below); a wrong pin must be refused.
# call [curl arguments]: sets HTTP_STATUS, HTTP_BODY and HTTP_AUTH (the
# WWW-Authenticate header, if any). Whatever is on stdin goes to curl.
HTTP_STATUS="" HTTP_BODY="" HTTP_AUTH=""
probe() { dc run --rm -T probe --silent --show-error --max-time 10 --write-out '\n%{http_code}\n%header{www-authenticate}END' "$@"; }
call() {
  local out rest re='^[0-9]{3}$'
  out="$(probe "$@")" || fail "a request from the probe to the lab failed"
  HTTP_AUTH="${out##*$'\n'}"
  HTTP_AUTH="${HTTP_AUTH%END}"
  rest="${out%$'\n'*}"
  HTTP_STATUS="${rest##*$'\n'}"
  HTTP_BODY="${rest%$'\n'*}"
  [[ $HTTP_STATUS =~ $re ]] || fail "the probe got an unreadable reply"
}
# Public key pin for curl, from a PEM certificate: sha256//<base64 of the SHA-256 of the key>.
pin_of() {
  local d re='^[A-Za-z0-9+/]{43}=$'
  d="$(openssl x509 -in "$1" -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl base64)" || fail "could not read a certificate's public key"
  [[ $d =~ $re ]] || fail "unexpected public key hash"
  printf 'sha256//%s' "$d"
}
# fetch_cert <service> <path in the container> <file>: certificates only, never a key.
fetch_cert() {
  local pem
  pem="$(dc exec -T "$1" cat "$2")" || fail "could not read the $1 certificate"
  [[ $pem == *"BEGIN CERTIFICATE"* ]] || fail "the $1 certificate file holds no certificate"
  [[ $pem != *"PRIVATE KEY"* ]] || fail "the $1 certificate file holds a private key: refusing to copy it"
  printf '%s\n' "$pem" > "$3"
  chmod 600 "$3"
}
# record <service> <call> <body>: keep a raw reply in lab/.data/replies/<service>/<call>.json.
# Nothing is stripped: a reply holding a credential or a canary fails the run instead.
REPLIES="$DATA/replies"
# Every form of a credential a reply must not hold: the passwords, the mint key,
# the macaroon (hex, base64, base64url), the rune, and the rpcauth salt$hash.
MAC_B64="$(printf '%s' "$MAC_HEX" | xxd -r -p | openssl base64 -A)" || fail "could not encode the macaroon"
MAC_B64URL="$(printf '%s' "$MAC_B64" | tr '+/' '-_' | tr -d '=')"
REPLY_SECRETS=("$RPC_PASSWORD" "$WATCH_PASSWORD" "$MINT_KEY" "$MAC_HEX" "$MAC_B64" "$MAC_B64URL" "$RUNE" "${RPCAUTH_LINE#*:}" "${WATCH_RPCAUTH_LINE#*:}")
for each in "${REPLY_SECRETS[@]}"; do [ -n "$each" ] || fail "an empty credential in the reply check"; done
record() {
  local svc=$1 name=$2 body=$3 secret
  [[ $svc =~ ^[a-z]+$ ]] && [[ $name =~ ^[a-z0-9-]+$ ]] || fail "unexpected reply name"
  for secret in "${REPLY_SECRETS[@]}"; do
    [[ $body != *"$secret"* ]] || fail "the $svc $name reply holds a credential: not recording it"
  done
  [[ $body != *gdlabcanary-* ]] || fail "the $svc $name reply holds a canary: not recording it"
  printf '%s' "$body" | jq -e . >/dev/null || fail "the $svc $name reply is not JSON"
  mkdir -p "$REPLIES/$svc"
  printf '%s' "$body" > "$REPLIES/$svc/$name.json"
}

# bitcoind, no credential: only a 401 with Basic realm="jsonrpc" says "Bitcoin Core's RPC".
call -H 'Content-Type: application/json' --data '{"jsonrpc":"1.0","id":"gd","method":"getnetworkinfo","params":[]}' http://bitcoind:18443/ </dev/null
{ [ "$HTTP_STATUS" = 401 ] && [ "$HTTP_AUTH" = 'Basic realm="jsonrpc"' ]; } || fail "bitcoind did not answer an unauthenticated call with 401 and WWW-Authenticate: Basic realm=\"jsonrpc\""
# bitcoind, gdwatch: the real wire reply (the {"result", "error", "id"} envelope), through the
# probe, with the Basic header built here and sent on stdin.
btc_rpc() {
  call -H 'Content-Type: application/json' --data "{\"jsonrpc\":\"1.0\",\"id\":\"gd\",\"method\":\"$1\",\"params\":[]}" -H @- http://bitcoind:18443/ < <(printf 'Authorization: Basic %s\n' "$(printf 'gdwatch:%s' "$WATCH_PASSWORD" | openssl base64 -A)")
  [ "$HTTP_STATUS" = 200 ] || fail "bitcoind $1 as gdwatch over HTTP answered $HTTP_STATUS, not 200"
  printf '%s' "$HTTP_BODY" | jq -e '.error == null and .result != null' >/dev/null || fail "bitcoind $1 over HTTP returned an error"
}
btc_rpc getnetworkinfo
record bitcoind getnetworkinfo "$HTTP_BODY"
btc_rpc getblockchaininfo
record bitcoind getblockchaininfo "$HTTP_BODY"

# The two REST certificates (certificates only), and the pins taken from them.
fetch_cert lnd /data/tls.cert "$DATA/creds/lnd-tls.cert"
fetch_cert cln /data/regtest/server.pem "$DATA/creds/clnrest-server.cert"
LND_PIN="$(pin_of "$DATA/creds/lnd-tls.cert")"
CLN_PIN="$(pin_of "$DATA/creds/clnrest-server.cert")"
# Each server is called with the other one's pin: curl must refuse with exactly
# exit 90 (CURLE_SSL_PINNEDPUBKEYNOTMATCH); any other code means the pin was not tested.
wrong_pin() { # service-name, then the probe arguments
  local rc=0
  probe "${@:2}" </dev/null >/dev/null 2>&1 || rc=$?
  [ "$rc" = 90 ] || fail "the pin was not tested for $1: curl exited $rc, expected 90 (pin mismatch)"
}
wrong_pin lnd --insecure --pinnedpubkey "$CLN_PIN" https://lnd:8080/v1/state
wrong_pin clnrest --insecure --pinnedpubkey "$LND_PIN" https://cln:3010/v1/getinfo

# LND, no macaroon: the pinned certificate plus a state reply identify it.
call --insecure --pinnedpubkey "$LND_PIN" https://lnd:8080/v1/state </dev/null
[ "$HTTP_STATUS" = 200 ] || fail "LND's REST /v1/state answered HTTP $HTTP_STATUS, not 200"
printf '%s' "$HTTP_BODY" | jq -e '.state | type == "string"' >/dev/null || fail "LND's /v1/state reply has no state"
record lnd state "$HTTP_BODY"
# LND, info:read macaroon: the versioner reads, the balance is refused.
call --insecure --pinnedpubkey "$LND_PIN" -H @- https://lnd:8080/v2/versioner/version < <(printf 'Grpc-Metadata-macaroon: %s\n' "$MAC_HEX")
[ "$HTTP_STATUS" = 200 ] || fail "the info:read macaroon could not read LND's versioner over REST (HTTP $HTTP_STATUS)"
LND_REST_RAW="$(printf '%s' "$HTTP_BODY" | jq -er .version)" || fail "LND's REST versioner reply has no version"
LND_REST_VER="$(plain "$LND_REST_RAW")"
LND_WANT="$(label lnd expected-version)" || fail "could not read LND's expected version"
[ "$LND_REST_VER" = "$LND_WANT" ] || fail "LND's REST versioner says '$LND_REST_VER', not the pinned image's version"
record lnd versioner-version "$HTTP_BODY"
call --insecure --pinnedpubkey "$LND_PIN" -H @- https://lnd:8080/v1/balance/blockchain < <(printf 'Grpc-Metadata-macaroon: %s\n' "$MAC_HEX")
case $HTTP_STATUS in 403 | 500) ;; *) fail "the info:read macaroon was not refused the blockchain balance over REST (HTTP $HTTP_STATUS)" ;; esac
printf '%s' "$HTTP_BODY" | grep -qi 'permission denied' || fail "LND refused the blockchain balance, but not with a permission error"
LND_REFUSED_STATUS=$HTTP_STATUS
# Core Lightning clnrest, getinfo rune: getinfo reads, listfunds is refused.
call -H 'Content-Type: application/json' --data '{}' --insecure --pinnedpubkey "$CLN_PIN" -H @- https://cln:3010/v1/getinfo < <(printf 'Rune: %s\n' "$RUNE")
# clnrest answers a successful POST with 201 (Created), not 200.
case $HTTP_STATUS in 200 | 201) ;; *) fail "the getinfo rune could not call clnrest getinfo (HTTP $HTTP_STATUS)" ;; esac
CLN_REST_RAW="$(printf '%s' "$HTTP_BODY" | jq -er .version)" || fail "clnrest getinfo reply has no version"
CLN_REST_VER="$(plain "$CLN_REST_RAW")"
CLN_WANT="$(label cln expected-version)" || fail "could not read Core Lightning's expected version"
[ "${CLN_REST_VER#v}" = "$CLN_WANT" ] || fail "clnrest says '$CLN_REST_VER', not the pinned image's version"
record cln getinfo "$HTTP_BODY"
call -H 'Content-Type: application/json' --data '{}' --insecure --pinnedpubkey "$CLN_PIN" -H @- https://cln:3010/v1/listfunds < <(printf 'Rune: %s\n' "$RUNE")
case $HTTP_STATUS in 2*) fail "the getinfo rune was allowed clnrest listfunds" ;; esac
printf '%s' "$HTTP_BODY" | grep -qi 'not permitted' || fail "clnrest refused listfunds, but with an unexpected error"
CLN_REFUSED_STATUS=$HTTP_STATUS
# Nutshell and strfry, no credential.
call http://nutshell:3338/v1/info </dev/null
[ "$HTTP_STATUS" = 200 ] || fail "Nutshell's /v1/info answered HTTP $HTTP_STATUS, not 200"
record nutshell info "$HTTP_BODY"
call -H 'Accept: application/nostr+json' http://strfry:7777/ </dev/null
[ "$HTTP_STATUS" = 200 ] || fail "strfry's NIP-11 answered HTTP $HTTP_STATUS, not 200"
record strfry nip11 "$HTTP_BODY"
step "identification: bitcoind 401 without a login; LND and clnrest answer under a pinned certificate; REST logins read the version and are refused wider calls (LND HTTP $LND_REFUSED_STATUS, clnrest HTTP $CLN_REFUSED_STATUS); 7 replies recorded"

# 9. Versions, read from the services themselves, must match the pinned images' labels.
# Versions are written as upstream names them: no leading "v", and Bitcoin Core's
# "32.1.0" is its release "32.1".
BTC_CHAIN="$(plain "$(bcli getblockchaininfo | jq -er .chain)")"
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

# Facts about the containers themselves, read-only from `docker inspect` of the
# running containers: CPU width, where data lives, and whether anything is
# published on the host. Each lands in a global (no subshell, so fail works).
LAB_ARCH="" LAB_STORAGE="" LAB_EXPOSURE=""
# How many of these say the container is reachable from outside: all ports
# published (-P), any host port binding (configured or live), host networking,
# or a shared network namespace with another container.
EXPOSED_JQ='[.[0]
  | (.HostConfig.PublishAllPorts == true),
    ((.HostConfig.PortBindings // {}) | to_entries[] | select((.value // []) | length > 0) | true),
    ((.NetworkSettings.Ports // {}) | to_entries[] | select((.value // []) | length > 0) | true),
    ((.HostConfig.NetworkMode // "") | (. == "host" or startswith("container:")))
  ] | map(select(.)) | length'
# tmpfs needs a read-only root, at least one tmpfs (as a configured tmpfs or as
# a mount of type tmpfs) and no other kind of mount.
STORAGE_JQ='.[0] | if (.HostConfig.ReadonlyRootfs == true)
  and (((.HostConfig.Tmpfs // {}) | length > 0) or any((.Mounts // [])[]; .Type == "tmpfs"))
  and all((.Mounts // [])[]; .Type == "tmpfs") then "tmpfs" else "disk" end'
# The image's architecture (input: `docker image inspect`) against the
# architecture of the manifest the container's image was actually pulled as
# (--arg c: that one architecture word, read from the container's `docker
# inspect` through stdin; the inspect JSON holds the lab's generated passwords
# in the container environment, so it never goes into a command's arguments;
# the descriptor exists from Docker 28.1 / API 1.48 with the containerd image
# store, and c is empty without it). If both
# are there and differ, the answer is "mixed", never the host's guess; on an
# older Docker the container has no descriptor and the image value is used.
# shellcheck disable=SC2016
ARCH_JQ='.[0].Architecture as $a
  | (if $c == "" then $a else $c end) as $b
  | if $a == $b then $a else "mixed" end'
inspect_lab() {
  local cids cid img a kind seen_arch="" storage=tmpfs exposure=none want c ci imgj st n carch
  cids="$(dc ps -aq)" || fail "could not list the lab's containers"
  want="$(dc config --services | grep -c .)" || fail "could not list the compose services"
  c="$(printf '%s\n' "$cids" | grep -c .)" || c=0
  [ "$c" -eq "$want" ] && [ "$want" -gt 0 ] || fail "expected $want lab containers, found $c"
  while IFS= read -r cid; do
    [[ $cid =~ ^[0-9a-f]{12,64}$ ]] || fail "unexpected container id"
    # Each docker answer is captured first: a failed inspection fails the run
    # and is never read as "disk" or "mixed".
    ci="$(docker inspect "$cid")" || fail "docker inspect failed"
    img="$(printf '%s' "$ci" | jq -er '.[0].Image')" || fail "docker inspect gave no image"
    imgj="$(docker image inspect "$img")" || fail "docker image inspect failed"
    carch="$(printf '%s' "$ci" | jq -r '.[0].ImageManifestDescriptor.platform.architecture // empty')" || fail "docker inspect gave no platform"
    [ -z "$carch" ] || carch="$(plain "$carch")"
    a="$(printf '%s' "$imgj" | jq -er --arg c "$carch" "$ARCH_JQ")" || fail "docker image inspect gave no architecture"
    a="$(plain "$a")"
    case $a in
      amd64 | arm64 | ppc64le | s390x | riscv64 | loong64 | mips64 | mips64le) kind=64-bit ;;
      386 | arm | mips | mipsle) kind=32-bit ;;
      mixed) kind=mixed ;;
      *) fail "unknown image architecture" ;;
    esac
    if [ -z "$seen_arch" ]; then seen_arch=$kind; elif [ "$seen_arch" != "$kind" ]; then seen_arch=mixed; fi
    [ "$kind" != mixed ] || seen_arch=mixed
    st="$(printf '%s' "$ci" | jq -er "$STORAGE_JQ")" || fail "docker inspect gave no storage facts"
    [ "$st" = tmpfs ] || storage=disk
    n="$(printf '%s' "$ci" | jq -er "$EXPOSED_JQ")" || fail "docker inspect gave no network facts"
    [ "$n" = 0 ] || exposure=published
    ci="" imgj=""
  done <<< "$cids"
  LAB_ARCH=$seen_arch LAB_STORAGE=$storage LAB_EXPOSURE=$exposure
}
inspect_lab
step "containers: $LAB_ARCH, storage $LAB_STORAGE, exposure $LAB_EXPOSURE"

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
  printf 'chain = "%s"\n' "$BTC_CHAIN"
  printf 'arch = "%s"\nblock_storage = "%s"\nexposure = "%s"\n' "$LAB_ARCH" "$LAB_STORAGE" "$LAB_EXPOSURE"
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
echo "  manifest: lab/.data/manifest.toml   narrow logins: lab/.data/creds/   raw replies: lab/.data/replies/"
[ "$ELAPSED" -le "$MAX_SECONDS" ] || { echo "lab/up.sh: FAILED: took ${ELAPSED}s, over the ${MAX_SECONDS}s budget" >&2; exit 4; }
