#!/usr/bin/env bash
# record-setup.sh: records what runs on a node, keeping only the facts Guard
# Dog needs (field extracts, not copies) with identifying details removed, so
# Guard Dog can be tested against a real setup.
#
# Read-only: it reads a fixed list of files, runs a fixed list of commands
# and asks the Docker engine three list questions. It never reads keys,
# seeds, wallets, macaroons, passwords or databases (it refuses files with
# names like those), never changes anything on the machine and never talks to
# the network (only the local Docker socket).
#
# Run it with a clean environment:  env -i PATH=/usr/bin:/bin bash record-setup.sh ...
#
# Ways to run it:
#   record-setup.sh --out DIR [--root DIR] [--docker-socket PATH]
#                   [--reply SERVICE/CALL=FILE]... [--redact-term WORD]...
#   record-setup.sh --redact-dir IN --out DIR [--redact-term WORD]...
#   record-setup.sh --check-path PATH
#   record-setup.sh --check-binary PATH
#   record-setup.sh --help
#
# Exit codes:
#   0  done
#   1  usage or environment problem (bad argument, output folder not empty,
#      run as root, perl missing, a reply that is not JSON, too many addresses)
#   2  refused to read a secret-looking or unsafe path; nothing was written
#   3  done, but a secret-shaped value was found and removed; read the files
#   4  the self-check failed; the output was deleted
#
# Read every file it writes before you share it.

# Clean start, always: the script runs again in an empty environment, so nothing
# the caller exported (PATH tricks, PERL5OPT, proxy variables, HOME, exported
# functions, ...) can change what it does. Only a safe TMPDIR survives. The
# marker argument below is not trusted: the second run checks that its
# environment really is clean and stops if it is not.
#
# Out of scope: code that already runs as you. A BASH_ENV or ENV file, a shell
# startup file or a hostile bash itself can change this script before its first
# line runs, so the clean start does not claim to stop them (bash ignores BASH_ENV
# in the relaunch only because `env -i` removes it; the marker argument passed
# directly skips that, and a BASH_ENV given then is the caller's own code).
#
# Nothing in this block can be shadowed by a function the caller exported: it
# uses only shell keywords ([[ ]], if, for), variable assignments and commands
# given by full path (a command name with a slash is never looked up as a
# function). Names such as [, exec, exit, compgen or printf are not used until
# the check has passed, and the check reads the real environment through
# /usr/bin/env, which lists every exported variable and every exported function
# (as BASH_FUNC_name%%), so a hostile function cannot hide itself from it.
if [[ "${1:-}" != "--gd-clean-launch" ]]; then
    gd_pass=()
    if [[ -n "${TMPDIR:-}" && "$TMPDIR" == /* && -d "$TMPDIR" && -O "$TMPDIR" ]]; then
        if [[ -n "$(/usr/bin/find "$TMPDIR" -maxdepth 0 ! -perm -g+w ! -perm -o+w 2>/dev/null)" ]]; then
            gd_pass+=("TMPDIR=$TMPDIR")
        fi
    fi
    exec /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C ${gd_pass[@]+"${gd_pass[@]}"} /bin/bash "$0" --gd-clean-launch "$@"
fi
gd_nl=$'\n'
gd_env_re="^(((PATH|LC_ALL|TMPDIR|PWD|OLDPWD|SHLVL|_)=[^${gd_nl}]*${gd_nl})*)\$"
gd_env=$(/usr/bin/env)
if ! [[ "${gd_env}${gd_nl}" =~ $gd_env_re ]]; then
    /usr/bin/printf '%s\n' "The environment is not clean. Run: env -i PATH=/usr/bin:/bin bash record-setup.sh ..." >&2
    # exit can be shadowed too, so a kill from a clean child shell follows it.
    exit 1
    # $PPID must expand in the child shell, so the single quotes are intended.
    # shellcheck disable=SC2317,SC2016
    /usr/bin/env -i /bin/sh -c 'kill -9 "$PPID"'
fi
unset gd_nl gd_env_re gd_env gd_pass
shift

set -euo pipefail
umask 077

FORMAT=2

# The list below is read by the redactor and by the Rust tests (one entry per
# line, a hash, a space, then the value). Change it here only. A kept domain
# matches exactly; its subdomains are not kept.
# BEGIN KEPT-DOMAINS
# docker.io
# docker.com
# ghcr.io
# quay.io
# gcr.io
# github.com
# githubusercontent.com
# gitlab.com
# getumbrel.com
# umbrel.com
# start9.com
# raspiblitz.org
# mynodebtc.com
# bitcoincore.org
# bitcoin.org
# lightning.engineering
# lightning.community
# blockstream.com
# corelightning.org
# cashu.space
# nostr.com
# btcpayserver.org
# debian.org
# ubuntu.com
# canonical.com
# raspberrypi.com
# raspberrypi.org
# torproject.org
# nixos.org
# example.com
# example.org
# example.net
# registry-1.docker.io
# raw.githubusercontent.com
# objects.githubusercontent.com
# END KEPT-DOMAINS

# The redactor. One Perl program (strict and warnings only, nothing else is
# imported, so it runs on a bare Debian perl-base). Layer 1 keeps only named,
# type-checked fields of each file and drops everything else. Layer 2 then
# pseudonymises what is left. Raw text is only ever matched by these patterns;
# it never reaches a shell, a path or a command.
IFS= read -r -d '' REDACTOR <<'PERL' || true
use strict;
use warnings;

my ($RAW, $OUT, $TERMSFILE, $MODE, $TESTFLAG) = @ARGV;
my %SECRET_CLASS = map { $_ => 1 } qw(pem-private-key xprv nsec wif-key macaroon seed-words
    secret-value bearer-token url-userinfo token);

sub fail {
    my ($msg, $code) = @_;
    print STDERR "$msg\n";
    exit $code;
}

# ---------- a small JSON reader and writer ----------
# A value is [type, payload]: o (hash), a (array), s (string), n (number text),
# l (true, false, null) or x (a string that was too long).
my ($JT, $JBAD, $JLONG, $JLONGSECRET) = ('', 0, 0, 0);

sub jws { $JT =~ /\G[ \t\r\n]*/gc; return; }

sub jstring {
    return undef if $JT !~ /\G"/gc;
    my ($out, $buf, $bytes) = ('', '', 0);
    my $flush = sub {
        my $b = $buf;
        utf8::decode($b);
        $out .= $b;
        $buf = '';
    };
    my %esc = ('"' => '"', '\\' => '\\', '/' => '/', b => "\b", f => "\f", n => "\n", r => "\r", t => "\t");
    while (1) {
        if ($JT =~ /\G([^"\\\x00-\x1f]+)/gc) { $buf .= $1; $bytes += length $1; }
        elsif ($JT =~ /\G\\(["\\\/bfnrt])/gc) {
            $flush->();
            $out .= $esc{$1};
            $bytes++;
        }
        elsif ($JT =~ /\G\\u([0-9A-Fa-f]{4})/gc) {
            my $cp = hex $1;
            $flush->();
            if ($cp >= 0xD800 && $cp <= 0xDBFF) {
                if ($JT =~ /\G\\u([dD][c-fC-F][0-9A-Fa-f]{2})/gc) {
                    $cp = 0x10000 + (($cp - 0xD800) << 10) + (hex($1) - 0xDC00);
                } else { $cp = 0xFFFD; }
            } elsif ($cp >= 0xDC00 && $cp <= 0xDFFF) { $cp = 0xFFFD; }
            $out .= chr $cp;
            $bytes += 4;
        }
        elsif ($JT =~ /\G"/gc) { last; }
        else { $JBAD = 1; return undef; }
    }
    $flush->();
    $JLONG = $bytes > 4096 ? 1 : 0;
    # A string that is too long to keep is still searched for a secret first.
    $JLONGSECRET++ if $JLONG && looks_secret($out);
    return $out;
}

sub jvalue {
    my ($depth) = @_;
    if ($depth > 32) { $JBAD = 1; return undef; }
    jws();
    if ($JT =~ /\G\{/gc) {
        my %h;
        jws();
        if ($JT =~ /\G\}/gc) { return ['o', \%h]; }
        while (1) {
            jws();
            my $k = jstring();
            return undef if !defined $k;
            jws();
            if ($JT !~ /\G:/gc) { $JBAD = 1; return undef; }
            my $v = jvalue($depth + 1);
            return undef if $JBAD;
            $h{$k} = $v;
            jws();
            if ($JT =~ /\G,/gc) { next; }
            if ($JT =~ /\G\}/gc) { last; }
            $JBAD = 1;
            return undef;
        }
        return ['o', \%h];
    }
    if ($JT =~ /\G\[/gc) {
        my @a;
        jws();
        if ($JT =~ /\G\]/gc) { return ['a', \@a]; }
        while (1) {
            my $v = jvalue($depth + 1);
            return undef if $JBAD;
            push @a, $v;
            jws();
            if ($JT =~ /\G,/gc) { next; }
            if ($JT =~ /\G\]/gc) { last; }
            $JBAD = 1;
            return undef;
        }
        return ['a', \@a];
    }
    if (substr($JT, pos($JT), 1) eq '"') {
        my $s = jstring();
        return undef if !defined $s;
        return $JLONG ? ['x', ''] : ['s', $s];
    }
    if ($JT =~ /\G(-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/gc) { return ['n', $1]; }
    if ($JT =~ /\G(true|false|null)/gc) { return ['l', $1]; }
    $JBAD = 1;
    return undef;
}

sub json_parse {
    my ($text) = @_;
    return undef if length($text) > 16 * 1024 * 1024;
    $JT = $text;
    $JBAD = 0;
    pos($JT) = 0;
    my $v = jvalue(0);
    return undef if $JBAD || !defined $v;
    jws();
    return undef if pos($JT) != length($JT);
    return $v;
}

sub json_esc {
    my ($c) = @_;
    return '\\"' if $c == 0x22;
    return '\\\\' if $c == 0x5c;
    if ($c > 0xFFFF) {
        my $d = $c - 0x10000;
        return sprintf('\\u%04x\\u%04x', 0xD800 + ($d >> 10), 0xDC00 + ($d & 0x3FF));
    }
    return sprintf('\\u%04x', $c);
}

sub json_str {
    my ($s) = @_;
    $s =~ s/(["\\]|[^\x20-\x7e])/json_esc(ord $1)/ge;
    return '"' . $s . '"';
}

sub json_write {
    my ($v) = @_;
    my ($t, $x) = @$v;
    if ($t eq 'o') { return '{' . join(',', map { json_str($_) . ':' . json_write($x->{$_}) } sort keys %$x) . '}'; }
    if ($t eq 'a') { return '[' . join(',', map { json_write($_) } @$x) . ']'; }
    if ($t eq 's') { return json_str($x); }
    return $x;
}

sub json_top {
    my ($v) = @_;
    if ($v->[0] eq 'a') {
        return "[]\n" if !@{ $v->[1] };
        return "[\n" . join(",\n", map { json_write($_) } @{ $v->[1] }) . "\n]\n";
    }
    return json_write($v) . "\n";
}

if ($MODE eq 'jsoncheck') {
    open(my $jh, '<:raw', $RAW) or exit 1;
    my $t = do { local $/; <$jh> };
    close $jh;
    exit(defined json_parse(defined $t ? $t : '') ? 0 : 1);
}

# The list of kept domains from the script's own marker block, on standard input.
my %kept;
while (my $l = <STDIN>) {
    chomp $l;
    if ($l =~ /^K ([a-z0-9.-]+)$/) { $kept{$1} = 1 }
}

my @terms;
if (open(my $th, '<', $TERMSFILE)) {
    my %seen;
    while (my $t = <$th>) {
        chomp $t;
        next if $t eq '' || $seen{lc $t}++;
        push @terms, $t;
    }
    close $th;
}
@terms = sort { length($b) <=> length($a) or lc($a) cmp lc($b) } @terms;
my $TERMS = @terms ? join('|', map { quotemeta } @terms) : '';

my %PLATFORM_DEFAULT = map { $_ => 1 } qw(admin bitcoin lnd btcpay electrs fulcrum rtl thunderhub
    mempool tor debian-tor lndg joinmarket umbrel start9 mynode pi ubuntu debian root raspiblitz
    raspberrypi localhost nixos operator user);

# ---------- numbering and placeholders ----------
my (%map, %cnt, %occ, %rawset, %phset, %p24, %keptseen);
my $p24n = 0;
# Every text of the input, lower-cased: replacement addresses are chosen so that
# none of them appears in it, so a replacement can never be mistaken for the
# value it replaced (and the self-check can never skip a real address that
# happens to look like one of ours).
my $CORPUS = '';
# True when the input is a recording this script made earlier (its own log is
# there): its placeholders are expected, and a second pass must give the same names.
my $REREDACT = 0;
# The addresses of the input in normal form (an IPv4 without leading zeros, an
# IPv6 as eight four-digit groups), so a replacement that spells the same address
# another way (fd00:0:0:0:0:0:0:1 and fd00::1) is also refused.
my (%IN4, %IN4NET, %IN6);
sub note_addresses {
    my ($s) = @_;
    while ($s =~ /(?<![0-9A-Za-z.])(\d{1,3}(?:\.\d{1,3}){3})(?![0-9A-Za-z])/g) {
        my @o = map { $_ + 0 } split /\./, $1;
        next if grep { $_ > 255 } @o;
        $IN4{join('.', @o)} = 1;
        $IN4NET{join('.', @o[0 .. 2])} = 1;
    }
    while ($s =~ /(?<![0-9A-Fa-f:])([0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7})(?![0-9A-Fa-f:])/g) {
        my $g = ipv6_groups($1);
        $IN6{join(':', @$g)} = 1 if defined $g;
    }
    return;
}
sub in_input {
    my ($c) = @_;
    return 1 if index($CORPUS, lc $c) >= 0;
    if ($c =~ /^\d{1,3}(?:\.\d{1,3}){3}\z/) { return 1 if $IN4{join('.', map { $_ + 0 } split /\./, $c)}; }
    elsif (my $g = ipv6_groups($c)) { return 1 if $IN6{join(':', @$g)}; }
    return 0;
}
my ($pubn, %v6n) = (0);
sub pub_addr {
    my ($n) = @_;
    return "203.0.113.$n" if $n <= 254;
    return '198.51.100.' . ($n - 254) if $n <= 508;
    return '192.0.2.' . ($n - 508) if $n <= 762;
    return undef;
}
sub next_public {
    while (1) {
        $pubn++;
        my $c = pub_addr($pubn);
        fail('Too many different public addresses in this setup.', 1) if !defined $c;
        return $c if !in_input($c);
    }
}
sub next_v6 {
    my ($prefix) = @_;
    while (1) {
        $v6n{$prefix}++;
        fail('Too many different IPv6 addresses in this setup.', 1) if $v6n{$prefix} > 65535;
        my $c = sprintf('%s::%x', $prefix, $v6n{$prefix});
        return $c if !in_input($c);
    }
}
my $extrasecret = 0;
my $DROPPED = 0;

# Whitespace that is not a tab or line break, and zero-width characters, become
# a plain space before anything is detected, so NBSP-separated words can't hide.
sub norm_ws {
    my ($s) = @_;
    my $c = $s;
    return $s if !utf8::decode($c);
    $c =~ s/[^\S\t\r\n]|[\x{200B}-\x{200D}\x{2060}\x{FEFF}]/ /g;
    utf8::encode($c);
    return $c;
}

# Public software, reviewed. Names outside these lists are private identifiers.
my %PUBLIC_NAMES = map { $_ => 1 } qw(bitcoind bitcoin-cli bitcoin-qt bitcoin bitcoin-core lnd lncli
    lightningd lightning-cli lightning core-lightning cln electrs fulcrum tor strfry nutshell cashu mint
    mempool btcpay btcpayserver nbxplorer thunderhub rtl lndg joinmarket nginx redis postgres postgresql
    mariadb mysql docker dockerd containerd cron sshd ssh systemd dbus chronyd ntpd rsyslogd avahi-daemon
    bash wpa_supplicant NetworkManager dhcpcd);
my %PUBLIC_PACKAGES = map { $_ => 1 } qw(tor tor-geoipdb torsocks openssh-server openssh-client
    openssh-sftp-server openssl libssl3 libssl1.1 ca-certificates curl wget git bash dash coreutils
    systemd udev dbus nginx apache2 redis-server postgresql mariadb-server docker.io docker-ce
    docker-ce-cli containerd containerd.io runc ufw fail2ban cron rsyslog chrony ntp python3 perl
    libc6 libgcc-s1 libstdc++6 zlib1g libsqlite3-0 sqlite3 bitcoind bitcoin-qt lightningd electrs
    fulcrum unattended-upgrades apt dpkg util-linux login passwd base-files raspberrypi-kernel
    raspberrypi-bootloader raspi-config firmware-brcm80211 wireguard wireguard-tools nftables iptables
    smartmontools tmux screen vim nano htop);
my %PUBLIC_REPOS = map { $_ => 1 } ('lightninglabs/lnd', 'lightninglabs/loop', 'lightninglabs/pool',
    'btcpayserver/btcpayserver', 'btcpayserver/nbxplorer', 'btcpayserver/lightning', 'btcpayserver/bitcoin',
    'bitcoin/bitcoin', 'lncm/bitcoind', 'lncm/lnd', 'lncm/electrs', 'elementsproject/lightningd',
    'cashubtc/nutshell', 'cashubtc/cdk-mintd', 'hoytech/strfry', 'mempool/frontend', 'mempool/backend',
    'thunderhub/thunderhub', 'cryptosharks131/lndg', 'nginx', 'redis', 'postgres', 'mariadb', 'mysql', 'tor');
my %PUBLIC_SOURCES = map { $_ => 1 } ('github.com/hoytech/strfry', 'github.com/lightningnetwork/lnd',
    'github.com/bitcoin/bitcoin', 'github.com/btcpayserver/btcpayserver', 'github.com/cashubtc/nutshell');
my %PUBLIC_SERVICES = map { $_ => 1 } qw(bitcoin-core lnd core-lightning strfry nutshell tor electrs fulcrum
    btcpay mempool bitcoin lightning btcpay-server thunderhub rtl lndg);
my %PUBLIC_FLAGS = map { $_ => 1 } qw(IsolateClientAddr IsolateSOCKSAuth IsolateClientProtocol
    NoIsolateSOCKSAuth KeepAliveIsolateSOCKSAuth IsolateDestPort IsolateDestAddr OnionTrafficOnly CacheDNS
    CacheIPv4DNS CacheIPv6DNS PreferIPv6 NoAdvertise IPv6Only IPv4Only NoListen auto);

# Dropped or replaced text is still checked: a secret in a discarded field still counts.
sub dropped {
    my ($raw) = @_;
    $DROPPED++;
    $extrasecret++ if defined $raw && looks_secret($raw);
    return;
}

sub scan_tree {
    my ($v) = @_;
    return if ref($v) ne 'ARRAY';
    my ($t, $x) = @$v;
    if ($t eq 's') { $extrasecret++ if looks_secret($x); }
    elsif ($t eq 'o') { for my $k (keys %$x) { $extrasecret++ if looks_secret($k); scan_tree($x->{$k}); } }
    elsif ($t eq 'a') { scan_tree($_) for @$x; }
    return;
}

sub pseudo {
    my ($class, $prefix, $raw) = @_;
    $extrasecret++ if looks_secret($raw, 'gen');
    return rep($class, $raw, $raw, sub { "$prefix-$_[0]" });
}

# Build metadata that may follow a version (-beta, -rc1, -alpine3.18, a short hash).
sub build_meta_ok {
    my ($s) = @_;
    for my $t (split /[-.+_~]/, $s) {
        next if $t eq '';
        return 0 if $t !~ /^(?:(?:alpha|beta|rc|pre|dev|preview|snapshot|stable|alpine|slim|bookworm|bullseye|buster|debian|ubuntu|arm64|amd64|armv[67]|aarch64|x86|linux|musl|glibc|build|r|b|p)[0-9]*|[0-9]{1,8}|g?(?=[0-9a-f]*[0-9])(?=[0-9a-f]*[a-f])[0-9a-f]{7,40})\z/i;
    }
    return 1;
}

# A version-shaped value as it is, a version with unknown text after it cut back to
# the version, or undef when nothing in it is a version.
sub version_clean {
    my ($v) = @_;
    return $v if $v =~ /^REDACTED-[A-Z0-9]{2,12}-[0-9]{1,6}\z/;
    return $v if $v =~ /^(?:latest|stable)\z/ || $v =~ /^(?=[0-9a-f]*[0-9])[0-9a-f]{7,40}\z/;
    if ($v =~ /^(v?[0-9]+(?:\.[0-9]+){0,4})([-+_.~].*)?\z/s) {
        my ($prefix, $rest) = ($1, $2);
        return $v if !defined $rest || build_meta_ok($rest);
        return $prefix;
    }
    return undef;
}

# A Debian version: an optional epoch, the upstream version, then only revision and
# build tokens (digits, deb12u1, bpo12, rpi1, ubuntu, +b1, dfsg ...). Anything else
# in it is the owner's text.
sub dpkg_version_ok {
    my ($v) = @_;
    return 1 if $v =~ /^REDACTED-[A-Z0-9]{2,12}-[0-9]{1,6}\z/;
    return 0 if $v !~ /^(?:[0-9]+:)?([0-9][A-Za-z0-9.+~:-]*)\z/;
    my $rest = $1;
    $rest =~ s/^[0-9]+(?:\.[0-9]+)*//;
    for my $t (split /[-+~.:]/, $rest) {
        next if $t eq '';
        return 0 if $t !~ /^(?:[0-9]+|[a-z]{1,2}[0-9]*|[0-9]*(?:deb|bpo|rpi|ubuntu|build|b|rc|alpha|beta|pre|dev|git|svn|hg|really)[0-9]*(?:u[0-9]+)?|dfsg|ds|nmu|g?(?=[0-9a-f]*[0-9])(?=[0-9a-f]*[a-f])[0-9a-f]{7,40})\z/;
    }
    return 1;
}

sub pseudo_image {
    my ($s) = @_;
    return $s if $s =~ /^sha256:[0-9a-f]{64}\z/;
    my $digest = '';
    my $ref = $s;
    $digest = $1 if $ref =~ s/(\@sha256:[0-9a-f]{64})\z//;
    my $body = $ref;
    my $tag;
    $tag = $1 if $body =~ s/:([^\/:]+)\z//;
    my @p = split m{/}, $body;
    my $host;
    $host = shift @p if @p > 1 && $p[0] =~ /[.:]|^localhost\z/;
    my $path = lc join('/', @p);
    if ((!defined $host || $kept{lc $host}) && $PUBLIC_REPOS{$path}) {
        $extrasecret++ if looks_secret($s, 'gen');
        # A tag is kept only as far as it is a version (latest and stable count as
        # one); anything else is the operator's own text, even on a public repository.
        if (defined $tag) {
            my $c = version_clean($tag);
            if (!defined $c) { $tag = pseudo('image-tag', 'tag', $tag); }
            elsif ($c ne $tag) { $rawset{$tag} = 1; $tag = $c; }
        }
        return $body . (defined $tag ? ":$tag" : '') . $digest;
    }
    return pseudo('image', 'image', $ref) . $digest;
}

my @B58 = split //, '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
my @B32 = split //, 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
my @B32O = split //, 'abcdefghijklmnopqrstuvwxyz234567';

sub digits {
    my ($n, $alpha) = @_;
    my $base = scalar @$alpha;
    my $s = '';
    while ($n > 0) { $s = $alpha->[$n % $base] . $s; $n = int($n / $base); }
    return $s eq '' ? $alpha->[0] : $s;
}

# prefix + pad characters + suffix, at least as long as $len.
sub padded {
    my ($prefix, $pad, $suffix, $len) = @_;
    my $room = $len - length($prefix) - length($suffix);
    $room = 0 if $room < 0;
    return $prefix . ($pad x $room) . $suffix;
}

sub rep {
    my ($class, $raw, $key, $maker) = @_;
    $occ{$class}++;
    $rawset{$raw} = 1;
    my $ph = $map{$class}{$key};
    if (!defined $ph) {
        $cnt{$class}++;
        $ph = $maker->($cnt{$class});
        # A fresh input must not hold a text that equals one of our placeholders: it
        # would come out as it went in and the self-check could not tell it apart.
        if (!$REREDACT) {
            my $guard = 0;
            while ($guard++ < 10000 && index($CORPUS, lc $ph) >= 0) {
                $cnt{$class}++;
                $ph = $maker->($cnt{$class});
            }
        }
        $map{$class}{$key} = $ph;
        $phset{$ph} = 1;
    }
    return $ph;
}

sub valid_v4 {
    my ($ip) = @_;
    return 0 if $ip !~ /^\d{1,3}(?:\.\d{1,3}){3}\z/;
    for my $o (split /\./, $ip) { return 0 if $o > 255; }
    return 1;
}

sub map_ipv4 {
    my ($ip) = @_;
    my @o = split /\./, $ip;
    return $ip if @o != 4;
    for my $o (@o) { return $ip if length($o) > 3 || $o > 255; }
    my ($a, $b, $c, $d) = map { $_ + 0 } @o;
    return $ip if $a == 0 || $a == 127 || $a >= 224;
    my $private = $a == 10 || ($a == 172 && $b >= 16 && $b <= 31) || ($a == 192 && $b == 168)
        || ($a == 100 && $b >= 64 && $b <= 127) || ($a == 169 && $b == 254);
    my $key = "$a.$b.$c.$d";
    if ($private) {
        return rep('ipv4-private', $ip, $key, sub {
            my $net = "$a.$b.$c";
            if (!defined $p24{$net}) {
                do {
                    $p24n++;
                    fail('Too many different private addresses in this setup.', 1) if $p24n > 254;
                } while (in_input("10.200.$p24n.") || $IN4NET{"10.200.$p24n"});
                $p24{$net} = $p24n;
            }
            return "10.200.$p24{$net}.$d";
        });
    }
    return rep('ipv4-public', $ip, $key, sub { next_public() });
}

sub ipv6_groups {
    my ($s) = @_;
    return undef if $s !~ /^[0-9A-Fa-f:]+$/;
    return undef if $s =~ /:::/;
    my @halves = split /::/, $s, -1;
    return undef if @halves > 2;
    my @g;
    if (@halves == 2) {
        my @l = length($halves[0]) ? split(/:/, $halves[0], -1) : ();
        my @r = length($halves[1]) ? split(/:/, $halves[1], -1) : ();
        for my $x (@l, @r) { return undef if $x !~ /^[0-9A-Fa-f]{1,4}$/; }
        return undef if @l + @r > 7;
        @g = (@l, ('0') x (8 - @l - @r), @r);
    } else {
        @g = split /:/, $s, -1;
        return undef if @g != 8;
        for my $x (@g) { return undef if $x !~ /^[0-9A-Fa-f]{1,4}$/; }
    }
    return [map { sprintf('%04x', hex $_) } @g];
}

sub map_ipv6 {
    my ($raw) = @_;
    if ($raw =~ /^(.*:)(\d{1,3}(?:\.\d{1,3}){3})$/) {
        return $1 . map_ipv4($2);
    }
    my $g = ipv6_groups($raw);
    return $raw if !defined $g;
    my $first = hex $g->[0];
    return $raw if !grep { $_ ne '0000' } @$g;
    return $raw if join('', @$g[0 .. 6]) eq '0' x 28 && $g->[7] eq '0001';
    return $raw if $first >= 0xff00;
    my $key = join(':', @$g);
    if ($first >= 0xfe80 && $first <= 0xfebf) {
        return rep('ipv6-link-local', $raw, $key, sub { next_v6('fe80') });
    }
    if ($first >= 0xfc00 && $first <= 0xfdff) {
        return rep('ipv6-ula', $raw, $key, sub { next_v6('fd00') });
    }
    return rep('ipv6-global', $raw, $key, sub { next_v6('2001:db8') });
}

sub valid_ip {
    my ($s) = @_;
    return 1 if valid_v4($s);
    return valid_v4($1) if $s =~ /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})\z/i;
    return defined ipv6_groups($s) ? 1 : 0;
}

# ---------- layer 1: keep only named, type-checked fields ----------

# A schema is a hash: k (kind) plus re, min, max, f (fields) or e (element).
sub S_str { my ($re) = @_; return { k => 'str', re => qr/^(?:$re)\z/ }; }
sub S_int { my ($min, $max) = @_; return { k => 'int', min => $min, max => $max }; }
sub S_obj { return { k => 'obj', f => {@_} }; }
sub S_arr { return { k => 'arr', e => $_[0] }; }
sub S_enum { return { k => 'enum', list => { map { $_ => 1 } @_ } }; }
my $S_BOOL = { k => 'bool' };
my $S_IP = { k => 'ip' };

sub clean {
    my ($v, $s) = @_;
    my ($t, $x) = @$v;
    my $k = $s->{k};
    if ($k eq 'str') { return ($t eq 's' && $x =~ $s->{re}) ? $v : undef; }
    if ($k eq 'int') {
        return undef if $t ne 'n' || $x !~ /^(?:0|[1-9][0-9]{0,14})\z/;
        return undef if defined $s->{min} && $x < $s->{min};
        return undef if defined $s->{max} && $x > $s->{max};
        return $v;
    }
    if ($k eq 'bool') { return ($t eq 'l' && ($x eq 'true' || $x eq 'false')) ? $v : undef; }
    if ($k eq 'enum') { return ($t eq 's' && $s->{list}{$x}) ? $v : undef; }
    if ($k eq 'ip') { return ($t eq 's' && valid_ip($x)) ? $v : undef; }
    if ($k eq 'obj') {
        return undef if $t ne 'o';
        my %new;
        for my $key (sort keys %$x) {
            if (exists $s->{f}{$key}) {
                my $c = clean($x->{$key}, $s->{f}{$key});
                if (defined $c) { $new{$key} = $c; } else { $DROPPED++; scan_tree($x->{$key}); }
            } else { $DROPPED++; $extrasecret++ if looks_secret($key); scan_tree($x->{$key}); }
        }
        return ['o', \%new];
    }
    if ($k eq 'arr') {
        return undef if $t ne 'a';
        my @new;
        for my $item (@$x) {
            my $c = clean($item, $s->{e});
            if (defined $c) { push @new, $c; } else { $DROPPED++; scan_tree($item); }
        }
        return ['a', \@new];
    }
    return undef;
}

my $LABELVAL = S_str('[A-Za-z0-9 ._:/@+-]{1,200}');
my @LABELKEYS = qw(
    com.docker.compose.project com.docker.compose.service com.docker.compose.version
    org.opencontainers.image.version org.opencontainers.image.revision
    org.opencontainers.image.title org.opencontainers.image.source);
my %LABELKEY = map { $_ => 1 } @LABELKEYS;
my $LABELS = S_obj(map { $_ => $LABELVAL } @LABELKEYS);
my $IMAGEREF = S_str('[A-Za-z0-9][A-Za-z0-9._/:@-]{0,255}');
my $DIGEST = S_str('sha256:[0-9a-f]{64}');
my $PORT = S_int(1, 65535);
my $VER64 = S_str('[A-Za-z0-9._+-]{1,64}');
my $VERSTR = S_str('[A-Za-z0-9 ._:=+-]{1,80}');
my $SLUGISH = S_str('[a-z0-9_-]{1,16}');

my %SCHEMA;
$SCHEMA{'docker-ps.json'} = S_arr(S_obj(
    Names => S_arr(S_str('/[A-Za-z0-9][A-Za-z0-9_.-]{0,127}')),
    Image => $IMAGEREF,
    ImageID => $DIGEST,
    State => S_enum(qw(created running paused restarting removing exited dead)),
    Status => S_str('[A-Za-z0-9 ()._:-]{1,64}'),
    Labels => $LABELS,
    Ports => S_arr(S_obj(IP => $S_IP, PrivatePort => $PORT, PublicPort => $PORT, Type => S_enum(qw(tcp udp sctp)))),
));
$SCHEMA{'docker-images.json'} = S_arr(S_obj(
    Id => $DIGEST,
    RepoTags => S_arr($IMAGEREF),
    RepoDigests => S_arr(S_str('[A-Za-z0-9][A-Za-z0-9._/:-]{0,255}@sha256:[0-9a-f]{64}')),
    Labels => $LABELS,
));
$SCHEMA{'docker-version.json'} = S_obj(
    (map { $_ => $VER64 } qw(Version ApiVersion MinAPIVersion Os Arch KernelVersion GitCommit)),
    Components => S_arr(S_obj(Name => $VER64, Version => $VER64)),
);
my $NI = S_obj(
    version => S_int(), subversion => S_str('(?:/[A-Za-z][A-Za-z ]{0,30}:[0-9][0-9A-Za-z.+-]{0,30})+/'),
    protocolversion => S_int(), localservicesnames => S_arr(S_str('[A-Za-z0-9_]{1,40}')),
    networks => S_arr(S_obj(name => $SLUGISH, reachable => $S_BOOL, limited => $S_BOOL)),
);
my $LNDV = S_obj(
    version => $VERSTR, commit => $VERSTR, commit_hash => S_str('[0-9a-f]{40}'),
    app_major => S_int(), app_minor => S_int(), app_patch => S_int(), app_pre_release => $VERSTR,
    build_tags => S_arr($VERSTR), go_version => $VERSTR,
);
my $GETVERSION = S_obj(lnd => $LNDV, lncli => $LNDV);
my $GETINFO = S_obj(
    version => $VERSTR, commit_hash => S_str('[0-9a-f]{40}'),
    chains => S_arr(S_obj(chain => $SLUGISH, network => $SLUGISH)),
    network => $SLUGISH, synced_to_chain => $S_BOOL,
);
my $NIP11 = S_obj(
    software => S_str('[A-Za-z0-9+.:/_@-]{1,200}'), version => $VER64, supported_nips => S_arr(S_int()),
);
my $NUT06 = S_obj(version => S_str('[A-Za-z0-9._/+-]{1,64}'));
my $MYNODE = S_obj(map { $_ => S_str('[A-Za-z0-9 ._+-]{1,64}') } qw(name short_name latest_version));

sub extract_json {
    my ($name, $text) = @_;
    $JLONGSECRET = 0;
    my $v = json_parse($text);
    $extrasecret += $JLONGSECRET;
    return undef if !defined $v;
    my $schema;
    if ($name =~ m{^replies/[^/]+/server-version\.json\z}) {
        my $list = $v->[0] eq 'a' ? $v : ($v->[0] eq 'o' && $v->[1]{result} ? $v->[1]{result} : undef);
        return undef if !defined $list || $list->[0] ne 'a' || @{ $list->[1] } != 2;
        my $item = S_str('[A-Za-z0-9 ._+-]{1,64}');
        my @out;
        for my $e (@{ $list->[1] }) {
            my $c = clean($e, $item);
            return undef if !defined $c;
            push @out, $c;
        }
        return ['o', { result => ['a', \@out] }];
    }
    elsif (exists $SCHEMA{$name}) { $schema = $SCHEMA{$name}; }
    elsif ($name =~ m{^replies/[^/]+/getnetworkinfo\.json\z}) { $schema = $NI; }
    elsif ($name =~ m{^replies/[^/]+/getversion\.json\z}) { $schema = $GETVERSION; }
    elsif ($name =~ m{^replies/[^/]+/getinfo\.json\z}) { $schema = $GETINFO; }
    elsif ($name =~ m{^replies/[^/]+/nip11\.json\z}) { $schema = $NIP11; }
    elsif ($name =~ m{^replies/[^/]+/nut06\.json\z}) { $schema = $NUT06; }
    elsif ($name =~ m{^apps/[^/]+/[^/]+\.json\z}) { $schema = $MYNODE; }
    else { return undef; }
    my $c = clean($v, $schema);
    pseudo_json($name, $c) if defined $c;
    return $c;
}

sub pseudo_labels {
    my ($lv) = @_;
    return if ref($lv) ne 'ARRAY' || $lv->[0] ne 'o';
    for my $k (sort keys %{ $lv->[1] }) {
        my $val = $lv->[1]{$k};
        next if $val->[0] ne 's';
        my $x = $val->[1];
        if ($k =~ /\.(?:version|revision)\z/) {
            # Free text in a version label is the operator's own: only a version stays.
            my $c = version_clean($x);
            if (!defined $c) { $val->[1] = pseudo('label-value', 'label', $x); }
            elsif ($c ne $x) { $rawset{$x} = 1; $val->[1] = $c; }
            next;
        }
        if ($k eq 'org.opencontainers.image.source') {
            my $bare = $x;
            $bare =~ s{^(?:git\+)?[a-z]+:/+}{};
            $bare =~ s/\.git\z//;
            next if $PUBLIC_SOURCES{$bare};
        }
        elsif ($PUBLIC_NAMES{lc $x}) { next; }
        $val->[1] = pseudo('label-value', 'label', $x);
    }
    return;
}

sub pseudo_json {
    my ($name, $v) = @_;
    if ($name eq 'docker-ps.json') {
        for my $c (@{ $v->[1] }) {
            next if $c->[0] ne 'o';
            my $h = $c->[1];
            if (exists $h->{Names}) {
                for my $n (@{ $h->{Names}[1] }) {
                    my $raw = substr($n->[1], 1);
                    $n->[1] = '/' . pseudo('container-name', 'container', $raw) if !$PUBLIC_NAMES{lc $raw};
                }
            }
            $h->{Image}[1] = pseudo_image($h->{Image}[1]) if exists $h->{Image};
            pseudo_labels($h->{Labels}) if exists $h->{Labels};
        }
    }
    elsif ($name =~ m{^replies/[^/]+/nip11\.json\z}) {
        # The relay's software URL names the operator's account unless it is a reviewed public source.
        my $sw = $v->[1]{software};
        if (defined $sw && $sw->[0] eq 's') {
            (my $bare = $sw->[1]) =~ s{^(?:git\+)?[a-z]+:/+}{};
            $bare =~ s/\.git\z//;
            $bare =~ s{/+\z}{};
            $sw->[1] = pseudo('software', 'software', $sw->[1]) if !$PUBLIC_SOURCES{$bare};
        }
    }
    elsif ($name =~ m{^apps/[^/]+/[^/]+\.json\z}) {
        # A myNode display name is kept only when it is a public product name.
        for my $k (qw(name short_name)) {
            my $e = $v->[1]{$k};
            next if !defined $e || $e->[0] ne 's';
            my $lc = lc $e->[1];
            (my $dash = $lc) =~ s/[ ]+/-/g;
            (my $solid = $lc) =~ s/[ ]+//g;
            next if grep { $PUBLIC_NAMES{$_} || $PUBLIC_SERVICES{$_} } ($lc, $dash, $solid);
            $e->[1] = pseudo('app-name', 'name', $e->[1]);
        }
    }
    elsif ($name eq 'docker-images.json') {
        for my $c (@{ $v->[1] }) {
            next if $c->[0] ne 'o';
            my $h = $c->[1];
            for my $k (qw(RepoTags RepoDigests)) {
                next if !exists $h->{$k};
                $_->[1] = pseudo_image($_->[1]) for @{ $h->{$k}[1] };
            }
            pseudo_labels($h->{Labels}) if exists $h->{Labels};
        }
    }
    return;
}

sub joined { return @_ ? join("\n", @_) . "\n" : ''; }

sub extract_umbrel {
    my ($text, $folder) = @_;
    # The app's id (its folder when the file has none) decides whether its display name is public.
    my $appid = $folder;
    $appid = $2 if $text =~ /^id:[ ]+(["']?)([A-Za-z0-9._()+-]{1,80})\1[ \t\r]*$/m;
    my @out;
    my $deps = 0;
    for my $line (split /\n/, $text, -1) {
        $line =~ s/\r\z//;
        next if $line =~ /^\s*\z/;
        if ($line =~ /^(manifestVersion|id|name|version|category|port):[ ]+(.*)\z/) {
            my ($key, $val) = ($1, $2);
            $deps = 0;
            if ($key eq 'manifestVersion' && $val !~ /^["']?[0-9]{1,3}(?:\.[0-9]{1,3})?["']?\z/) { dropped($line); next; }
            if ($key eq 'port' && $val !~ /^["']?[0-9]{1,5}["']?\z/) { dropped($line); next; }
            if ($key eq 'version' && $val =~ /^(["']?)(.*)\1\z/) {
                # Only a version stays; free text there is the operator's own.
                my ($q, $bare) = ($1, $2);
                my $c = version_clean($bare);
                if (!defined $c) { $c = rep('version-text', $bare, "apps/$appid/version", sub { "version-$_[0]" }); }
                elsif ($c ne $bare) { $rawset{$bare} = 1; }
                $val = $q . $c . $q;
            }
            if ($key eq 'category' && $val =~ /^(["']?)(.*)\1\z/) {
                # Umbrel's own categories only.
                my ($q, $bare) = ($1, $2);
                if (lc $bare !~ /^(?:bitcoin|lightning|files|media|networking|social|automation|finance|development|security|utility|ai|gaming|nostr|wallet|productivity)\z/) {
                    $val = rep('category-text', $bare, "category/$bare", sub { 'category-other' });
                }
            }
            # A display name is kept only for a public app; otherwise it is name-N, one number per app.
            if ($key eq 'name' && !$PUBLIC_SERVICES{$appid}) {
                my $id = $appid;
                $val = rep('app-name', $val, "apps/$id/name", sub { "name-$_[0]" });
            }
            # The id is the folder's name: it gets the same pseudonym as the folder.
            if ($key eq 'id' && $val =~ /^(["']?)([A-Za-z0-9._()+-]{1,80})\1\z/ && !$PUBLIC_SERVICES{$2}) {
                my ($q, $bare) = ($1, $2);
                $val = $q . rep('path-name', $bare, "apps/$bare", sub { "app-$_[0]" }) . $q;
            }
            if ($val =~ /^["']?[A-Za-z0-9 ._()+-]{0,80}["']?\z/) { push @out, "$key: $val"; } else { dropped($line); }
        }
        elsif ($line =~ /^dependencies:[ ]*\[\][ ]*\z/) { push @out, 'dependencies: []'; $deps = 0; }
        elsif ($line =~ /^dependencies:[ ]*\z/) { push @out, 'dependencies:'; $deps = 1; }
        elsif ($deps && $line =~ /^  - ([a-z0-9]+(?:-[a-z0-9]+)*)\z/) {
            # A dependency is an app id: it gets the pseudonym of the folder of that name.
            my $dep = $1;
            $dep = rep('path-name', $dep, "apps/$dep", sub { "app-$_[0]" }) if !$PUBLIC_SERVICES{$dep};
            push @out, "  - $dep";
        }
        else { $deps = 0; dropped($line); }
    }
    return joined(@out);
}

# Units that every Debian, Raspberry Pi OS, RaspiBlitz, Umbrel or myNode box has; any other unit name is private.
my %PUBLIC_UNITS = map { $_ => 1 } qw(cron ssh sshd docker containerd dbus nginx redis-server redis postgresql
    mariadb mysql rsyslog chrony ntp networking networkmanager wpa_supplicant avahi-daemon dhcpcd getty
    serial-getty console-getty user user-runtime-dir rc-local apt-daily apt-daily-upgrade unattended-upgrades
    fail2ban ufw nftables iptables smartmontools bluetooth hciuart raspi-config rpi-eeprom-update triggerhappy
    polkit modemmanager accounts-daemon udisks2 lightdm packagekit snapd cups zramswap haveged
    background raspiblitz blitzapi btc-rpc-explorer lit litd loopd poold lnbits
    umbrel umbrel-startup umbrel-external-storage umbrel-connection-details mynode mynode-reboot
    docker-compose btcpay-server
    systemd-journald systemd-logind systemd-networkd systemd-resolved systemd-timesyncd systemd-udevd
    systemd-udev-trigger systemd-udev-settle systemd-tmpfiles-setup systemd-tmpfiles-setup-dev
    systemd-tmpfiles-clean systemd-sysctl systemd-modules-load systemd-remount-fs systemd-random-seed
    systemd-update-utmp systemd-user-sessions systemd-journal-flush systemd-fsck-root systemd-rfkill
    systemd-hostnamed systemd-timedated systemd-localed systemd-machined systemd-backlight);
sub public_unit { my ($b) = @_; $b = lc $b; return $PUBLIC_UNITS{$b} || $PUBLIC_NAMES{$b} || $PUBLIC_SERVICES{$b} ? 1 : 0; }

sub extract_systemctl {
    my ($text) = @_;
    my @out;
    for my $line (split /\n/, $text) {
        my @f = split ' ', $line;
        if (@f < 4) { dropped($line) if @f; next; }
        my ($unit, $load, $active, $sub) = @f[0 .. 3];
        my $ok = $unit =~ /^[A-Za-z0-9@._:\\-]{1,200}\.service\z/;
        for my $c ($load, $active, $sub) { $ok = 0 if $c !~ /^[a-z-]{1,20}\z/; }
        if (!$ok) { dropped($line); next; }
        my ($ubase, $uinst) = $unit =~ /^([^@]*)@(.*)\.service\z/ ? ($1, $2) : ($unit =~ /^(.*)\.service\z/ ? ($1, undef) : ($unit, undef));
        # Any unit name that is not on the public list is replaced whole (a key in
        # it is counted by pseudo), so no private prefix stays beside a key.
        $ubase = pseudo('unit-name', 'unit', $ubase) if !public_unit($ubase);
        if (defined $uinst) {
            $uinst = pseudo('unit-instance', 'instance', $uinst)
                if $uinst !~ /^(?:default|lo|eth0|wlan0|[0-9]{1,10}|tty[A-Za-z0-9]{1,6})\z/;
            $unit = "$ubase\@$uinst.service";
        } else { $unit = "$ubase.service"; }
        push @out, "$unit $load $active $sub";
    }
    return joined(@out);
}

sub extract_dpkg {
    my ($text) = @_;
    my @out;
    for my $line (split /\n/, $text) {
        my @f = split /\t/, $line, -1;
        if (@f != 3 || $f[0] !~ /^[a-z0-9][a-z0-9+.-]{0,100}\z/ || $f[1] !~ /^[A-Za-z0-9.+~:-]{1,100}\z/
            || $f[2] !~ /^[a-zA-Z ]{1,3}\z/) { dropped($line); next; }
        $f[0] = pseudo('package', 'package', $f[0]) if !$PUBLIC_PACKAGES{$f[0]};
        # A Debian version starts with a digit (after an optional epoch); other text is the owner's.
        $f[1] = pseudo('version-text', 'version', $f[1])
            if !dpkg_version_ok($f[1]);
        push @out, join("\t", @f);
    }
    return joined(@out);
}

# One socket address: 0.0.0.0:80, *:80, [::1]:80, 127.0.0.53%lo:53. Returns it rebuilt or undef.
# An interface name the platform gives stays; one the owner chose is replaced.
sub zone_name {
    my ($z) = @_;
    return $z if $z =~ /^(?:lo|eth[0-9]{1,2}|wlan[0-9]{1,2}|en[ospx][0-9a-z]{1,12}|wl[ospx][0-9a-z]{1,12}|docker0|iface-[0-9]+)\z/;
    return pseudo('iface', 'iface', $z);
}

sub ss_addr {
    my ($s) = @_;
    if ($s =~ /^\[([0-9A-Fa-f:.]+)(?:%([a-z0-9-]{1,15}))?\]:(\d{1,5}|\*)\z/) {
        my ($ip, $zone, $port) = ($1, $2, $3);
        return undef if !valid_ip($ip);
        $zone = zone_name($zone) if defined $zone;
        return '[' . $ip . (defined $zone ? "%$zone" : '') . "]:$port";
    }
    if ($s =~ /^(\*|\d{1,3}(?:\.\d{1,3}){3})(?:%([a-z0-9-]{1,15}))?:(\d{1,5}|\*)\z/) {
        my ($ip, $zone, $port) = ($1, $2, $3);
        return undef if $ip ne '*' && !valid_v4($ip);
        $zone = zone_name($zone) if defined $zone;
        return $ip . (defined $zone ? "%$zone" : '') . ":$port";
    }
    return undef;
}

sub extract_ss {
    my ($text) = @_;
    my @out;
    for my $line (split /\n/, $text) {
        next if $line =~ /^\s*\z/;
        if ($line =~ /^State\b/) {
            if ($line =~ /^[A-Za-z: -]+\z/) { push @out, join(' ', split(' ', $line)); } else { dropped($line); }
            next;
        }
        my @f = split ' ', $line, 6;
        if (@f < 5 || $f[0] !~ /^[A-Z-]{1,16}\z/ || $f[1] !~ /^\d{1,10}\z/ || $f[2] !~ /^\d{1,10}\z/) { dropped($line); next; }
        my $local = ss_addr($f[3]);
        my $peer = ss_addr($f[4]);
        if (!defined $local || !defined $peer) { dropped($line); next; }
        my $row = "$f[0] $f[1] $f[2] $local $peer";
        if (defined $f[5]) {
            if ($f[5] =~ /^users:\(\((.*)\)\)\s*\z/) {
                my @procs;
                for my $p (split /\),\(/, $1) {
                    if ($p =~ /^"([A-Za-z0-9._-]{1,32})",pid=(\d{1,10}),fd=(\d{1,10})\z/) {
                        my ($pn, $pid, $fd) = ($1, $2, $3);
                        $pn = pseudo('process', 'process', $pn) if !$PUBLIC_NAMES{lc $pn};
                        push @procs, "(\"$pn\",pid=$pid,fd=$fd)";
                    }
                    else { dropped($line); }
                }
                $row .= ' users:(' . join(',', @procs) . ')' if @procs;
            } else { dropped($line); }
        }
        push @out, $row;
    }
    return joined(@out);
}

sub extract_torrc {
    my ($text) = @_;
    my %dir = map { lc($_) => $_ } qw(SocksPort ControlPort ORPort DirPort HiddenServiceDir HiddenServicePort
        HiddenServiceVersion CookieAuthentication RunAsDaemon UseBridges ExitRelay ClientOnly);
    my @out;
    for my $line (split /\n/, $text) {
        $line =~ s/\r\z//;
        $line =~ s/^[ \t]+//;
        next if $line eq '' || $line =~ /^#/;
        if ($line !~ /^([A-Za-z]+)[ \t]+(.*?)[ \t]*\z/ || !$dir{lc $1}) { dropped($line); next; }
        my ($name, $rest) = ($dir{lc $1}, $2);
        if ($name eq 'HiddenServiceDir') {
            my $p = $rest;
            $p =~ s/^"(.*)"\z/$1/;
            $p =~ s{/+\z}{};
            my ($last) = $p =~ m{([^/]*)\z};
            $last = 'service' if !defined $last || $last !~ /^[A-Za-z0-9_.-]{1,64}\z/;
            # The folder's own name is chosen by the node's owner; only the usual ones stay.
            # RaspiBlitz names them after the service and its port (lnd9735).
            (my $stem = lc $last) =~ s/[0-9]{1,5}\z//;
            $last = pseudo('tor-dir', 'hs', $last)
                if $last ne 'service' && $last !~ /^(?:hidden_service|hiddenservice|hidden-service|web80|web443)\z/i
                && !$PUBLIC_NAMES{$stem} && !$PUBLIC_SERVICES{$stem};
            push @out, "HiddenServiceDir /REDACTED/$last";
            next;
        }
        my @tok;
        my $bad = 0;
        for my $t (split /[ \t]+/, $rest) {
            if ($t =~ /^unix:/) { push @tok, 'unix:REDACTED'; }
            elsif ($t =~ /^\d{1,5}\z/ || $PUBLIC_FLAGS{$t}) { push @tok, $t; }
            elsif ($t =~ /^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})\z/ && valid_v4($1)) { push @tok, $t; }
            elsif ($t =~ /^\[([0-9A-Fa-f:]+)\]:(\d{1,5})\z/ && valid_ip($1)) { push @tok, $t; }
            else { $bad = 1; last; }
        }
        if ($bad || !@tok) { dropped($line); next; }
        push @out, "$name " . join(' ', @tok);
    }
    return joined(@out);
}

sub extract_binaries {
    my ($text) = @_;
    my @out;
    my $n = -1;
    for my $line (split /\n/, $text) {
        $line =~ s/\r\z//;
        if ($line =~ m{^== (/[A-Za-z0-9._/-]{1,200})\z}) { push @out, $line; $n = 0; next; }
        if ($n >= 0 && $n < 3 && $line =~ /^[-A-Za-z0-9 \t._:()\/+,=@\x80-\xff]{1,120}\z/) { push @out, $line; $n++; next; }
        dropped($line);
    }
    return joined(@out);
}

sub extract_lines {
    my ($text, $re) = @_;
    my @out;
    for my $line (split /\n/, $text) {
        if ($line =~ $re) { push @out, $line; } else { dropped($line); }
    }
    return joined(@out);
}

# Returns the extracted text, or undef when the file can't be read as its kind.
sub extract {
    my ($name, $text) = @_;
    if ($name =~ /\.json\z/) {
        my $v = extract_json($name, $text);
        return undef if !defined $v;
        my $r = redact_tree($name, $v);
        joined_seed_pass($r);
        return json_top($r);
    }
    # A mnemonic goes whole before any line rule can keep part of it.
    $text = seed_pass($name, norm_ws($text))
        if $name eq 'binaries-version.txt' || $name eq 'dpkg-query.txt' || $name =~ m{^apps/[^/]+/umbrel-app\.yml\z};
    return extract_umbrel($text, $1) if $name =~ m{^apps/([^/]+)/umbrel-app\.yml\z};
    return extract_systemctl($text) if $name eq 'systemctl-list-units.txt';
    return extract_dpkg($text) if $name eq 'dpkg-query.txt';
    return extract_ss($text) if $name eq 'ss-tlnp.txt' || $name eq 'ss-ulnp.txt';
    return extract_torrc($text) if $name eq 'torrc';
    return extract_binaries($text) if $name eq 'binaries-version.txt';
    return extract_lines($text, qr/^code(?:Version|Release)="?[A-Za-z0-9._-]{1,32}"?\z/) if $name eq 'raspiblitz-version.txt';
    return extract_lines($text, qr/^(?:[A-Za-z][A-Za-z0-9_]*="?(?:on|off)"?|(?:network|chain|lightning)="?[a-z]{1,16}"?)\z/) if $name eq 'raspiblitz-conf.txt';
    return extract_lines($text, qr/^(?:baseimage|cpu|vm|network|chain|lightning)="?[A-Za-z0-9._-]{1,32}"?\z/) if $name eq 'raspiblitz-info.txt';
    return undef;
}

# ---------- layer 2: the patterns, in priority order ----------
my @SECRETS = qw(pem secretnest secretval secretflag userinfo bearer xprv xpub nsec npub nentity wif macaroon
    lninvoice btcaddr onion keptdigest nodepubkey longhex hex64);
my @REST = qw(email mac ipv6 ipv4 homeuser term domain token);
my @ORDER = (@SECRETS, @REST);

my $B58 = '[1-9A-HJ-NP-Za-km-z]';
my $B32 = '[02-9ac-hj-np-z]';
my $NB = '(?<![A-Za-z0-9])';
my $NA = '(?![A-Za-z0-9])';
my $NH = '(?<![0-9A-Fa-f])';
my $NHA = '(?![0-9A-Fa-f])';
my $KEYWORDS = '(?i:password|passwd|pass|secret|token|apikey|api_key|api-key|auth|rpcauth|rpcuser|macaroon|rune|cookie|seed|mnemonic|privkey|private_key|credential|hashedcontrolpassword)';
my $SECRETKEY = '(?<![A-Za-z0-9_.-])[A-Za-z0-9_.-]*' . $KEYWORDS . '[A-Za-z0-9_.-]*';
# A mnemonic: 12 or more words of 3 to 8 letters (every word of the BIP39 English
# list fits; the list itself is not shipped). Between two words: white space or
# commas of any length, or 1 to 3 characters that are neither letters nor digits
# (a dash, an underscore, a colon, a dot, a slash, a bar, a mix of them), with an
# optional list number ("1. word 2) word"; a number is a list number only after
# white space or a bracket and before a dot, bracket or colon, so the "-1 " of a
# placeholder such as REDACTED-ADDRESS-1 is not one). Free text (the version
# output and every JSON value) may run over line breaks; a table file is read line by line
# (a row of a table is never a mnemonic) with the old rule across lines for
# white space only. The two forms never overlap, so the match cannot blow up.
my $WORD = '[A-Za-z]{3,8}';
my $SEP_GEN = '(?:[ \t,\r\n]{4,}|[^A-Za-z0-9]{1,3}|[ \t,\r\n(\[]{1,3}[0-9]{1,2}[.)\]:][^A-Za-z0-9]{0,2})';
my $SEP_LINE = '(?:[ \t,]{4,}|[^A-Za-z0-9\r\n]{1,3}|[ \t,(\[]{1,3}[0-9]{1,2}[.)\]:][^A-Za-z0-9\r\n]{0,2})';
my $RE_SEED_GEN = qr/(?<![A-Za-z0-9])(?:$WORD$SEP_GEN){11,}$WORD(?![A-Za-z0-9])/;
my $RE_SEED_LINE = qr/(?<![A-Za-z0-9])(?:$WORD$SEP_LINE){11,}$WORD(?![A-Za-z0-9])/;
my $RE_SEED_WS = qr/(?<![A-Za-z0-9])(?:$WORD[ \t,\r\n]+){11,}$WORD(?![A-Za-z0-9])/;
my $LABEL = '[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?';

my %ALT = (
    pem => '(?<pem>-----BEGIN [A-Z ]*PRIVATE KEY-----(?s:.*?)-----END [A-Z ]*PRIVATE KEY-----|-----BEGIN [A-Z ]*PRIVATE KEY-----(?s:.*)\z)',
    secretnest => '(?<secretnest>(?<snpre>' . $SECRETKEY . '["\']?[ \t]*[=:][ \t]*)(?<snv>(?<sbal>[\[{](?:[^{}\[\]"]++|"(?:[^"\\\\]|\\\\.)*+"|(?&sbal))*+[\]}])))',
    secretval => '(?<secretval>(?<svpre>' . $SECRETKEY . '["\']?[ \t]*[=:][ \t]*)(?!(?i:Bearer|Basic)[ \t])(?:"(?<svq>(?:[^"\\\\\r\n]|\\\\.)*)"|\'(?<svs>[^\'\r\n]*)\'|(?<svu>[^\s,;"\'{}\[\]]+)))',
    secretflag => '(?<secretflag>(?<sfpre>(?<![A-Za-z0-9_.-])--?[A-Za-z0-9_.-]*' . $KEYWORDS . '[A-Za-z0-9_.-]*[ \t]+)(?<sfv>[^\s,;"\'{}\[\]-][^\s,;"\'{}\[\]]*))',
    userinfo => '(?<userinfo>(?<uipre>[A-Za-z][A-Za-z0-9+.-]*://)(?<uiu>[^\s/@:\'"]*:[^\s/@\'"]+)@)',
    bearer => '(?<bearer>(?<brpre>\b(?i:bearer|basic)[ \t]+)(?<brv>[A-Za-z0-9+/=._~-]+))',
    xprv => '(?<xprv>[xtyzuvYZUV]prv' . $B58 . '{100,112})',
    xpub => '(?<xpub>[xtyzuvYZUV]pub' . $B58 . '{100,112})',
    nsec => '(?<nsec>(?i:nsec1' . $B32 . '{58}))',
    npub => '(?<npub>(?i:npub1' . $B32 . '{58}))',
    nentity => '(?<nentity>(?i:(?:nprofile|nevent|naddr)1' . $B32 . '{20,}))',
    wif => '(?<wif>' . $NB . '[5KLc9]' . $B58 . '{50,51}' . $NA . ')',
    macaroon => '(?<macaroon>' . $NH . '(?i:0201036c6e64)[0-9A-Fa-f]{88,}' . $NHA . '|(?<![A-Za-z0-9+/=_-])AgEDbG5k[A-Za-z0-9+/_-]{32,}={0,2})',
    lninvoice => '(?<lninvoice>(?i:' . $NB . 'ln(?:bcrt|bc|tb)[0-9a-z]{20,}' . $NA . '))',
    btcaddr => '(?<btcaddr>(?i:' . $NB . '(?:bcrt|bc|tb)1' . $B32 . '{8,87}' . $NA . ')|' . $NB . '[13mn2]' . $B58 . '{25,34}' . $NA . ')',
    onion => '(?<onion>(?i:' . $NB . '(?:[a-z2-7]{56}|[a-z2-7]{16})\.onion' . $NA . '))',
    keptdigest => '(?<keptdigest>sha256:[0-9a-f]{64}' . $NHA . ')',
    nodepubkey => '(?<nodepubkey>' . $NH . '0[23][0-9A-Fa-f]{64}' . $NHA . ')',
    longhex => '(?<longhex>' . $NH . '[0-9A-Fa-f]{100,}' . $NHA . ')',
    hex64 => '(?<hex64>' . $NH . '[0-9A-Fa-f]{64}' . $NHA . ')',
    email => '(?<email>(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@(?:' . $LABEL . '\.)+[A-Za-z]{2,63}(?![A-Za-z0-9_-]))',
    mac => '(?<mac>(?<![0-9A-Fa-f:])[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}(?![0-9A-Fa-f:]))',
    ipv6 => '(?<ipv6>(?<![0-9A-Fa-f:])(?=[0-9A-Fa-f:]*:[0-9A-Fa-f:]*:)(?:[0-9A-Fa-f:]*:(?:\d{1,3}\.){3}\d{1,3}|[0-9A-Fa-f:]+))',
    ipv4 => '(?<ipv4>(?<![0-9A-Za-z.])\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?![0-9A-Za-z])(?!\.[0-9]))',
    homeuser => '(?<homeuser>(?<hupre>/(?:home|Users)/)(?<huu>[^/\s"\',;:\x00]+)(?=[/"\'\s]|\z))',
    term => '(?<term>(?<![A-Za-z0-9])(?i:' . ($TERMS eq '' ? '(?!)' : $TERMS) . ')(?![A-Za-z0-9]))',
    domain => '(?<domain>(?<![A-Za-z0-9_-])(?:' . $LABEL . '\.)+[A-Za-z]{2,63}(?![A-Za-z0-9_-]))',
    token => '(?<token>(?<![A-Za-z0-9_+=-])[A-Za-z0-9_+=-]{32,})',
);
my $RE_SECRET = join('|', map { $ALT{$_} } @SECRETS);
$RE_SECRET = qr/$RE_SECRET/;
my $RE_REST = join('|', map { $ALT{$_} } @REST);
$RE_REST = qr/$RE_REST/;

my %NOT_DOMAIN = map { $_ => 1 } qw(service socket target timer mount path slice scope device swap yml yaml
    json toml conf txt git log example invalid test localhost);

my ($CUR, $ORIG, $DIGEST_FIELD) = ('', '', 0);

sub is_default_user { my $u = lc $_[0]; return $PLATFORM_DEFAULT{$u} || $u =~ /^user-\d+$/; }

# Free text (the version output, every JSON value) is read across line breaks;
# every other file is a table, read line by line.
sub free_text { my ($n) = @_; return ($n eq 'binaries-version.txt' || $n =~ /\.json\z/) ? 1 : 0; }

# Replaces every mnemonic in a text with a placeholder, before any other rule
# looks at the text (so `seed=<12 words>` goes whole, not word one only).
sub seed_pass {
    my ($name, $text) = @_;
    my $mk = sub { my ($m) = @_; return rep('seed-words', $m, $m, sub { "REDACTED-WORDS-$_[0]" }); };
    if (free_text($name)) { $text =~ s/($RE_SEED_GEN)/$mk->($1)/ge; }
    else {
        $text =~ s/($RE_SEED_WS)/$mk->($1)/ge;
        $text =~ s/($RE_SEED_LINE)/$mk->($1)/ge;
    }
    return $text;
}

# A mnemonic split across several JSON values (a build_tags array): the values
# of the whole file, joined with a space, are searched too, and every value
# that holds a part of a run is replaced.
# Only fields that hold free text (versions, build tags, version labels) are
# joined: an enum, a port, a name or an address is never part of a phrase.
sub free_key {
    my ($k) = @_;
    return (defined $k && $k =~ /^(?:version|commit|app_pre_release|build_tags|go_version|latest_version|[A-Za-z0-9_.-]+\.(?:version|revision))\z/) ? 1 : 0;
}
sub tree_nodes {
    my ($v, $acc, $key) = @_;
    return if ref($v) ne 'ARRAY';
    my ($t, $x) = @$v;
    if ($t eq 's') { push @$acc, $v if free_key($key); }
    elsif ($t eq 'o') { tree_nodes($x->{$_}, $acc, $_) for sort keys %$x; }
    elsif ($t eq 'a') { tree_nodes($_, $acc, $key) for @$x; }
    return;
}

sub joined_seed_pass {
    my ($v) = @_;
    my @nodes;
    tree_nodes($v, \@nodes);
    return if @nodes < 2;
    my ($joined, @spans) = ('');
    for my $n (@nodes) {
        my $s = norm_ws($n->[1]);
        push @spans, [length($joined), length($joined) + length($s)];
        $joined .= $s . ' ';
    }
    my %hit;
    while ($joined =~ /$RE_SEED_GEN/g) {
        my ($s, $e) = ($-[0], $+[0]);
        for my $i (0 .. $#nodes) { $hit{$i} = 1 if $spans[$i][0] < $e && $spans[$i][1] > $s; }
    }
    for my $i (sort { $a <=> $b } keys %hit) {
        my $raw = $nodes[$i][1];
        $nodes[$i][1] = rep('seed-words', $raw, $raw, sub { "REDACTED-WORDS-$_[0]" }) if $raw ne '';
    }
    return;
}

# Does a value that sits in a secret-named place have the shape of a key or seed?
# $mode: 'ws' (the default, for text that is dropped or never kept: a phrase is
# words joined by white space or commas only), 'gen' (a value that is kept: the
# wider 1 to 3 character separator rule too) or 'none' (leave mnemonics out).
sub looks_secret {
    my ($v, $mode) = @_;
    $mode = 'ws' if !defined $mode;
    $v = norm_ws($v);
    return 1 if $v =~ /nsec1[02-9ac-hj-np-z]{58}/i;
    return 1 if $v =~ /[xtyzuvYZUV]prv[1-9A-HJ-NP-Za-km-z]{100,112}/;
    return 1 if $v =~ /(?<![A-Za-z0-9])[5KLc9][1-9A-HJ-NP-Za-km-z]{50,51}(?![A-Za-z0-9])/;
    return 1 if $v =~ /0201036c6e64[0-9A-Fa-f]{88,}/i || $v =~ /AgEDbG5k[A-Za-z0-9+\/_-]{32,}/;
    return 1 if $v =~ /-----BEGIN [A-Z ]*PRIVATE KEY-----/;
    return 1 if $mode eq 'gen' && $v =~ $RE_SEED_GEN;
    return 1 if $mode eq 'ws' && $v =~ $RE_SEED_WS;
    return 0;
}

my %H;
$H{pem} = sub {
    my ($m) = @_;
    return $m if $m =~ /^-----BEGIN REDACTED PRIVATE KEY \d+-----/;
    return rep('pem-private-key', $m, $m, sub {
        "-----BEGIN REDACTED PRIVATE KEY $_[0]-----\nREDACTED\n-----END REDACTED PRIVATE KEY $_[0]-----" });
};
sub secret_value {
    my ($v) = @_;
    return $v if $v eq '' || $v =~ /^(?:0|1|on|off|true|false|auto|yes|no)\z/i;
    $extrasecret++ if looks_secret($v, 'gen');
    # A value already in placeholder form stays only when it is exactly one
    # (REDACTED-CLASS-number) and nothing in it looks like a secret.
    return $v if $v =~ /^REDACTED-[A-Z0-9]{2,12}-[0-9]{1,6}\z/ && !looks_secret($v, 'gen');
    return rep('secret-value', $v, $v, sub { "REDACTED-SECRET-$_[0]" });
}
$H{secretnest} = sub {
    my ($m, $g) = @_;
    return $g->{snpre} . '"' . secret_value($g->{snv}) . '"';
};
$H{secretval} = sub {
    my ($m, $g) = @_;
    if (defined $g->{svq}) { return $m if $g->{svq} eq ''; return $g->{svpre} . '"' . secret_value($g->{svq}) . '"'; }
    if (defined $g->{svs}) { return $m if $g->{svs} eq ''; return $g->{svpre} . "'" . secret_value($g->{svs}) . "'"; }
    return $g->{svpre} . secret_value($g->{svu});
};
$H{secretflag} = sub {
    my ($m, $g) = @_;
    return $g->{sfpre} . secret_value($g->{sfv});
};
$H{userinfo} = sub {
    my ($m, $g) = @_;
    return $m if $g->{uiu} =~ /^REDACTED-USERINFO-\d+$/;
    return $g->{uipre} . rep('url-userinfo', $g->{uiu}, $g->{uiu}, sub { "REDACTED-USERINFO-$_[0]" }) . '@';
};
$H{bearer} = sub {
    my ($m, $g) = @_;
    my $v = $g->{brv};
    return $m if $v =~ /^REDACTED-BEARER-\d+$/;
    return $g->{brpre} . rep('bearer-token', $v, $v, sub { "REDACTED-BEARER-$_[0]" });
};
$H{xprv} = sub {
    my ($m) = @_;
    return rep('xprv', $m, $m, sub { "REDACTED-XPRV-$_[0]" });
};
$H{xpub} = sub {
    my ($m) = @_;
    return rep('xpub', $m, $m, sub { "REDACTED-XPUB-$_[0]" });
};
$H{nsec} = sub {
    my ($m) = @_;
    return rep('nsec', $m, lc $m, sub { "REDACTED-NSEC-$_[0]" });
};
$H{npub} = sub {
    my ($m) = @_;
    return rep('npub', $m, lc $m, sub { "REDACTED-NPUB-$_[0]" });
};
$H{nentity} = sub {
    my ($m) = @_;
    return rep('nostr-entity', $m, lc $m, sub { "REDACTED-NENTITY-$_[0]" });
};
$H{wif} = sub {
    my ($m) = @_;
    return rep('wif-key', $m, $m, sub { "REDACTED-WIF-$_[0]" });
};
$H{macaroon} = sub {
    my ($m) = @_;
    return rep('macaroon', $m, $m, sub { "REDACTED-MACAROON-$_[0]" });
};
$H{lninvoice} = sub {
    my ($m) = @_;
    return rep('ln-invoice', $m, lc $m, sub { "REDACTED-INVOICE-$_[0]" });
};
$H{btcaddr} = sub {
    my ($m) = @_;
    if ($m !~ /^(?:bcrt|bc|tb)1/i) {
        return $m if $m !~ /[A-Z]/ || $m !~ /[a-z]/ || $m !~ /[0-9]/;
    }
    return rep('btc-address', $m, lc $m, sub { "REDACTED-ADDRESS-$_[0]" });
};
$H{onion} = sub {
    my ($m) = @_;
    return rep('onion', $m, lc $m, sub { "REDACTED-ONION-$_[0].onion" });
};
# A digest is kept only in a typed digest field of the Docker files (Id, ImageID,
# RepoDigests), where the whole string is the digest or ends with one. Docker
# never puts a digest in RepoTags, so one there is a scalar and is replaced.
# Anywhere else it could be a private-key scalar and is replaced.
$H{keptdigest} = sub {
    my ($m, $g, $pos) = @_;
    if ($DIGEST_FIELD && ($pos == 0 || substr($ORIG, $pos - 1, 1) eq '@') && $pos + length($m) == length($ORIG)) {
        return $m;
    }
    my $hex = substr($m, 7);
    return 'sha256:' . rep('hex64', $hex, lc $hex, sub { "REDACTED-HEX64-$_[0]" });
};
$H{nodepubkey} = sub {
    my ($m) = @_;
    return rep('node-pubkey', $m, lc $m, sub { "REDACTED-NODEKEY-$_[0]" });
};
$H{longhex} = sub {
    my ($m) = @_;
    return rep('long-hex', $m, lc $m, sub { "REDACTED-HEX-$_[0]" });
};
$H{hex64} = sub {
    my ($m) = @_;
    return rep('hex64', $m, lc $m, sub { "REDACTED-HEX64-$_[0]" });
};
$H{email} = sub {
    my ($m) = @_;
    return $m if $m =~ /^user-\d+\@example\.invalid$/;
    my ($last) = lc($m) =~ /\.([a-z]+)\z/;
    return $m if defined $last && $NOT_DOMAIN{$last};
    return rep('email', $m, lc $m, sub { "user-$_[0]\@example.invalid" });
};
$H{mac} = sub {
    my ($m) = @_;
    return rep('mac', $m, lc $m, sub { "REDACTED-MAC-$_[0]" });
};
$H{ipv6} = sub { return map_ipv6($_[0]); };
sub in_dpkg_version_column {
    my ($pos) = @_;
    return 0 if $CUR ne 'dpkg-query.txt';
    my $ls = rindex($ORIG, "\n", $pos - 1) + 1;
    my $before = substr($ORIG, $ls, $pos - $ls);
    my $tabs = () = $before =~ /\t/g;
    return $tabs == 1;
}
$H{ipv4} = sub {
    my ($m, $g, $pos) = @_;
    return $m if in_dpkg_version_column($pos);
    return map_ipv4($m);
};
$H{homeuser} = sub {
    my ($m, $g) = @_;
    return $m if is_default_user($g->{huu});
    return $g->{hupre} . rep('home-user', $g->{huu}, $g->{huu}, sub { "user-$_[0]" });
};
$H{term} = sub {
    my ($m) = @_;
    return rep('term', $m, lc $m, sub { "redacted-host-$_[0]" });
};
$H{domain} = sub {
    my ($m, $g, $pos) = @_;
    my $lc = lc $m;
    my ($last) = $lc =~ /\.([a-z]+)\z/;
    return $m if $NOT_DOMAIN{$last} || $lc =~ /^redacted-onion-\d+\.onion\z/;
    return $m if in_dpkg_version_column($pos);
    if ($kept{$lc}) { $keptseen{$lc} = 1; return $m; }
    return rep('domain', $m, $lc, sub { "host-$_[0].example" });
};
$H{token} = sub {
    my ($m) = @_;
    return $m if $m !~ /[A-Z]/ || $m !~ /[a-z]/ || $m !~ /[0-9]/;
    return rep('token', $m, $m, sub { "REDACTED-TOKEN-$_[0]" });
};

sub handle {
    my %g = %+;
    my $m = $&;
    my $pos = $-[0];
    for my $c (@ORDER) {
        next unless defined $g{$c};
        return $H{$c}->($m, \%g, $pos);
    }
    return $m;
}

sub redact {
    my ($name, $text) = @_;
    $CUR = $name;
    $text = norm_ws($text);
    $text = seed_pass($name, $text);
    $ORIG = $text;
    $text =~ s/$RE_SECRET/handle()/ge;
    $ORIG = $text;
    $text =~ s/$RE_REST/handle()/ge;
    return $text;
}

# JSON: only the values are redacted, never the keys.
# $key is the name of the field the value sits in (an array's elements share
# their array's field name).
sub redact_tree {
    my ($name, $v, $key) = @_;
    my ($t, $x) = @$v;
    if ($t eq 's') {
        # `repo:tag@sha256:X` in docker-ps Image is pinned like RepoDigests is.
        $DIGEST_FIELD = (($name =~ /^docker-(?:ps|images)\.json\z/ && defined $key && $key =~ /^(?:Id|ImageID|RepoDigests)\z/)
            || ($name eq 'docker-ps.json' && defined $key && $key eq 'Image')) ? 1 : 0;
        my $r = redact($name, $x);
        $DIGEST_FIELD = 0;
        return ['s', $r];
    }
    if ($t eq 'o') { return ['o', { map { $_ => redact_tree($name, $x->{$_}, $_) } sort keys %$x }]; }
    if ($t eq 'a') { return ['a', [map { redact_tree($name, $_, $key) } @$x]]; }
    return $v;
}

# ---------- read the input ----------
sub walk {
    my ($rel, $acc) = @_;
    my $dir = length $rel ? "$RAW/$rel" : $RAW;
    opendir(my $dh, $dir) or fail("Cannot read $dir. Nothing was written.", 1);
    my @e = sort grep { $_ ne '.' && $_ ne '..' } readdir $dh;
    closedir $dh;
    for my $e (@e) {
        my $r = length $rel ? "$rel/$e" : $e;
        my $p = "$RAW/$r";
        if (-l $p) { fail("Refused to read $r: it is a symlink. Nothing was written.", 2); }
        elsif (-d $p) { walk($r, $acc); }
        elsif (-f $p) { push @$acc, $r; }
        else { fail("Refused to read $r: not a regular file. Nothing was written.", 2); }
    }
}

my @files;
walk('', \@files);
@files = sort grep { $_ ne 'record-log.txt' } @files;

my @drafts;
my $platform = '';
if (open(my $rh, '<:raw', "$RAW/record-log.txt")) {
    my $first = <$rh>;
    # Only in --redact-dir: in record mode the log's first line is always ours.
    $REREDACT = 1 if $MODE eq 'redact-dir' && defined $first && $first =~ /^record-setup\.sh format /;
    close $rh;
}
if ($MODE eq 'record' && -f "$RAW/record-log.txt") {
    open(my $lh, '<:raw', "$RAW/record-log.txt") or fail('Cannot read the log draft.', 1);
    while (my $l = <$lh>) {
        chomp $l;
        if ($l =~ /^platform-hint (.*)$/) { $platform = $1; }
        elsif ($l !~ /^record-setup\.sh format /) { push @drafts, $l; }
    }
    close $lh;
}

# Output path: a service or app folder that is not public software gets a number,
# and so does a file name that the format does not fix (an app's own .json file).
my %FIXED_FILES = map { $_ => 1 } qw(umbrel-app.yml getnetworkinfo.json getinfo.json getversion.json
    nip11.json nut06.json server-version.json);
sub out_name {
    my ($f) = @_;
    # A folder on its own (a refused folder in the log).
    if ($f =~ m{^(replies|apps)/([^/]+)\z}s) {
        my ($kind, $id) = ($1, $2);
        return $f if $PUBLIC_SERVICES{$id};
        return "$kind/" . rep('path-name', $id, "$kind/$id", sub { ($kind eq 'replies' ? 'service' : 'app') . "-$_[0]" });
    }
    if ($f =~ m{^(replies|apps)/([^/]+)/(.*)\z}s) {
        my ($kind, $id, $rest) = ($1, $2, $3);
        my $raw_id = $id;
        if (!$PUBLIC_SERVICES{$id}) {
            my $word = $kind eq 'replies' ? 'service' : 'app';
            $id = rep('path-name', $id, "$kind/$id", sub { "$word-$_[0]" });
        }
        if (!$FIXED_FILES{$rest}) {
            my ($stem, $ext) = $rest =~ m{^([^/]+)(\.json)\z} ? ($1, $2) : ($rest, '');
            if ($ext ne '' && $stem eq $raw_id) { $rest = "$id$ext"; }
            elsif ($ext ne '' && ($PUBLIC_SERVICES{$stem} || $PUBLIC_NAMES{lc $stem})) { }
            else { $rest = rep('path-file', $stem, "$kind/$raw_id/$rest", sub { "file-$_[0]" }) . $ext; }
        }
        return "$kind/$id/$rest";
    }
    return $f;
}

# Read every file first: the corpus of input values must be complete before any
# replacement is chosen.
my %intext;
for my $f (@files) {
    open(my $fh, '<:raw', "$RAW/$f") or fail("Cannot read $f. Nothing was written.", 1);
    my $text = do { local $/; <$fh> };
    close $fh;
    $text = '' if !defined $text;
    $intext{$f} = $text;
    my @pieces = (norm_ws($text));
    if ($f =~ /\.json\z/) {
        my $jv = json_parse($text);
        push @pieces, map { norm_ws($_) } tree_strings($jv) if defined $jv;
    }
    $CORPUS .= lc(join("\n", @pieces)) . "\n";
    note_addresses($_) for @pieces;
}
$CORPUS .= lc(norm_ws(join("\n", @drafts))) . "\n";
note_addresses(norm_ws(join("\n", @drafts)));

# Everything found so far that counts as a secret (replaced, or seen in dropped text).
sub secret_total {
    my $n = $extrasecret;
    $n += $occ{$_} for grep { $SECRET_CLASS{$_} } keys %occ;
    return $n;
}

# Does the whole raw text of a file hold a secret shape, wherever the extractor
# put it (or threw it away)? Free text is read across lines; a table line by
# line; a torrc's comments are prose, so they are only searched for key shapes,
# not for 12 plain words. A unit's description is checked for 12 words as well
# (on its own line). Everything dropped is read by the white-space-and-commas
# rule only: paths, URLs and dashed names (a lncli features map, compose labels,
# bind mounts) are not phrases.
sub raw_looks_secret {
    my ($f, $text) = @_;
    if ($f =~ /\.json\z/) {
        my $v = json_parse($text);
        if (defined $v) {
            my @strings;
            tree_strings_and_keys($v, \@strings);
            return 1 if grep { looks_secret($_) } @strings;
            my @free;
            tree_nodes($v, \@free);
            return looks_secret(join(' ', map { $_->[1] } @free)) ? 1 : 0;
        }
        return looks_secret($text) ? 1 : 0;
    }
    if ($f eq 'systemctl-list-units.txt') {
        return 1 if looks_secret($text, 'none');
        for my $line (split /\n/, $text) {
            my @w = split ' ', $line, 5;
            return 1 if @w == 5 && looks_secret($w[4]);
        }
        return 0;
    }
    if ($f eq 'torrc') {
        return 1 if looks_secret($text, 'none');
        return looks_secret(join("\n", grep { !/^[ \t]*#/ } split /\n/, $text)) ? 1 : 0;
    }
    return looks_secret($text) ? 1 : 0;
}

# The kept value columns of a table file, joined: 12 or more different words in a
# row (an on/off list is not one) are a phrase split over lines. Flag only.
sub columns_look_seedy {
    my ($f, $text) = @_;
    my @vals;
    for my $line (split /\n/, $text) {
        $line =~ s/\r\z//;
        if ($f =~ m{^apps/[^/]+/umbrel-app\.yml\z}) {
            if ($line =~ /^(?:manifestVersion|id|name|version|category|port):[ ]+["']?(.*?)["']?\z/) { push @vals, $1; }
            elsif ($line =~ /^  - ([a-z0-9-]+)\z/) { push @vals, $1; }
        }
        elsif ($f =~ /^raspiblitz-(?:conf|info|version)\.txt\z/) { push @vals, $1 if $line =~ /^[A-Za-z][A-Za-z0-9_]*="?([^"]*)"?\z/; }
        elsif ($f eq 'dpkg-query.txt') { my @c = split /\t/, $line; push @vals, $c[1] if @c == 3; }
    }
    return 0 if @vals < 12;
    my $joined = join(' ', @vals);
    while ($joined =~ /($RE_SEED_GEN)/g) {
        my %w = map { lc($_) => 1 } ($1 =~ /[A-Za-z]{3,8}/g);
        return 1 if keys %w >= 8;
    }
    return 0;
}

sub tree_strings_and_keys {
    my ($v, $acc) = @_;
    return if ref($v) ne 'ARRAY';
    my ($t, $x) = @$v;
    if ($t eq 's') { push @$acc, $x; }
    elsif ($t eq 'o') { for my $k (sort keys %$x) { push @$acc, $k; tree_strings_and_keys($x->{$k}, $acc); } }
    elsif ($t eq 'a') { tree_strings_and_keys($_, $acc) for @$x; }
    return;
}

my %outdata;
my @dropnotes;
for my $f (@files) {
    my $text = $intext{$f};
    $DROPPED = 0;
    my $before = secret_total();
    my $kept = extract($f, $text);
    my $shown = out_name($f);
    my $final;
    if (!defined $kept) { push @dropnotes, "dropped $shown unparseable"; }
    else {
        push @dropnotes, "dropped $shown $DROPPED" if $DROPPED > 0;
        $final = $f =~ /\.json\z/ ? $kept : redact($f, $kept);
        $final =~ tr/\x80-\xff/?/ if $f eq 'binaries-version.txt';
    }
    # A secret shape in input that was dropped or never kept still counts. The log
    # names the file, never the value.
    if (secret_total() == $before) {
        if (raw_looks_secret($f, $text)) {
            $extrasecret++;
            push @dropnotes, "secret-shape-in-dropped-input $shown";
        }
        elsif (columns_look_seedy($f, $text)) {
            $extrasecret++;
            push @dropnotes, "seed-shaped-values-in-columns $shown";
        }
    }
    $outdata{$shown} = $final if defined $final;
}
# A refused file is named by its folder's pseudonym and the word refused-file: the
# reason may quote the file's own name (name matches *wallet*), which must not be
# registered as a value to look for.
sub refused_name {
    my ($p) = @_;
    if ($p =~ m{^(replies|apps)/([^/]+)/}s) {
        my ($kind, $id) = ($1, $2);
        return out_name("$kind/$id") . '/refused-file';
    }
    return out_name($p);
}
for my $l (@drafts) {
    if ($l =~ m{^refused ((?:replies|apps)/\S+)(.*)\z}s) { $l = 'refused ' . refused_name($1) . $2; }
    elsif ($l =~ m{^(collected|skipped|dropped|filtered) ((?:replies|apps)/\S+)(.*)\z}s) { $l = "$1 " . out_name($2) . $3; }
}
my @loglines = sort map { redact('record-log.txt', $_) } (@drafts, @dropnotes);

# ---------- the log ----------
my @log = ('record-setup.sh format 2', ($MODE eq 'record' ? 'mode record' : 'mode redact-dir') . ($TESTFLAG ? ' test-tools' : ''));
push @log, "platform-hint $platform" if $MODE eq 'record';
push @log, @loglines;
my $secrets = $extrasecret;
for my $c (sort keys %occ) {
    push @log, 'replaced ' . $c . ' ' . $occ{$c} . ' ' . scalar(keys %{ $map{$c} });
    $secrets += $occ{$c} if $SECRET_CLASS{$c};
}
push @log, map { "kept-domain $_" } sort keys %keptseen;
push @log, "secret-shaped-values-removed $secrets";
$outdata{'record-log.txt'} = join("\n", @log) . "\n";

# ---------- self-check, before anything is written ----------
# A value of 6 or more bytes must not appear anywhere. A shorter one must not
# appear as a whole word.
my @check = grep { length($_) > 0 && !$phset{$_} } sort keys %rawset;
# A JSON key may legitimately equal a value that was redacted elsewhere, so JSON
# files are searched by their values only.
sub tree_strings {
    my ($v) = @_;
    my ($t, $x) = @$v;
    return ($x) if $t eq 's';
    return map { tree_strings($x->{$_}) } sort keys %$x if $t eq 'o';
    return map { tree_strings($_) } @$x if $t eq 'a';
    return ();
}
my %haystack = (%outdata, "\0names" => join("\n", sort keys %outdata));
for my $f (keys %outdata) {
    next if $f !~ /\.json\z/;
    my $v = json_parse($outdata{$f});
    $haystack{$f} = join("\n", tree_strings($v)) if defined $v;
}
for my $f (sort keys %haystack) {
    for my $raw (@check) {
        my $hit = length($raw) >= 6
            ? index($haystack{$f}, $raw) >= 0
            : $haystack{$f} =~ /(?<![A-Za-z0-9])\Q$raw\E(?![A-Za-z0-9])/;
        if ($hit) {
            fail('Self-check failed: a value that was redacted in one place still appears in another. Nothing was kept.', 4);
        }
    }
}

# ---------- write ----------
sub ensure_dir {
    my ($path) = @_;
    my $cur = $OUT;
    for my $part (split m{/}, $path) {
        $cur .= "/$part";
        fail("Refused to write through a link: $cur.", 2) if -l $cur;
        next if -d $cur;
        mkdir($cur, 0700) or fail("Cannot create $cur.", 1);
    }
}
# Files are created exclusively (O_CREAT|O_EXCL), which also refuses a symlink
# at the final name; no other file mode or flag is needed.
my ($O_CREAT, $O_EXCL) = $^O eq 'linux' ? (0x40, 0x80) : (0x200, 0x800);
for my $f (sort keys %outdata) {
    if ($f =~ m{^(.*)/[^/]+$}) { ensure_dir($1); }
    sysopen(my $oh, "$OUT/$f", 1 | $O_CREAT | $O_EXCL, 0600) or fail("Cannot create $OUT/$f.", 1);
    binmode $oh;
    my $data = $outdata{$f};
    my $off = 0;
    while ($off < length $data) {
        my $n = syswrite($oh, $data, length($data) - $off, $off);
        fail("Cannot write $OUT/$f.", 1) if !defined $n;
        $off += $n;
    }
    close $oh or fail("Cannot write $OUT/$f.", 1);
}

print "Output folder: $OUT\n";
print 'Files written: ' . scalar(keys %outdata) . "\n";
for my $c (sort keys %occ) {
    print "Replaced $c: $occ{$c} times, " . scalar(keys %{ $map{$c} }) . " different values\n";
}
print "Not redacted on purpose: service names, versions, ports, image digests and the kept domains listed in record-log.txt. Read every file before you share it.\n";
if ($secrets > 0) {
    print STDERR "A secret-looking value was found and removed. Read the files before sharing them.\n";
    exit 3;
}
exit 0;
PERL

# ---------- trusted tools ----------
# The two lines marked test-injection-point are rewritten only in temporary copies
# of this script made by the tests, which use stub tools. There is no switch in
# this file or in the environment that changes them.
TRUSTED_DIRS="/usr/sbin /usr/bin /sbin /bin" # test-injection-point
TEST_MODE=0 # test-injection-point
TRUSTED_PATH="${TRUSTED_DIRS// /:}"

# tool NAME: prints the absolute path of NAME from the trusted folders only.
tool() {
    local name="$1" d
    # shellcheck disable=SC2086
    for d in $TRUSTED_DIRS; do
        if [ -f "$d/$name" ] && [ -x "$d/$name" ]; then
            printf '%s\n' "$d/$name"
            return 0
        fi
    done
    return 0
}

die() {
    printf '%s\n' "$1" >&2
    exit "${2:-1}"
}

need() {
    local p
    p=$(tool "$1")
    [ -n "$p" ] || die "$1 is missing. It is part of every Debian and Raspberry Pi OS install; this box is unusual. Stopping."
    printf '%s\n' "$p"
}

if [ "$TEST_MODE" = 1 ] && { [ "$EUID" -eq 0 ] || [ "$UID" -eq 0 ]; }; then
    die "Test mode is refused for root."
fi

PERL=$(need perl)
MKTEMP=$(need mktemp)
RM=$(need rm)
MKDIR=$(need mkdir)
CHMOD=$(need chmod)
CAT=$(need cat)
SORT=$(need sort)
GREP=$(need grep)
HEAD=$(need head)
WC=$(need wc)
FIND=$(need find)
ENV=$(need env)
TR=$(need tr)
CURL=$(tool curl)
TIMEOUT=$(tool timeout)
IDCMD=$(tool id)
HOSTNAMECMD=$(tool hostname)

# run_clean COMMAND...: runs a program in an empty environment with the trusted PATH.
run_clean() {
    "$ENV" -i PATH="$TRUSTED_PATH" LC_ALL=C "$@"
}

# ---------- helpers ----------
usage() {
    "$CAT" <<'USAGE_EOF'
Usage:
  record-setup.sh --out DIR [--root DIR] [--docker-socket PATH]
                  [--reply SERVICE/CALL=FILE]... [--redact-term WORD]...
  record-setup.sh --redact-dir IN --out DIR [--redact-term WORD]...
  record-setup.sh --check-path PATH
  record-setup.sh --check-binary PATH
  record-setup.sh --help

Records a setup (record mode) or redacts a folder of recordings (redact mode).
Only named fields are kept; everything else is dropped. SERVICE is a lower-case
name like bitcoin-core. CALL is one of: getnetworkinfo getinfo getversion nip11
nut06 server-version. A reply file must be the command's JSON output, unchanged.
A WORD is 4 to 63 letters, digits, dots, dashes or underscores.
--check-path says whether the script would read a path (ok, or refused: why).
--check-binary says whether the script would run a program for its version.
Run it as: env -i PATH=/usr/bin:/bin bash record-setup.sh ...
Exit codes: 0 done, 1 usage or environment problem, 2 refused a secret-looking
or unsafe path, 3 done but a secret-shaped value was removed, 4 self-check failed.
Read every file it writes before you share it.
USAGE_EOF
}

die_usage() {
    printf '%s\n\n' "$1" >&2
    usage >&2
    exit 1
}

SLUG_RE='^[a-z0-9]+(-[a-z0-9]+)*$'
TERM_RE='^[A-Za-z0-9._-]{4,63}$'
JSON_NAME_RE='^[a-z0-9_-]{1,40}\.json$'
MAX_BYTES=1048576
DOCKER_MAX_BYTES=16777216

REFUSE_REASON=""

# refuse_name NAME: sets REFUSE_REASON and returns 0 when a name looks secret.
refuse_name() {
    local lower comp rest
    lower=$(printf '%s' "$1" | "$TR" "[:upper:]" "[:lower:]")
    rest="$lower"
    while [ -n "$rest" ]; do
        comp="${rest%%/*}"
        if [ "$comp" = "$rest" ]; then
            rest=""
        else
            rest="${rest#*/}"
        fi
        [ -n "$comp" ] || continue
        case "$comp" in
            *seed*) REFUSE_REASON="name matches *seed*" ;;
            *mnemonic*) REFUSE_REASON="name matches *mnemonic*" ;;
            *macaroon*) REFUSE_REASON="name matches *macaroon*" ;;
            nsec*) REFUSE_REASON="name matches nsec*" ;;
            *nsec*) REFUSE_REASON="name matches *nsec*" ;;
            *wallet*) REFUSE_REASON="name matches *wallet*" ;;
            .env) REFUSE_REASON="name matches .env" ;;
            .env.*) REFUSE_REASON="name matches .env.*" ;;
            *.env) REFUSE_REASON="name matches *.env" ;;
            exports.sh) REFUSE_REASON="name matches exports.sh" ;;
            *secret*) REFUSE_REASON="name matches *secret*" ;;
            *private*) REFUSE_REASON="name matches *private*" ;;
            *key*) REFUSE_REASON="name matches *key*" ;;
            *cookie*) REFUSE_REASON="name matches *cookie*" ;;
            *password*) REFUSE_REASON="name matches *password*" ;;
            *passwd*) REFUSE_REASON="name matches *passwd*" ;;
            *rpcauth*) REFUSE_REASON="name matches *rpcauth*" ;;
            *credential*) REFUSE_REASON="name matches *credential*" ;;
            *token*) REFUSE_REASON="name matches *token*" ;;
            *.pem) REFUSE_REASON="name matches *.pem" ;;
            *.p12) REFUSE_REASON="name matches *.p12" ;;
            *.pfx) REFUSE_REASON="name matches *.pfx" ;;
            *.kdbx) REFUSE_REASON="name matches *.kdbx" ;;
            *.gpg) REFUSE_REASON="name matches *.gpg" ;;
            *.age) REFUSE_REASON="name matches *.age" ;;
            *.db) REFUSE_REASON="name matches *.db" ;;
            *.sqlite*) REFUSE_REASON="name matches *.sqlite*" ;;
            channel.backup) REFUSE_REASON="name matches channel.backup" ;;
            *.scb) REFUSE_REASON="name matches *.scb" ;;
            *backup*) REFUSE_REASON="name matches *backup*" ;;
            *.dat) REFUSE_REASON="name matches *.dat" ;;
            id_rsa*) REFUSE_REASON="name matches id_rsa*" ;;
            id_ed25519*) REFUSE_REASON="name matches id_ed25519*" ;;
            shadow) REFUSE_REASON="name matches shadow" ;;
            hidden_service*) REFUSE_REASON="name matches hidden_service*" ;;
            raspiblitz.setup) REFUSE_REASON="name matches raspiblitz.setup" ;;
            *) ;;
        esac
        if [ -n "$REFUSE_REASON" ]; then
            return 0
        fi
    done
    return 1
}

# Names that are safe to show in a message (control characters turned to ?).
printable() {
    printf '%s' "$1" | "$TR" -c '[:print:]' '?'
}

die_refused() {
    die "Refused to read $(printable "$1"): $2. Nothing was written." 2
}

PWD_P=$(pwd -P)

# trusted_dir DIR: succeeds when DIR belongs to root or to this user and nobody
# else can write to it, or when it is a sticky root folder like /tmp.
trusted_dir() {
    if [ -n "$("$FIND" "$1" -maxdepth 0 \( -user 0 -o -user "$EUID" \) ! -perm -g+w ! -perm -o+w 2>/dev/null)" ]; then
        return 0
    fi
    [ -n "$("$FIND" "$1" -maxdepth 0 -perm -1000 -user 0 2>/dev/null)" ]
}

# check_path KIND PATH [skipnames] [limit]
# KIND is file, dir, out or socket. Returns 0 when the path is safe; otherwise
# sets REFUSE_REASON and returns 2. The path may not pass through a symlink, and
# every folder above it must be trusted (see trusted_dir).
check_path() {
    local kind="$1" p="$2" skipnames="${3:-}" limit="${4:-$MAX_BYTES}"
    local abs dirpart base canon parent size cur rest comp
    REFUSE_REASON=""
    case "$p" in
        /*) abs="$p" ;;
        ./*) abs="$PWD_P/${p#./}" ;;
        *) abs="$PWD_P/$p" ;;
    esac
    while [ "${#abs}" -gt 1 ] && [ "${abs%/}" != "$abs" ]; do
        abs="${abs%/}"
    done
    if [ "$abs" = "/" ]; then
        canon="/"
        parent="/"
        base=""
    else
        dirpart="${abs%/*}"
        [ -n "$dirpart" ] || dirpart="/"
        base="${abs##*/}"
        parent=$(cd -P -- "$dirpart" 2>/dev/null && pwd -P) || {
            REFUSE_REASON="parent folder missing"
            return 2
        }
        if [ "$parent" = "/" ]; then
            canon="/$base"
        else
            canon="$parent/$base"
        fi
    fi
    if [ "$canon" != "$abs" ]; then
        # Only the system links /tmp, /var and /etc (macOS) and /var/run (Linux) are accepted.
        case "$abs" in
            /tmp/* | /var/* | /etc/*)
                if [ "$canon" != "/private$abs" ] && [ "$canon" != "/run/${abs#/var/run/}" ]; then
                    REFUSE_REASON="symlink in path"
                    return 2
                fi
                ;;
            *)
                REFUSE_REASON="symlink in path"
                return 2
                ;;
        esac
    fi
    if [ -L "$canon" ]; then
        REFUSE_REASON="symlink in path"
        return 2
    fi
    case "$kind" in
        file) [ -f "$canon" ] || { REFUSE_REASON="wrong type"; return 2; } ;;
        dir) [ -d "$canon" ] || { REFUSE_REASON="wrong type"; return 2; } ;;
        socket) [ -S "$canon" ] || { REFUSE_REASON="wrong type"; return 2; } ;;
        out)
            if [ -e "$canon" ] && [ ! -d "$canon" ]; then
                REFUSE_REASON="wrong type"
                return 2
            fi
            ;;
        *) ;;
    esac
    # Every folder above the path, from / down.
    if ! trusted_dir /; then
        REFUSE_REASON="untrusted parent /"
        return 2
    fi
    rest="${canon#/}"
    case "$rest" in
        */*) rest="${rest%/*}" ;;
        *) rest="" ;;
    esac
    cur=""
    while [ -n "$rest" ]; do
        comp="${rest%%/*}"
        if [ "$comp" = "$rest" ]; then
            rest=""
        else
            rest="${rest#*/}"
        fi
        cur="$cur/$comp"
        if ! trusted_dir "$cur"; then
            REFUSE_REASON="untrusted parent $cur"
            return 2
        fi
    done
    if [ "$kind" = "file" ]; then
        size=$("$WC" -c <"$canon" | "$TR" -d ' ')
        if [ "$size" -gt "$limit" ]; then
            REFUSE_REASON="it is larger than the size limit"
            return 2
        fi
        if [ -z "$skipnames" ]; then
            if refuse_name "$base"; then
                return 2
            fi
            if [ "$parent" != "/" ] && refuse_name "${parent##*/}"; then
                return 2
            fi
        fi
    fi
    if [ "$kind" = "dir" ]; then
        if [ -n "$("$FIND" "$canon" -type l 2>/dev/null | "$HEAD" -n 1)" ]; then
            REFUSE_REASON="contains a symlink"
            return 2
        fi
    fi
    return 0
}

# binary_ok PATH: a program the recorder may run. The program and every folder
# above it must be owned by root and not writable by anyone else, with no symlink.
binary_ok() {
    local p="$1" cur="" rest comp found
    check_path file "$p" skipnames || return 2
    if [ -z "$("$FIND" / -maxdepth 0 -user 0 ! -perm -g+w ! -perm -o+w 2>/dev/null)" ]; then
        REFUSE_REASON="untrusted parent /"
        return 2
    fi
    rest="${p#/}"
    case "$rest" in
        */*) rest="${rest%/*}" ;;
        *) rest="" ;;
    esac
    while [ -n "$rest" ]; do
        comp="${rest%%/*}"
        if [ "$comp" = "$rest" ]; then
            rest=""
        else
            rest="${rest#*/}"
        fi
        cur="$cur/$comp"
        if [ -z "$("$FIND" "$cur" -maxdepth 0 -user 0 ! -perm -g+w ! -perm -o+w 2>/dev/null)" ]; then
            REFUSE_REASON="untrusted parent $cur"
            return 2
        fi
    done
    found=$("$FIND" "$p" -maxdepth 0 -type f -user 0 ! -perm -g+w ! -perm -o+w 2>/dev/null || true)
    if [ "$found" != "$p" ]; then
        REFUSE_REASON="not owned by root or writable by others"
        return 2
    fi
    return 0
}

is_platform_default() {
    case "$1" in
        admin | bitcoin | lnd | btcpay | electrs | fulcrum | rtl | thunderhub | mempool | tor | debian-tor | lndg | joinmarket | umbrel | start9 | mynode | pi | ubuntu | debian | root | raspiblitz | raspberrypi | localhost | nixos | operator | user) return 0 ;;
        *) return 1 ;;
    esac
}

# ---------- arguments ----------
OUT=""
ROOT="/"
SOCK="/var/run/docker.sock"
REDACT_DIR=""
HAVE_REDACT_DIR=0
REPLIES=()
REPLY_KEYS=" "
TERMS_ARG=()

need_value() {
    [ "$1" -ge 2 ] || die_usage "Missing value for $2."
}

while [ $# -gt 0 ]; do
    case "$1" in
        --help)
            usage
            exit 0
            ;;
        --check-path)
            need_value "$#" "$1"
            if [ -d "$2" ]; then
                kind=dir
            else
                kind="file"
            fi
            if check_path "$kind" "$2"; then
                printf 'ok\n'
                exit 0
            fi
            printf 'refused: %s\n' "$REFUSE_REASON"
            exit 2
            ;;
        --check-binary)
            need_value "$#" "$1"
            if binary_ok "$2"; then
                printf 'ok\n'
                exit 0
            fi
            printf 'refused: %s\n' "$REFUSE_REASON"
            exit 2
            ;;
        --out)
            need_value "$#" "$1"
            OUT="$2"
            shift 2
            ;;
        --root)
            need_value "$#" "$1"
            ROOT="$2"
            shift 2
            ;;
        --docker-socket)
            need_value "$#" "$1"
            SOCK="$2"
            shift 2
            ;;
        --redact-dir)
            need_value "$#" "$1"
            REDACT_DIR="$2"
            HAVE_REDACT_DIR=1
            shift 2
            ;;
        --redact-term)
            need_value "$#" "$1"
            if ! [[ $2 =~ $TERM_RE ]]; then
                die_usage "A --redact-term must be 4 to 63 letters, digits, dots, dashes or underscores."
            fi
            TERMS_ARG+=("$2")
            shift 2
            ;;
        --reply)
            need_value "$#" "$1"
            spec="$2"
            if [[ $spec != *=* || $spec != */* ]]; then
                die_usage "A --reply must look like SERVICE/CALL=FILE."
            fi
            left="${spec%%=*}"
            rfile="${spec#*=}"
            svc="${left%%/*}"
            call="${left#*/}"
            if ! [[ $svc =~ $SLUG_RE ]] || [ "${#svc}" -gt 40 ]; then
                die_usage "The service name in --reply must be lower-case words joined by dashes, up to 40 characters."
            fi
            case "$call" in
                getnetworkinfo | getinfo | getversion | nip11 | nut06 | server-version) ;;
                *) die_usage "The call in --reply must be one of: getnetworkinfo getinfo getversion nip11 nut06 server-version." ;;
            esac
            case "$REPLY_KEYS" in
                *" $svc/$call "*) die_usage "The same --reply SERVICE/CALL was given twice." ;;
                *) ;;
            esac
            REPLY_KEYS="$REPLY_KEYS$svc/$call "
            REPLIES+=("$svc/$call=$rfile")
            shift 2
            ;;
        *)
            die_usage "Unknown option: $(printable "$1")"
            ;;
    esac
done

[ -n "$OUT" ] || die_usage "--out is required."

if [ "$HAVE_REDACT_DIR" = 1 ]; then
    MODE="redact-dir"
    if [ "${#REPLIES[@]}" -gt 0 ] || [ "$ROOT" != "/" ] || [ "$SOCK" != "/var/run/docker.sock" ]; then
        die_usage "--root, --docker-socket and --reply only work in record mode."
    fi
else
    MODE="record"
    if [ "$EUID" -eq 0 ] || [ "$UID" -eq 0 ]; then
        die "Don't run this as root. Run it as your normal login user (on RaspiBlitz that's admin). If that user can't read the Docker socket, the Docker part is skipped and logged."
    fi
fi

if [ -e "$OUT" ] || [ -L "$OUT" ]; then
    if [ ! -d "$OUT" ]; then
        die "The output folder must be new or empty."
    fi
    if [ -n "$("$FIND" "$OUT" -mindepth 1 -maxdepth 1 | "$HEAD" -n 1)" ]; then
        die "The output folder must be new or empty."
    fi
fi

if [ "$MODE" = "redact-dir" ]; then
    [ -d "$REDACT_DIR" ] || die "The --redact-dir folder must be an existing folder."
else
    [ -d "$ROOT" ] || die "The --root folder must be an existing folder."
fi

if [ "$TEST_MODE" = 1 ]; then
    printf '%s\n' "TEST MODE: tools from a test folder; this is not a valid recording" >&2
fi

ROOT_IS_SLASH=0
if [ "$ROOT" = "/" ]; then
    ROOT_IS_SLASH=1
    ROOT=""
else
    ROOT="${ROOT%/}"
fi

# ---------- path refusals (all before any folder is made) ----------
# Succeeds when $1 is a path the recording format allows (not manifest.toml).
recording_path_ok() {
    local p="$1" id file
    case "$p" in
        systemctl-list-units.txt | dpkg-query.txt | ss-tlnp.txt | ss-ulnp.txt | torrc | binaries-version.txt | raspiblitz-version.txt | raspiblitz-conf.txt | raspiblitz-info.txt | docker-version.json | docker-ps.json | docker-images.json) return 0 ;;
        apps/*/umbrel-app.yml)
            id="${p#apps/}"
            id="${id%%/*}"
            [[ $id =~ $SLUG_RE ]] && [ "${#id}" -le 40 ] && [ "$p" = "apps/$id/umbrel-app.yml" ]
            return
            ;;
        apps/*/*.json)
            id="${p#apps/}"
            id="${id%%/*}"
            file="${p##*/}"
            [[ $id =~ $SLUG_RE ]] && [ "${#id}" -le 40 ] && [ "$p" = "apps/$id/$file" ] && [[ $file =~ $JSON_NAME_RE ]]
            return
            ;;
        replies/*/*.json)
            id="${p#replies/}"
            id="${id%%/*}"
            file="${p##*/}"
            if ! { [[ $id =~ $SLUG_RE ]] && [ "${#id}" -le 40 ] && [ "$p" = "replies/$id/$file" ]; }; then
                return 1
            fi
            case "$file" in
                getnetworkinfo.json | getinfo.json | getversion.json | nip11.json | nut06.json | server-version.json) return 0 ;;
                *) return 1 ;;
            esac
            ;;
        *) return 1 ;;
    esac
}

check_path out "$OUT" || die_refused "$OUT" "$REFUSE_REASON"
if [ -d "$OUT" ]; then
    if [ ! -O "$OUT" ] || [ -z "$("$FIND" "$OUT" -maxdepth 0 -perm 700 2>/dev/null)" ]; then
        die_refused "$OUT" "the output folder must be owned by you with mode 0700"
    fi
fi

if [ "$MODE" = "redact-dir" ]; then
    check_path dir "$REDACT_DIR" || die_refused "$REDACT_DIR" "$REFUSE_REASON"
    in_list=$("$FIND" "$REDACT_DIR" -mindepth 1 | "$SORT") || die "Cannot read the --redact-dir folder."
    if [ -n "$in_list" ]; then
        while IFS= read -r p; do
            rel="${p#"$REDACT_DIR"/}"
            [ -d "$p" ] && continue
            [ "$rel" = "record-log.txt" ] && continue
            if [ ! -f "$p" ]; then
                die_refused "$rel" "it is not a regular file"
            fi
            limit="$MAX_BYTES"
            case "$rel" in
                docker-*.json) limit="$DOCKER_MAX_BYTES" ;;
                *) ;;
            esac
            size=$("$WC" -c <"$p" | "$TR" -d ' ')
            REFUSE_REASON=""
            if refuse_name "$rel"; then
                die_refused "$rel" "$REFUSE_REASON"
            fi
            if [ "$size" -gt "$limit" ]; then
                die_refused "$rel" "it is larger than the size limit"
            fi
            if ! recording_path_ok "$rel"; then
                die "This file is not part of the recording format: $(printable "$rel")"
            fi
        done <<<"$in_list"
    fi
else
    if [ "$ROOT_IS_SLASH" != 1 ]; then
        check_path dir "$ROOT" || die_refused "$ROOT" "$REFUSE_REASON"
    fi
    for entry in ${REPLIES[@]+"${REPLIES[@]}"}; do
        rfile="${entry#*=}"
        check_path file "$rfile" || die_refused "$rfile" "$REFUSE_REASON"
        if ! run_clean "$PERL" -e "$REDACTOR" -- "$rfile" x x jsoncheck </dev/null; then
            die "The reply file for ${entry%%=*} is not JSON. Save the command's JSON output, unchanged."
        fi
    done
fi

# ---------- the list from the marker block ----------
LISTS=""
block=""
while IFS= read -r line; do
    case "$line" in
        "# BEGIN KEPT-DOMAINS") block="K" ;;
        "# END KEPT-DOMAINS") block="" ;;
        "# "*)
            if [ -n "$block" ]; then
                LISTS="$LISTS$block ${line#\# }"$'\n'
            fi
            ;;
        *) ;;
    esac
done <"$0"

# ---------- staging (raw data lives only here) ----------
if [ -d /dev/shm ] && [ -w /dev/shm ]; then
    STAGE=$("$MKTEMP" -d /dev/shm/gd-record.XXXXXX)
else
    # The clean start only passes a TMPDIR that is yours and not writable by others,
    # but the marker argument can be passed directly, so the check is repeated here;
    # anything else falls back to /tmp (which is sticky).
    STAGE_BASE=/tmp
    if [ -n "${TMPDIR:-}" ] && [[ $TMPDIR == /* ]] && [ -d "$TMPDIR" ] && [ -O "$TMPDIR" ] &&
        [ -n "$("$FIND" "$TMPDIR" -maxdepth 0 ! -perm -g+w ! -perm -o+w 2>/dev/null)" ]; then
        STAGE_BASE="$TMPDIR"
    fi
    STAGE=$("$MKTEMP" -d "$STAGE_BASE/gd-record.XXXXXX")
fi
# shellcheck disable=SC2317,SC2329  # cleanup runs from the traps below (SC2317 in older shellcheck, SC2329 in newer)
cleanup() {
    "$RM" -rf "${STAGE:?}"
}
trap cleanup EXIT
trap 'cleanup; exit 1' INT TERM HUP
"$CHMOD" 700 "$STAGE"
"$MKDIR" "$STAGE/raw"
RAW="$STAGE/raw"
TERMS="$STAGE/.terms"
: >"$TERMS"
"$CHMOD" 600 "$TERMS"
LOG="$RAW/record-log.txt"

[ -d "$OUT" ] || "$MKDIR" "$OUT"
"$CHMOD" 700 "$OUT"

for t in ${TERMS_ARG[@]+"${TERMS_ARG[@]}"}; do
    printf '%s\n' "$t" >>"$TERMS"
done

logline() {
    printf '%s\n' "$*" >>"$LOG"
}

TESTFLAG=""
if [ "$TEST_MODE" = 1 ]; then
    TESTFLAG=1
fi

if [ "$MODE" = "redact-dir" ]; then
    rc=0
    run_clean "$PERL" -e "$REDACTOR" -- "$REDACT_DIR" "$OUT" "$TERMS" "$MODE" "$TESTFLAG" <<<"$LISTS" || rc=$?
    exit "$rc"
fi

# ---------- record mode ----------
: >"$LOG"
logline "record-setup.sh format $FORMAT"

add_term() {
    local what="$1" value="$2" lower
    lower=$(printf '%s' "$value" | "$TR" "[:upper:]" "[:lower:]")
    if [ "${#value}" -lt 4 ]; then
        logline "term-skipped $what too-short"
    elif is_platform_default "$lower"; then
        logline "term-skipped $what platform-default"
    elif [[ $value =~ $TERM_RE ]]; then
        printf '%s\n' "$value" >>"$TERMS"
    else
        logline "term-skipped $what unusual-characters"
    fi
}

host_name=""
if [ -n "$HOSTNAMECMD" ]; then
    host_name=$(run_clean "$HOSTNAMECMD" 2>/dev/null | "$HEAD" -n 1 || true)
fi
add_term hostname "$host_name"
case "$host_name" in
    *.*) add_term hostname-short "${host_name%%.*}" ;;
    *) ;;
esac
user_name=""
if [ -n "$IDCMD" ]; then
    user_name=$(run_clean "$IDCMD" -un 2>/dev/null | "$HEAD" -n 1 || true)
fi
add_term username "$user_name"

COLLECTED_DOCKER=0
COLLECTED_SYSTEMD=0

# 1. Docker: three list questions, nothing else.
docker_get() {
    local file="$1" url="$2"
    if run_clean "$CURL" -q --request GET --proto =http --noproxy '*' --max-redirs 0 --silent --show-error --fail --max-time 15 --max-filesize 16777216 --unix-socket "$SOCK" --output "$RAW/$file" "$url" 2>/dev/null; then
        logline "collected $file"
        COLLECTED_DOCKER=1
    else
        "$RM" -f "${RAW:?}/${file:?}"
        logline "skipped $file docker-socket-unreadable"
    fi
}
docker_ok=1
docker_why=""
if [ -z "$CURL" ]; then
    docker_ok=0
    docker_why="curl-missing"
elif [ ! -S "$SOCK" ]; then
    docker_ok=0
    docker_why="no-docker-socket"
elif ! check_path socket "$SOCK"; then
    docker_ok=0
    docker_why="untrusted-socket"
fi
if [ "$docker_ok" = 1 ]; then
    docker_get docker-version.json "http://localhost/version"
    docker_get docker-ps.json "http://localhost/containers/json?all=true"
    docker_get docker-images.json "http://localhost/images/json"
else
    for f in docker-version.json docker-ps.json docker-images.json; do
        logline "skipped $f $docker_why"
    done
fi

# run_to FILE NAME ARGS...: the command's output becomes the recording file.
run_to() {
    local file="$1" name="$2" path
    shift 2
    path=$(tool "$name")
    if [ -z "$path" ]; then
        logline "skipped $file command-missing"
        return 1
    fi
    if run_clean "$path" "$@" >"$RAW/$file" 2>/dev/null; then
        logline "collected $file"
        return 0
    fi
    "$RM" -f "${RAW:?}/${file:?}"
    logline "skipped $file command-failed"
    return 1
}

# 2 to 4: system lists.
if run_to systemctl-list-units.txt systemctl list-units --type=service --all --no-pager --plain --no-legend; then
    COLLECTED_SYSTEMD=1
fi
# shellcheck disable=SC2016
run_to dpkg-query.txt dpkg-query -W -f='${Package}\t${Version}\t${db:Status-Abbrev}\n' || true
run_to ss-tlnp.txt ss -tlnp || true
run_to ss-ulnp.txt ss -ulnp || true

# copy_file PATH_ON_BOX RECORDING_PATH: copies one fixed file after the checks.
copy_file() {
    local rel="$1" dest="$2" full="$ROOT$1"
    if [ ! -e "$full" ] && [ ! -L "$full" ]; then
        logline "skipped $dest not-present"
        return 1
    fi
    if ! check_path file "$full"; then
        # An app's folder name is the owner's own text: the log names the recording
        # path (the redactor turns it into apps/app-N/...), never the path on the box,
        # and never the parent folder a reason may name.
        case "$dest" in
            apps/*) logline "refused $dest ${REFUSE_REASON%% /*}" ;;
            *) logline "refused $rel $REFUSE_REASON" ;;
        esac
        return 1
    fi
    case "$dest" in
        */*) "$MKDIR" -p "$RAW/${dest%/*}" ;;
        *) ;;
    esac
    if "$CAT" "$full" >"$RAW/$dest" 2>/dev/null; then
        logline "collected $dest"
        return 0
    fi
    "$RM" -f "${RAW:?}/${dest:?}"
    logline "skipped $dest unreadable"
    return 1
}

# 5. Tor.
copy_file /etc/tor/torrc torrc || true

# 6. Versions of a fixed list of root-owned programs.
if [ "$ROOT_IS_SLASH" != 1 ]; then
    logline "skipped binaries-version.txt root-not-slash"
elif [ -z "$TIMEOUT" ]; then
    logline "skipped binaries-version.txt command-missing"
else
    ran=0
    : >"$RAW/binaries-version.txt"
    for p in /usr/local/bin/bitcoind /usr/local/bin/lnd /usr/local/bin/lightningd /usr/local/bin/Fulcrum /usr/local/bin/electrs /usr/bin/tor /usr/sbin/tor; do
        [ -e "$p" ] || continue
        [ -L "$p" ] && continue
        if ! binary_ok "$p"; then
            case "$REFUSE_REASON" in
                "untrusted parent"*) logline "skipped binaries-version.txt parent-writable $p" ;;
                *) logline "skipped binaries-version.txt unsafe-path $p" ;;
            esac
            continue
        fi
        {
            printf '== %s\n' "$p"
            "$ENV" -i PATH=/usr/bin:/bin "$TIMEOUT" 5 "$p" --version </dev/null 2>&1 | "$HEAD" -n 5 || true
        } >>"$RAW/binaries-version.txt"
        ran=1
    done
    if [ "$ran" = 1 ]; then
        logline "collected binaries-version.txt"
    else
        "$RM" -f "${RAW:?}/binaries-version.txt"
        logline "skipped binaries-version.txt none-found"
    fi
fi

# filter_file PATH_ON_BOX RECORDING_PATH EXTENDED_REGEX: keeps only matching lines.
filter_file() {
    local rel="$1" dest="$2" pattern="$3" full="$ROOT$1" kept dropped total
    if [ ! -e "$full" ] && [ ! -L "$full" ]; then
        logline "skipped $dest not-present"
        return 1
    fi
    if ! check_path file "$full" skipnames; then
        logline "refused $rel $REFUSE_REASON"
        return 1
    fi
    "$GREP" -E "$pattern" "$full" >"$RAW/$dest" 2>/dev/null || true
    kept=$("$WC" -l <"$RAW/$dest" | "$TR" -d ' ')
    total=$("$WC" -l <"$full" | "$TR" -d ' ')
    dropped=$((total - kept))
    [ "$dropped" -ge 0 ] || dropped=0
    logline "collected $dest"
    logline "filtered $dest kept $kept dropped $dropped"
    return 0
}

# 7. RaspiBlitz.
PLATFORM_RASPIBLITZ=0
filter_file /home/admin/_version.info raspiblitz-version.txt '^code(Version|Release)="?[A-Za-z0-9._-]{1,32}"?$' || true
if [ -e "$ROOT/home/admin/_version.info" ]; then
    PLATFORM_RASPIBLITZ=1
fi
if [ -e "$ROOT/mnt/hdd/app-data/raspiblitz.conf" ]; then
    PLATFORM_RASPIBLITZ=1
fi
filter_file /mnt/hdd/app-data/raspiblitz.conf raspiblitz-conf.txt '^([A-Za-z][A-Za-z0-9_]*="?(on|off)"?|(network|chain|lightning)="?[a-z]{1,16}"?)$' || true
filter_file /home/admin/raspiblitz.info raspiblitz-info.txt '^(baseimage|cpu|vm|network|chain|lightning)="?[A-Za-z0-9._-]{1,32}"?$' || true

# 8. Umbrel.
UMBREL_DIR="$ROOT/home/umbrel/umbrel/app-data"
PLATFORM_UMBREL=0
if [ -d "$UMBREL_DIR" ]; then
    PLATFORM_UMBREL=1
    for d in "$UMBREL_DIR"/*/; do
        [ -d "$d" ] || continue
        d="${d%/}"
        id="${d##*/}"
        if ! [[ $id =~ $SLUG_RE ]] || [ "${#id}" -gt 40 ]; then
            logline "skipped apps/invalid-name invalid-app-id"
            continue
        fi
        if ! check_path dir "$d"; then
            logline "refused apps/$id ${REFUSE_REASON%% /*}"
            continue
        fi
        copy_file "/home/umbrel/umbrel/app-data/$id/umbrel-app.yml" "apps/$id/umbrel-app.yml" || true
    done
fi

# 9. myNode.
MYNODE_DIR="$ROOT/usr/share/mynode_apps"
PLATFORM_MYNODE=0
if [ -d "$MYNODE_DIR" ]; then
    PLATFORM_MYNODE=1
    for d in "$MYNODE_DIR"/*/; do
        [ -d "$d" ] || continue
        d="${d%/}"
        id="${d##*/}"
        if ! [[ $id =~ $SLUG_RE ]] || [ "${#id}" -gt 40 ]; then
            logline "skipped apps/invalid-name invalid-app-id"
            continue
        fi
        if ! check_path dir "$d"; then
            logline "refused apps/$id ${REFUSE_REASON%% /*}"
            continue
        fi
        for f in "$d"/*.json; do
            [ -e "$f" ] || continue
            base="${f##*/}"
            if ! [[ $base =~ $JSON_NAME_RE ]]; then
                logline "skipped apps/$id/invalid-name invalid-file-name"
                continue
            fi
            copy_file "/usr/share/mynode_apps/$id/$base" "apps/$id/$base" || true
        done
    done
fi

# 10. Replies the person captured with their own commands.
for entry in ${REPLIES[@]+"${REPLIES[@]}"}; do
    left="${entry%%=*}"
    rfile="${entry#*=}"
    svc="${left%%/*}"
    call="${left#*/}"
    "$MKDIR" -p "$RAW/replies/$svc"
    "$CAT" "$rfile" >"$RAW/replies/$svc/$call.json"
    logline "collected replies/$svc/$call.json"
done

# platform hint
if [ "$PLATFORM_RASPIBLITZ" = 1 ]; then
    hint=raspiblitz
elif [ "$PLATFORM_UMBREL" = 1 ]; then
    hint=umbrel
elif [ "$PLATFORM_MYNODE" = 1 ]; then
    hint=mynode
elif [ "$COLLECTED_DOCKER" = 1 ]; then
    hint=docker
elif [ "$COLLECTED_SYSTEMD" = 1 ]; then
    hint=systemd
else
    hint=unknown
fi
logline "platform-hint $hint"

rc=0
run_clean "$PERL" -e "$REDACTOR" -- "$RAW" "$OUT" "$TERMS" "$MODE" "$TESTFLAG" <<<"$LISTS" || rc=$?
exit "$rc"
