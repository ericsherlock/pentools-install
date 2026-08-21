#!/usr/bin/env bash
#
# ci/run-install-test.sh <target> <category> [<sample-arg>]
#
# Runs a REAL install of one category on one target and gates on the
# installer's own summary (failed=0). Linux targets run inside a distro
# container; the macos target runs natively on the runner.
#
#   target      : kali | debian | fedora | arch | macos
#   category    : a manifest category (recon, web, ...)
#   mode        : smoke (1 tool/category) | full (all tools); default smoke
#
# Exits non-zero if any package in the category failed to install.

set -euo pipefail

target="${1:?target required}"
category="${2:?category required}"
mode="${3:-smoke}"

# smoke tier installs one representative tool per category; full installs all.
case "$mode" in
    full)  sample="" ;;
    *)     sample="--sample 1" ;;
esac

# Tools with no install path on a given target — genuinely absent from that
# ecosystem with no cross-distro fallback (verified from the full-tier run). A
# shard is tolerated ONLY if every failing tool is on this list (space-
# separated, keyed by target).
expected_fail_for() {
    case "$1" in
        # Kali-only or removed-from-Debian-trixie, no cross-distro fallback,
        # plus trivy (needs the Aqua repo/installer; go install unsupported).
        debian) echo "metasploit-framework beef-xss gvm burpsuite zaproxy feroxbuster ghidra jadx kismet radare2 rizin trivy" ;;
        # trivy: native only (arch/brew); needs the Aqua repo elsewhere.
        kali)   echo "trivy" ;;
        fedora) echo "trivy" ;;
        # wfuzz: pycurl fails to build against Homebrew's bleeding-edge Python.
        macos)  echo "wfuzz" ;;
        *)      echo "" ;;
    esac
}

# Pass if the installer reported failed=0, or if the only failures are tools
# known to be unavailable on this target (see expected_fail_for).
assert_clean() {
    local logfile="$1"
    grep -q 'Summary:' "$logfile" || { echo "No summary produced"; return 1; }
    grep -q 'failed=0' "$logfile" && { echo "OK: $target/$category clean (failed=0)"; return 0; }

    local failed exp leftover t
    failed=$(grep -E '\] Failed:' "$logfile" | sed -E 's/.*Failed: *//' | tr -s ' ')
    exp=" $(expected_fail_for "$target") "
    leftover=""
    for t in $failed; do
        case "$exp" in *" $t "*) : ;; *) leftover="$leftover $t" ;; esac
    done

    if [ -n "$(printf '%s' "$leftover" | tr -d ' ')" ]; then
        echo "::error::unexpected install failures on $target/$category:$leftover"
        grep -E 'FAIL |Summary:' "$logfile" || true
        return 1
    fi
    echo "OK: $target/$category — only known-unavailable tools failed ($failed)"
}

# Bootstrap the BlackArch repos (needed for many pacman package names).
blackarch_strap='
  pacman -Sy --noconfirm --needed archlinux-keyring curl
  for i in 1 2 3; do
    curl -fsSL https://blackarch.org/strap.sh -o /tmp/strap.sh && break
    echo "strap.sh download retry $i"; sleep 5
  done
  chmod +x /tmp/strap.sh && /tmp/strap.sh
  pacman -Sy --noconfirm
'

run_in_container() {
    local image="$1" setup="$2"
    docker run --rm -v "$PWD":/work -w /work "$image" bash -c "
        set -e
        $setup
        ./pentools_install --only '$category' --yes $sample 2>&1 | tee out.txt
    "
    assert_clean out.txt
}

# Toolchains needed so fallbacks work: go (go:), ruby/gems (gem:), git (git:),
# pipx (pipx:), plus a C/Rust build chain and dev headers for tools that build
# from source: cmake (pwntools), libcurl+headers (wfuzz/pycurl), ruby headers
# (wpscan gem native ext), libpcap headers (bettercap go build).
case "$target" in
    kali)
        run_in_container "kalilinux/kali-rolling" \
            "apt-get update && apt-get install -y gawk git golang-go ruby-full ruby-dev curl pipx findutils build-essential python3-dev cargo cmake libcurl4-openssl-dev libpcap-dev"
        ;;
    debian)
        run_in_container "debian:latest" \
            "apt-get update && apt-get install -y gawk git golang-go ruby-full ruby-dev curl pipx findutils build-essential python3-dev cargo cmake libcurl4-openssl-dev libpcap-dev"
        ;;
    fedora)
        run_in_container "fedora:latest" \
            "dnf install -y gawk git golang rubygems ruby-devel curl pipx findutils gcc gcc-c++ python3-devel cargo cmake libcurl-devel libpcap-devel"
        ;;
    arch)
        run_in_container "archlinux:latest" \
            "pacman -Sy --noconfirm --needed gawk git go ruby curl python-pipx findutils base-devel rust cmake libpcap && $blackarch_strap"
        ;;
    macos)
        # Native run on the macOS runner (Homebrew, no root). Ensure the go
        # toolchain is present for go: fallbacks (not preinstalled reliably).
        command -v go >/dev/null 2>&1 || brew install go
        ./pentools_install --only "$category" --yes $sample 2>&1 | tee out.txt
        assert_clean out.txt
        ;;
    *)
        echo "Unknown target: $target" >&2
        exit 2
        ;;
esac
