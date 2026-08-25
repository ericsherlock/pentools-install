#!/usr/bin/env bash
# ci/targets.sh — shared target environments for the install-test workflows.
#
# run_in_target <target> <inline-bash> : run <inline-bash> inside the target's
# environment — a distro container for Linux targets (with the toolchain and
# build deps the fallbacks need), or natively on the runner for macOS. The
# repo is mounted at /work (Linux) or is simply the cwd (macOS), so a command
# like "./pentools_install ..." resolves and writes its logs to the workspace.
#
# Sourced by run-install-test.sh and run-roundtrip-test.sh so the environment
# definitions stay in one place.

# expected_fail_for <target> : tools genuinely absent from that target (native
# cell attempted and fails, no cross-distro fallback). Shared by the install
# gate (tolerate) and the round-trip (skip).
expected_fail_for() {
    case "$1" in
        debian) echo "metasploit-framework beef-xss gvm burpsuite zaproxy feroxbuster ghidra jadx kismet radare2 rizin" ;;
        *)      echo "" ;;
    esac
}

# BlackArch bootstrap — needed for many pacman package names.
_blackarch_strap='
  pacman -Sy --noconfirm --needed archlinux-keyring curl
  for i in 1 2 3; do
    curl -fsSL https://blackarch.org/strap.sh -o /tmp/strap.sh && break
    echo "strap.sh download retry $i"; sleep 5
  done
  chmod +x /tmp/strap.sh && /tmp/strap.sh
  pacman -Sy --noconfirm
'

run_in_target() {
    local target="$1" script="$2" image setup
    case "$target" in
        kali)
            image="kalilinux/kali-rolling"
            setup="apt-get update && apt-get install -y gawk git golang-go ruby-full ruby-dev curl pipx findutils build-essential python3-dev python3-venv cargo cmake libcurl4-openssl-dev libpcap-dev"
            ;;
        debian)
            image="debian:latest"
            setup="apt-get update && apt-get install -y gawk git golang-go ruby-full ruby-dev curl pipx findutils build-essential python3-dev python3-venv cargo cmake libcurl4-openssl-dev libpcap-dev"
            ;;
        fedora)
            image="fedora:latest"
            setup="dnf install -y gawk git golang rubygems ruby-devel curl pipx findutils gcc gcc-c++ python3-devel cargo cmake libcurl-devel libpcap-devel libusb1-devel libnetfilter_queue-devel"
            ;;
        arch)
            image="archlinux:latest"
            setup="pacman -Sy --noconfirm --needed gawk git go ruby curl python-pipx findutils base-devel rust cmake libpcap && $_blackarch_strap"
            ;;
        macos)
            # Native on the macOS runner (Homebrew, no root). Ensure go exists
            # for go: fallbacks; then run the script directly.
            command -v go >/dev/null 2>&1 || brew install go
            bash -c "$script"
            return $?
            ;;
        *)
            echo "Unknown target: $target" >&2
            return 2
            ;;
    esac

    docker run --rm -v "$PWD":/work -w /work "$image" bash -c "
        set -e
        $setup
        $script
    "
}
