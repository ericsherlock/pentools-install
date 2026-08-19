#!/usr/bin/env bash
# lib/detect.sh — platform, package-manager, and architecture detection.
#
# Sourced by the main engine. Populates the following globals:
#   PT_OS        : linux | macos | unknown
#   PT_DISTRO    : distro id from /etc/os-release (debian, ubuntu, kali,
#                  fedora, rhel, arch, blackarch, ...) or "macos"/"unknown"
#   PT_PKG_MGR   : apt | dnf | pacman | brew  (the resolved manager)
#   PT_PKG_COL   : manifest column name for PT_PKG_MGR (apt|dnf|pacman|brew)
#   PT_ARCH      : amd64 | arm64 | <raw uname -m if unrecognized>
#   PT_NEEDS_ROOT: 1 if the resolved manager requires root, else 0
#
# All detection is best-effort and side-effect free (no installs).

# Detect the operating system family.
detect_os() {
    local uname_s
    uname_s=$(uname -s 2>/dev/null || echo unknown)
    case "$uname_s" in
        Linux)  PT_OS="linux" ;;
        Darwin) PT_OS="macos" ;;
        *)      PT_OS="unknown" ;;
    esac
}

# Detect the distro id (Linux only) from /etc/os-release.
detect_distro() {
    if [ "$PT_OS" = "macos" ]; then
        PT_DISTRO="macos"
        return
    fi
    if [ -r /etc/os-release ]; then
        # shellcheck disable=SC1091
        PT_DISTRO=$(. /etc/os-release 2>/dev/null && echo "${ID:-unknown}")
    else
        PT_DISTRO="unknown"
    fi
    [ -z "$PT_DISTRO" ] && PT_DISTRO="unknown"
}

# Normalize CPU architecture to the labels Go/binary releases use.
detect_arch() {
    local m
    m=$(uname -m 2>/dev/null || echo unknown)
    case "$m" in
        x86_64|amd64)      PT_ARCH="amd64" ;;
        aarch64|arm64)     PT_ARCH="arm64" ;;
        armv7l|armv6l|arm) PT_ARCH="arm" ;;
        i386|i686)         PT_ARCH="386" ;;
        *)                 PT_ARCH="$m" ;;
    esac
}

# Resolve the package manager. Preference order favors the OS-native manager;
# on macOS only Homebrew is considered. Sets PT_PKG_MGR, PT_PKG_COL,
# PT_NEEDS_ROOT. Returns 1 if no supported manager is found.
detect_pkg_mgr() {
    PT_PKG_MGR=""
    PT_PKG_COL=""
    PT_NEEDS_ROOT=1

    if [ "$PT_OS" = "macos" ]; then
        if command -v brew >/dev/null 2>&1; then
            PT_PKG_MGR="brew"; PT_PKG_COL="brew"; PT_NEEDS_ROOT=0
            return 0
        fi
        return 1
    fi

    # Linux: pick the first native manager present.
    if command -v apt-get >/dev/null 2>&1; then
        PT_PKG_MGR="apt"; PT_PKG_COL="apt"; PT_NEEDS_ROOT=1
    elif command -v dnf >/dev/null 2>&1; then
        PT_PKG_MGR="dnf"; PT_PKG_COL="dnf"; PT_NEEDS_ROOT=1
    elif command -v pacman >/dev/null 2>&1; then
        PT_PKG_MGR="pacman"; PT_PKG_COL="pacman"; PT_NEEDS_ROOT=1
    elif command -v brew >/dev/null 2>&1; then
        # Linuxbrew — supported as a fallback manager.
        PT_PKG_MGR="brew"; PT_PKG_COL="brew"; PT_NEEDS_ROOT=0
    else
        return 1
    fi
    return 0
}

# Run all detection steps. Returns 1 if no supported package manager found.
detect_platform() {
    detect_os
    detect_distro
    detect_arch
    detect_pkg_mgr
}

# Human-readable one-line summary of the detected platform.
platform_summary() {
    printf 'OS=%s distro=%s arch=%s pkg_mgr=%s needs_root=%s' \
        "${PT_OS:-?}" "${PT_DISTRO:-?}" "${PT_ARCH:-?}" \
        "${PT_PKG_MGR:-none}" "${PT_NEEDS_ROOT:-?}"
}
