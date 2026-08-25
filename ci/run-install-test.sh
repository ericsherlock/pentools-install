#!/usr/bin/env bash
#
# ci/run-install-test.sh <target> <category> [<mode>]
#
# Runs a REAL install of one category on one target and gates on the
# installer's own summary (failed=0). The target environment (distro
# container or native macOS) is provided by ci/targets.sh.
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

# shellcheck source=ci/targets.sh
. "$(dirname "$0")/targets.sh"

# smoke tier installs one representative tool per category; full installs all.
case "$mode" in
    full)  sample="" ;;
    *)     sample="--sample 1" ;;
esac

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

run_in_target "$target" "./pentools_install --only '$category' --yes $sample 2>&1 | tee out.txt"
assert_clean out.txt
