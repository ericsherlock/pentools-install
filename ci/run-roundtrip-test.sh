#!/usr/bin/env bash
#
# ci/run-roundtrip-test.sh <target>
#
# Exercises the full lifecycle on one target with a smoke-scale selection
# (one tool per category): install -> update -> uninstall. Asserts each phase
# reports failed=0, and on Linux targets asserts a concrete presence
# transition for `nmap` (installed -> still present after update -> gone after
# uninstall). macOS skips the presence check because tools may be preinstalled
# on the runner; it still gates on failed=0 for all three phases.

set -euo pipefail

target="${1:?target required}"

# shellcheck source=ci/targets.sh
. "$(dirname "$0")/targets.sh"

# Presence transition checks — Linux containers are clean, macOS may not be.
if [ "$target" = "macos" ]; then
    after_install=""
    after_uninstall=""
else
    after_install='command -v nmap >/dev/null || { echo "::error::nmap missing after install"; exit 1; }'
    after_uninstall='! command -v nmap >/dev/null || { echo "::error::nmap still present after uninstall"; exit 1; }'
fi

phases="
    set -e
    echo '== INSTALL =='
    ./pentools_install --all --sample 1 --yes 2>&1 | tee inst.txt
    grep -q 'failed=0' inst.txt
    $after_install

    echo '== UPDATE =='
    ./pentools_install --all --sample 1 --update --yes 2>&1 | tee upd.txt
    grep -q 'failed=0' upd.txt
    $after_install

    echo '== UNINSTALL =='
    ./pentools_install --all --sample 1 --uninstall --yes 2>&1 | tee unin.txt
    grep -q 'failed=0' unin.txt
    $after_uninstall

    echo 'ROUNDTRIP_OK'
"

run_in_target "$target" "$phases"
