#!/usr/bin/env bash
#
# ci/run-roundtrip-test.sh <target>
#
# Exercises the full lifecycle on one target with a smoke-scale selection
# (one tool per category): install -> update -> uninstall. Asserts each phase
# reports failed=0, and that `nmap` is present after install/update and gone
# after uninstall.
#
# Linux targets only: the runners for those are clean containers, so "we
# installed X, now remove X" is unambiguous. macOS is excluded here because its
# hosted runner ships tools preinstalled (e.g. awscli) that the presence gate
# can't distinguish from ones we installed; macOS install is covered by the
# install-test job instead.

set -euo pipefail

target="${1:?target required}"

# shellcheck source=ci/targets.sh
. "$(dirname "$0")/targets.sh"

# Skip tools that are genuinely unavailable on this target (they would fail the
# install phase for reasons unrelated to the lifecycle machinery).
skip="$(expected_fail_for "$target" | tr ' ' ',')"
skipflag=""
[ -n "$skip" ] && skipflag="--skip $skip"

phases="
    set -e
    echo '== INSTALL =='
    ./pentools_install --all --sample 1 $skipflag --yes 2>&1 | tee inst.txt
    grep -q 'failed=0' inst.txt
    command -v nmap >/dev/null || { echo '::error::nmap missing after install'; exit 1; }

    echo '== UPDATE =='
    ./pentools_install --all --sample 1 $skipflag --update --yes 2>&1 | tee upd.txt
    grep -q 'failed=0' upd.txt
    command -v nmap >/dev/null || { echo '::error::nmap missing after update'; exit 1; }

    echo '== UNINSTALL =='
    ./pentools_install --all --sample 1 $skipflag --uninstall --yes 2>&1 | tee unin.txt
    grep -q 'failed=0' unin.txt
    ! command -v nmap >/dev/null || { echo '::error::nmap still present after uninstall'; exit 1; }

    echo 'ROUNDTRIP_OK'
"

run_in_target "$target" "$phases"
