#!/usr/bin/env bash
# lib/ui.sh — category selection, listing, and the run summary.
#
# Kept POSIX-bash-3.2 friendly (macOS ships bash 3.2): no associative
# arrays, no ${var,,}. Requires log() and the PT_* globals from the engine.

# Curated menu order. Only categories actually present in the manifest are
# shown. "base" (git, pipx) is intentionally excluded — it is always
# installed because the fallbacks depend on it.
CATEGORY_ORDER="recon web wireless ad-lateral passwords forensics-re osint cloud vuln exploitation post-exploit wordlists"

# csv_contains <csv> <value> : true if <value> is an element of comma list.
csv_contains() {
    case ",$1," in
        *",$2,"*) return 0 ;;
        *)        return 1 ;;
    esac
}

# category_count <category> : number of manifest rows in <category>.
category_count() {
    awk -F'|' -v cat="$1" '
        /^[[:space:]]*#/ { next }
        /^[[:space:]]*$/ { next }
        {
            c = $2
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", c)
            if (c == cat) n++
        }
        END { print n + 0 }
    ' "$MANIFEST"
}

# present_categories : echo the menu-ordered categories that exist in the
# manifest (space separated).
present_categories() {
    local cat out=""
    for cat in $CATEGORY_ORDER; do
        [ "$(category_count "$cat")" -gt 0 ] && out="$out $cat"
    done
    printf '%s' "${out# }"
}

# print_categories : human-readable category listing with counts.
print_categories() {
    local cat
    echo "Categories in $MANIFEST:"
    for cat in $(present_categories); do
        printf '  %-14s %3d tools\n' "$cat" "$(category_count "$cat")"
    done
    printf '  %-14s (always installed)\n' "base"
}

# interactive_select : prompt the user to choose categories. Sets PT_SELECTED
# to a comma-separated list (always including "base").
interactive_select() {
    local cats i=1 line reply chosen="base"
    # Build a positional list of selectable categories.
    set -- $(present_categories)
    cats="$*"

    echo
    echo "Select tool categories to install:"
    i=1
    for c in $cats; do
        printf '  %2d) %-14s (%d tools)\n' "$i" "$c" "$(category_count "$c")"
        i=$((i + 1))
    done
    echo "   a) all categories"
    echo
    printf 'Enter numbers (comma/space separated), or "a" for all: '
    read -r reply

    case "$reply" in
        a|A|all|ALL|"")
            chosen="base"
            for c in $cats; do chosen="$chosen,$c"; done
            ;;
        *)
            # Map each entered index to a category name.
            local token idx c j
            reply="$(echo "$reply" | tr ',' ' ')"
            for token in $reply; do
                case "$token" in
                    ''|*[!0-9]*) log "Ignoring invalid selection: '$token'"; continue ;;
                esac
                j=1
                for c in $cats; do
                    if [ "$j" -eq "$token" ]; then
                        csv_contains "$chosen" "$c" || chosen="$chosen,$c"
                    fi
                    j=$((j + 1))
                done
            done
            ;;
    esac
    PT_SELECTED="$chosen"
}

# resolve_selection : decide PT_SELECTED based on flags, prompting only when
# necessary. --only wins; --all / --yes select everything; otherwise the
# interactive menu runs. "base" is always included.
resolve_selection() {
    local c
    if [ -n "${PT_ONLY:-}" ]; then
        # Validate requested categories against what exists.
        PT_SELECTED="base"
        for c in $(echo "$PT_ONLY" | tr ',' ' '); do
            if [ "$(category_count "$c")" -gt 0 ]; then
                PT_SELECTED="$PT_SELECTED,$c"
            else
                log "WARN: --only category '$c' not found in manifest; ignoring"
            fi
        done
    elif [ "${PT_ALL:-0}" -eq 1 ] || [ "${PT_ASSUME_YES:-0}" -eq 1 ] || [ "${PT_DRY_RUN:-0}" -eq 1 ]; then
        PT_SELECTED="base"
        for c in $(present_categories); do PT_SELECTED="$PT_SELECTED,$c"; done
    else
        interactive_select
    fi
    log "Selected categories:$(echo " $PT_SELECTED" | tr ',' ' ')"
}

# compute_sample_set : populate PT_SAMPLE_TOOLS with the first PT_SAMPLE tool
# names of each selected category (plus all "base" tools). Manifest order
# determines which tools are the "representatives". Used by --sample.
compute_sample_set() {
    PT_SAMPLE_TOOLS="$(awk -F'|' -v n="$PT_SAMPLE" -v sel=",$PT_SELECTED," '
        function trim(s){ gsub(/^[ \t]+|[ \t]+$/, "", s); return s }
        /^[[:space:]]*#/ { next }
        /^[[:space:]]*$/ { next }
        {
            name = trim($1); cat = trim($2)
            if (cat == "base") { print name; next }
            if (index(sel, "," cat ",") == 0) next
            count[cat]++
            if (count[cat] <= n) print name
        }
    ' "$MANIFEST" | tr "\n" " ")"
}

# print_summary : end-of-run report.
print_summary() {
    log "----------------------------------------------------------------"
    log "Summary: planned=$COUNT_PLANNED ok=$COUNT_OK skipped=$COUNT_SKIP failed=$COUNT_FAIL deselected=$COUNT_DESELECTED"
    [ -n "$SKIPPED_TOOLS" ] && log "Skipped:$SKIPPED_TOOLS"
    [ -n "$FAILED_TOOLS" ]  && log "Failed: $FAILED_TOOLS"
    log "Log written to: $LOGFILE"
}
