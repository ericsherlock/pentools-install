#!/usr/bin/env bash
# lib/installers.sh — install-method handlers.
#
# Every handler takes a resolved "spec" and either executes it or, when
# PT_DRY_RUN=1, prints the command it *would* run. Handlers never exit the
# process; they return non-zero on failure so the engine can record it and
# continue. Requires log() and the PT_* globals from the engine/detect.sh.
#
# Handlers implemented here (real, dry-run aware):
#   native pkg (apt/dnf/pacman/brew), pipx, gem, go, git
# Stubbed for later phases:
#   binary (release-asset download + extract)

# run <cmd...> : execute, or in dry-run mode just print the command.
run() {
    if [ "${PT_DRY_RUN:-0}" = "1" ]; then
        log "DRY-RUN: $*"
        return 0
    fi
    eval "$@"
}

# ---------------------------------------------------------------------------
# Idempotency helpers
# ---------------------------------------------------------------------------

# tool_present <command> : true if <command> is already on PATH.
tool_present() {
    command -v "$1" >/dev/null 2>&1
}

# ---------------------------------------------------------------------------
# Native package manager
# ---------------------------------------------------------------------------

# native_install <package> : install via the detected package manager.
native_install() {
    local pkg="$1"
    case "$PT_PKG_MGR" in
        apt)    run "apt-get install -y $pkg" ;;
        dnf)    run "dnf install -y $pkg" ;;
        pacman) run "pacman -S --noconfirm --needed $pkg" ;;
        brew)   run "brew install $pkg" ;;
        *)      log "No native installer for manager '$PT_PKG_MGR'"; return 1 ;;
    esac
}

# refresh_indexes : update the package manager's metadata once per run.
refresh_indexes() {
    case "$PT_PKG_MGR" in
        apt)    run "apt-get update" ;;
        dnf)    run "dnf makecache" ;;
        pacman) run "pacman -Sy --noconfirm" ;;
        brew)   run "brew update" ;;
    esac
}

# ---------------------------------------------------------------------------
# Fallback method handlers — each takes the spec *after* the "type:" prefix.
# ---------------------------------------------------------------------------

# pipx_install <spec> : PEP 668-safe Python tool install. <spec> may be a
# PyPI name or a VCS ref (e.g. git+https://github.com/org/repo).
pipx_install() {
    local spec="$1"
    if [ "${PT_DRY_RUN:-0}" != "1" ] && ! tool_present pipx; then
        log "pipx not found — attempting to bootstrap it"
        native_install pipx || run "python3 -m pip install --user pipx"
    fi
    run "pipx install $spec"
}

# gem_install <spec> : Ruby gem install.
gem_install() {
    run "gem install $1"
}

# go_install <spec> : 'go install module@version'.
go_install() {
    if [ "${PT_DRY_RUN:-0}" != "1" ] && ! tool_present go; then
        log "go toolchain not found — skipping go install of '$1'"
        return 1
    fi
    run "go install $1"
}

# git_install <url> : clone into $PT_GIT_DIR, or 'git pull' if it already
# exists (idempotent). Does not build — clone-only, as the legacy script did.
git_install() {
    local url="$1" dest name
    name=$(basename "$url" .git)
    dest="${PT_GIT_DIR:-$PWD/pentesting-tools}/$name"
    if [ -d "$dest/.git" ]; then
        log "$name already cloned — updating"
        run "git -C '$dest' pull --ff-only"
    else
        run "git clone --depth 1 '$url' '$dest'"
    fi
}

# binary_install <spec> : download a release asset and place it on PATH.
# Stubbed until Phase 2/3; records intent so --dry-run stays informative.
binary_install() {
    log "TODO(binary handler): would fetch release asset: $1"
    return 0
}

# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

# dispatch_fallback <type:spec> : route a fallback spec to its handler.
dispatch_fallback() {
    local raw="$1" type spec
    type="${raw%%:*}"
    spec="${raw#*:}"
    case "$type" in
        pipx)   pipx_install "$spec" ;;
        gem)    gem_install "$spec" ;;
        go)     go_install "$spec" ;;
        git)    git_install "$spec" ;;
        binary) binary_install "$spec" ;;
        *)      log "Unknown fallback method: '$type'"; return 1 ;;
    esac
}
