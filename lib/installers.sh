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

# binary_install <spec> : download a release asset and place it on PATH under
# /usr/local/bin. Spec forms:
#   binary:BIN@URL   -> install as <BIN> from <URL>
#   binary:URL       -> install as basename(URL)
# URL may contain {os} (linux|darwin) and {arch} (amd64|arm64|...) which are
# substituted for the detected platform. Handles raw binaries, .tar.gz/.tgz,
# and .zip assets; for archives the first file named <BIN> is extracted.
binary_install() {
    local spec="$1" bin url os tmp asset dest
    case "$spec" in
        *@*) bin="${spec%%@*}"; url="${spec#*@}" ;;
        *)   bin=""; url="$spec" ;;
    esac

    os="$PT_OS"; [ "$os" = "macos" ] && os="darwin"
    url="${url//\{os\}/$os}"
    url="${url//\{arch\}/$PT_ARCH}"
    # Derive the binary name from the (substituted) URL when not given as BIN@.
    [ -z "$bin" ] && bin="$(basename "$url")"
    dest="/usr/local/bin/$bin"

    if [ "${PT_DRY_RUN:-0}" = "1" ]; then
        log "DRY-RUN: download '$url' -> '$dest'"
        return 0
    fi

    local fetch
    if command -v curl >/dev/null 2>&1; then
        fetch="curl -fsSL -o"
    elif command -v wget >/dev/null 2>&1; then
        fetch="wget -qO"
    else
        log "Neither curl nor wget available for binary install of '$bin'"
        return 1
    fi

    tmp="$(mktemp -d)" || return 1
    asset="$tmp/$(basename "$url")"

    if ! $fetch "$asset" "$url"; then
        log "Download failed: $url"
        rm -rf "$tmp"; return 1
    fi

    local rc=0
    case "$asset" in
        *.tar.gz|*.tgz)
            tar -xzf "$asset" -C "$tmp" || rc=1
            _binary_place "$tmp" "$bin" "$dest" || rc=1
            ;;
        *.zip)
            (cd "$tmp" && unzip -oq "$asset") || rc=1
            _binary_place "$tmp" "$bin" "$dest" || rc=1
            ;;
        *)
            install -m 0755 "$asset" "$dest" || rc=1
            ;;
    esac

    rm -rf "$tmp"
    return "$rc"
}

# _binary_place <search_dir> <bin> <dest> : find the first file named <bin>
# under <search_dir> and install it to <dest>.
_binary_place() {
    local dir="$1" bin="$2" dest="$3" found
    found="$(find "$dir" -type f -name "$bin" -perm -u+x 2>/dev/null | head -n1)"
    [ -z "$found" ] && found="$(find "$dir" -type f -name "$bin" 2>/dev/null | head -n1)"
    if [ -z "$found" ]; then
        log "Could not locate '$bin' in downloaded archive"
        return 1
    fi
    install -m 0755 "$found" "$dest"
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
