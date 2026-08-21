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

# git_install <spec> : clone into $PT_GIT_DIR (or 'git pull' if present).
# Spec forms:
#   git:URL           -> clone only (data sets, PowerShell/Windows tools)
#   git:URL::ENTRY    -> clone, install requirements.txt into a venv when
#                        present, and write a PATH launcher (named after the
#                        tool's check/name) that runs ENTRY.
# The launcher goes in $PT_BINDIR (default /usr/local/bin). Uses the global
# R_CHECK/R_NAME set by resolve_tool for the launcher name.
git_install() {
    local spec="$1" url entry name dest
    case "$spec" in
        *::*) url="${spec%%::*}"; entry="${spec##*::}" ;;
        *)    url="$spec"; entry="" ;;
    esac
    name="$(basename "$url" .git)"
    dest="${PT_GIT_DIR:-$PWD/pentesting-tools}/$name"

    if [ "${PT_DRY_RUN:-0}" = "1" ]; then
        if [ -n "$entry" ]; then
            log "DRY-RUN: git clone $url -> $dest ; launcher ${PT_BINDIR:-/usr/local/bin}/${R_CHECK:-$name} -> $entry"
        else
            log "DRY-RUN: git clone $url -> $dest (clone-only)"
        fi
        return 0
    fi

    if [ -d "$dest/.git" ]; then
        log "$name already cloned — updating"
        git -C "$dest" pull --ff-only || return 1
    else
        git clone --depth 1 "$url" "$dest" || return 1
    fi

    # Clone-only: data sets and PowerShell/Windows tools have no Linux launcher.
    if [ -z "$entry" ]; then
        log "$name cloned to $dest (no CLI launcher)"
        return 0
    fi

    _git_make_launcher "$name" "$dest" "$entry"
}

# _git_make_launcher <name> <dest> <entry> : build a venv from requirements
# (if any) and write a PATH launcher. Degrades to clone-only (with a warning)
# if the entry point is missing or the launcher can't be written.
_git_make_launcher() {
    local name="$1" dest="$2" entry="$3"
    local entry_path="$dest/$entry" py="" cmd bindir wrapper

    if [ ! -f "$entry_path" ]; then
        log "WARN: entry point '$entry' not found in $name; left as clone-only"
        return 0
    fi

    # Python tools: isolate their requirements in a venv.
    if [ -f "$dest/requirements.txt" ] && command -v python3 >/dev/null 2>&1; then
        if python3 -m venv "$dest/.venv" >/dev/null 2>&1; then
            "$dest/.venv/bin/pip" install --quiet --upgrade pip >/dev/null 2>&1 || true
            if "$dest/.venv/bin/pip" install --quiet -r "$dest/requirements.txt" >/dev/null 2>&1; then
                py="$dest/.venv/bin/python"
            else
                log "WARN: $name requirements failed; launcher will use system python3"
            fi
        fi
    fi

    chmod +x "$entry_path" 2>/dev/null || true

    cmd="${R_CHECK:-$name}"
    bindir="${PT_BINDIR:-/usr/local/bin}"
    wrapper="$bindir/$cmd"
    mkdir -p "$bindir" 2>/dev/null || true

    {
        echo '#!/usr/bin/env bash'
        if [ -n "$py" ]; then
            printf 'cd "%s" && exec "%s" "%s" "$@"\n' "$dest" "$py" "$entry_path"
        else
            printf 'cd "%s" && exec "./%s" "$@"\n' "$dest" "$entry"
        fi
    } > "$wrapper" 2>/dev/null && chmod +x "$wrapper" || {
        log "WARN: could not write launcher $wrapper (need write access to $bindir); left as clone-only"
        return 0
    }

    log "$name installed; launcher: $wrapper"
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
