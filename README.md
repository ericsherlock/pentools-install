# pentools-install

**pentools-install** is a single Bash script that installs a curated, modern
set of **138 penetration-testing tools** across the major Linux distributions
and macOS. It auto-detects your package manager, installs each tool the *right*
way for your platform (native package when available, otherwise pipx / gem /
go / git / release binary), lets you pick which categories you want, and can
be re-run safely.

---

## Features

- **Multi-OS, auto-detected** — apt (Debian/Kali/Parrot), dnf (Fedora/RHEL),
  pacman (Arch/BlackArch), and Homebrew (macOS). No more picking your package
  manager by hand.
- **One unified manifest** — every tool is one row with per-OS package names
  and a cross-platform fallback. Native package wins; otherwise a working
  fallback (`pipx`, `gem`, `go`, `git`, or a release `binary`) is used.
- **PEP 668-safe** — Python tools install via **pipx**, so they work on modern
  distros that block system-wide `pip install`.
- **Category selection** — install everything, or just the categories you need,
  interactively or via flags.
- **Idempotent** — already-installed tools are detected and skipped; git tools
  update instead of failing on a second run.
- **Honest logging & summary** — every action is timestamped to `install_log`,
  and the run ends with an installed / skipped / failed / deselected tally.
- **Dry-run** — see exactly what *would* happen without touching your system.

---

## Supported platforms

| Package manager | Distros | Root required |
|-----------------|---------|:-------------:|
| `apt`    | Debian, Ubuntu, Kali, Parrot | yes |
| `dnf`    | Fedora, RHEL, Rocky, Alma     | yes |
| `pacman` | Arch, BlackArch, Manjaro      | yes |
| `brew`   | macOS (and Linuxbrew)         | no  |

> The `apt` column of the manifest targets **Kali/Debian** (many tools live only
> in Kali's repos), and the `pacman` column assumes the **BlackArch** repos are
> enabled. Fedora's security-tool coverage is thin, so many tools there install
> via `pipx`/`go`/`git` fallbacks. Where a tool isn't available on your platform
> at all, it is skipped with a note rather than failing.

---

## Usage

```bash
# Interactive: choose categories from a menu
sudo ./pentools_install            # Linux
./pentools_install                 # macOS (Homebrew — do NOT use sudo)

# Install everything, no prompts
sudo ./pentools_install --all --yes

# Only specific categories
sudo ./pentools_install --only recon,web,ad-lateral

# Everything except a few tools
sudo ./pentools_install --all --skip burpsuite,metasploit-framework

# See the plan without changing anything
./pentools_install --dry-run --all
```

### Options

| Flag | Description |
|------|-------------|
| `--all`           | Install every category (skips the menu). |
| `--only <cats>`   | Install only these categories (comma separated). |
| `--skip <tools>`  | Skip these tools by name (comma separated). |
| `--sample <N>`    | Install only the first N tools per selected category (0 = all). Used by the CI install-test smoke tier. |
| `--dry-run`       | Show what would be installed; make no changes. Needs no root. |
| `--yes`, `-y`     | Assume "yes"; install all categories if no `--only` is given. |
| `--list`          | List every tool in the manifest and exit. |
| `--categories`    | List categories with tool counts and exit. |
| `--help`, `-h`    | Show help and exit. |

---

## Categories

| Category | Tools | Examples |
|----------|:-----:|----------|
| `recon`        | 27 | nmap, masscan, subfinder, amass, httpx, gobuster |
| `web`          | 24 | ffuf, feroxbuster, nuclei, sqlmap, katana, wpscan |
| `wireless`     | 12 | aircrack-ng, wifite, kismet, bettercap, hcxtools |
| `ad-lateral`   | 14 | netexec, impacket, certipy, mitm6, bloodhound, kerbrute |
| `passwords`    | 10 | hashcat, john, hydra, medusa, name-that-hash |
| `forensics-re` | 17 | volatility3, radare2, ghidra, jadx, binwalk, pwntools |
| `osint`        | 10 | theharvester, spiderfoot, maigret, sherlock, shodan |
| `cloud`        |  7 | prowler, scoutsuite, pacu, trivy, cloud_enum |
| `vuln`         |  3 | lynis, gvm, chkrootkit |
| `exploitation` |  4 | metasploit-framework, exploitdb, setoolkit, beef-xss |
| `post-exploit` |  6 | chisel, ligolo-ng, sliver, mimikatz, powersploit |
| `wordlists`    |  2 | seclists, PayloadsAllTheThings |
| `base`         |  — | git, pipx (always installed — fallbacks depend on them) |

Run `./pentools_install --categories` for the live counts.

---

## How it works

1. **Detect** the OS, distribution, CPU architecture, and package manager
   (`lib/detect.sh`).
2. **Select** categories — from the interactive menu, or from `--only` / `--all`.
3. **Refresh** the package index once (`apt-get update`, `dnf makecache`,
   `pacman -Sy`, or `brew update`).
4. For each selected tool, **resolve** how to install it for your platform:
   - a real native package for your manager → install it natively (and if that
     install **fails** — e.g. a Kali-only name on plain Debian — automatically
     retry the tool's fallback);
   - otherwise the tool's **fallback** spec → `pipx` / `gem` / `go` / `git` /
     `binary`;
   - otherwise → **skip** with a note.
5. **Skip** anything already installed (idempotency check).
6. **Summarize**: `planned / ok / skipped / failed / deselected`, and where the
   log was written.

---

## The manifest

All tools live in [`tools.manifest`](tools.manifest), one per line:

```
name | category | method | apt | dnf | pacman | brew | fallback | check
```

- **name** — canonical name (also the default "already installed?" probe).
- **category** — one of the categories above.
- **method** — documents the canonical install path (`pkg`/`pipx`/`gem`/`go`/`git`/`binary`).
- **apt / dnf / pacman / brew** — native package name for that manager, or `-`
  if it isn't packaged there.
- **fallback** — used when there's no native package: `pipx:NAME`, `gem:NAME`,
  `go:MODULE@ver`, `git:URL`, or `binary:[BIN@]URL` (with `{os}`/`{arch}`
  placeholders).
- **check** — *optional* 9th field: an explicit command to test for "already
  installed", when the binary name differs from the tool name (e.g.
  `volatility3` → `vol`, `theharvester` → `theHarvester`).

### Adding or updating a tool

Add a row to `tools.manifest`. Fill in a native package name only where you
know it's correct for that manager; otherwise use `-` and provide a `fallback`
so the tool still installs everywhere. Example:

```
rustscan | recon | binary | - | - | rustscan | rustscan | binary:rustscan@https://github.com/bee-san/RustScan/releases/latest/download/rustscan-{arch}-{os}.tar.gz
```

Validate your change with:

```bash
./pentools_install --dry-run --all      # plan every tool, no changes
./pentools_install --list               # confirm the row parses
```

---

## Git-based tools

Tools installed from a git clone (when they aren't packaged for your manager)
land in `pentesting-tools/`. Where the manifest gives an entry point
(`git:URL::ENTRY`), the installer also:

- creates an isolated **venv** from the tool's `requirements.txt` (if present),
  so Python deps don't touch your system, and
- writes a small **launcher** onto `PATH` (`/usr/local/bin`, override with
  `PT_BINDIR`) so the tool is runnable by name.

Data sets (SecLists, PayloadsAllTheThings) and Windows/PowerShell tools
(Mimikatz, PowerSploit) are cloned only, and say so in the log.

---

## Logging

Every action is timestamped and written to `install_log` in the script
directory (override with `PT_LOGFILE`). Failed installs record the exact
command so you can re-run it by hand.

---

## Requirements

- One of: `apt` / `dnf` / `pacman` / `brew`.
- `bash`, `awk`, `git`, and core utilities.
- `python3` with `venv` for git-based Python tools (e.g. `python3-venv` on Debian).
- Root privileges for the native Linux managers (not for Homebrew).
- An internet connection.

---

## Continuous integration

Every push and PR runs [CI](.github/workflows/ci.yml):

- **ShellCheck** — full report, with a hard gate on errors.
- **Syntax** — `bash -n` across all scripts.
- **Manifest integrity** — every row has a valid field count.
- **Dry-run matrix** — a full `--dry-run --all` inside `debian`, `fedora`, and
  `archlinux` containers.

A separate [Install Test](.github/workflows/install-test.yml) workflow does
**real** installs (not dry-run), sharded `target × category` across Kali,
Debian, Fedora, Arch+BlackArch, and macOS, gated on the installer reporting
`failed=0`. It runs weekly (and on demand via the Actions tab) with a
**smoke** tier (one tool per category, the default) or a **full** tier (every
tool). Free on this public repo.

---

## Disclaimer

This script is intended for **authorized** penetration testing and security
research only. Many of the included tools are dual-use; use them only against
systems you own or have explicit written permission to test.

---

## License

MIT License.

---

## Credits

Tool selection informed by the Kali, BlackArch, and Homebrew security
ecosystems. Thanks to the maintainers of every included project.
