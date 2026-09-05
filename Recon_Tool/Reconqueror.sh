#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════
#  Reconqueror  —  Parallel Recon Framework
#  Authorized security testing use only.
# ══════════════════════════════════════════════════════════════════════════
#
#  OUTPUT STRUCTURE
#    output/<target>/<timestamp>/{raw,parsed,ports,urls,nuclei,
#                                  screenshots,reports,logs,.state}/
#    raw/ keeps every tool's unmodified output for debugging; reports/
#    are built only from cleaned, deduplicated data.
#

# ══════════════════════════════════════════════════════════════════════════

set -Eeuo pipefail
# NOTE: deliberately NOT setting IFS=$'\n\t' here. Several places in this
# script rely on default word-splitting (space/tab/newline) for
# space-separated lists — task dependency strings ("a b c"), `for rtype in
# A AAAA MX ...`, etc. A custom IFS silently breaks those. Values that need
# exact-token safety are quoted explicitly instead.

SCRIPT_NAME="Reconqueror"
SCRIPT_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"

have_cmd() { command -v "$1" >/dev/null 2>&1; }
# ══════════════════════════════════════════════════════════════════════════
#  CONFIGURATION
#  Precedence (highest wins): CLI flags > --config file > ./recon.conf
#  (if present in CWD) > the defaults below.
# ══════════════════════════════════════════════════════════════════════════

# ── Module toggles ─────────────────────────────────────────────
CFG_WHOIS=true
CFG_DNS=true
CFG_TARGET_INFO=true          # ASN/org/country/CDN/reverse-DNS lookup
CFG_SECURITY_HEADERS=true     # headers, robots.txt, sitemap.xml, TLS summary
CFG_THEHARVESTER=true
CFG_CRTSH=true
CFG_ASSETFINDER=true
CFG_AMASS=true
CFG_AMASS_ACTIVE_BRUTE=false  # amass active + brute-force with a wordlist (noisy, off by default)
CFG_DNSRECON=true
CFG_WAF_DETECT=true
CFG_TECH_DETECT=true
CFG_PORT_SCAN=true
CFG_WAYBACK=true
CFG_SCREENSHOTS=false         # off by default: needs headless chrome via httpx, slow
CFG_NUCLEI=true
CFG_JS_SCAN=true

# ── Report formats ────────────────────────────────────────────
# Only txt+html by default — set to true (or --enable) if you also want
# markdown/json copies of the same report data.
CFG_REPORT_MD=false
CFG_REPORT_JSON=false
CFG_REPORT_HTML=true

# ── Output filtering ────────────────────────────────────────────
CFG_KEEP_ALL_URLS=false       # true = skip liveness filtering entirely
CFG_FILTER_403=true           # true = drop 403s too (in addition to 404/410/400)

# ── Performance ──────────────────────────────────────────────────
CFG_MAX_PARALLEL=8            # max concurrent top-level tasks
CFG_THREADS=50                # thread/concurrency hint passed to httpx/nuclei/curl-xargs
CFG_NUCLEI_RATE_LIMIT=150     # requests/sec cap passed to nuclei
CFG_NUCLEI_SEVERITY="low,medium,high,critical"
CFG_RETRY_COUNT=1             # retries for transient (network) task failures
CFG_DASHBOARD_TICK=0.2        # seconds between dashboard redraws

# ── Scan mode ────────────────────────────────────────────────────
# "full": every enabled module runs, capped at CFG_TOOL_TIMEOUT each so a
#         single slow tool can never run away unbounded.
# "fast": the historically-slowest modules (nuclei, amass, wayback/js) are
#         skipped outright, whatweb/assetfinder/nmap get a much shorter
#         timeout, and nmap skips its -sV/-sC service-detection pass.
# Set directly to skip the interactive prompt; -y with neither --fast nor
# --full given defaults to "full" (least surprise for scripted/CI use).
CFG_SCAN_MODE=""               # "" | "fast" | "full"
CFG_TOOL_TIMEOUT=240           # per-tool ceiling (seconds) in full mode
CFG_FAST_TOOL_TIMEOUT=30       # per-tool ceiling (seconds) in fast mode
TOOL_TIMEOUT="$CFG_TOOL_TIMEOUT"  # actual ceiling used at runtime; resolve_scan_mode sets this properly

# ── Behaviour ────────────────────────────────────────────────────
CFG_CONNECTIVITY_CHECK=true
CFG_AUTO_INSTALL="prompt"     # prompt | yes | no
CFG_LOG_LEVEL="normal"        # quiet | normal | verbose | debug
CFG_COLOR="auto"              # auto | always | never
CFG_OUTPUT_ROOT="output"
CFG_WORDLIST=""               # only used when CFG_AMASS_ACTIVE_BRUTE=true

# Populated by CLI parsing later; declared here so `set -u` never trips on them.
TARGET=""
TARGET_LIST_FILE=""
CONFIG_FILE=""
RESUME_DIR=""
RESUME_REQUESTED=false
ASSUME_YES=false
EXPLICIT_OUTDIR=""

# Config keys that MUST be a plain positive integer if set — anything else
# in one of these fields is almost certainly a typo in the user's config
# file, and silently misusing it (e.g. inside arithmetic) could produce
# confusing downstream errors, so it's validated right after loading.
declare -a CFG_INT_KEYS=(CFG_MAX_PARALLEL CFG_THREADS CFG_NUCLEI_RATE_LIMIT CFG_RETRY_COUNT)

# Load a `KEY=value` config file. Deliberately simple (source-based) rather
# than a hand-rolled parser: it's the standard, well-understood pattern for
# shell tool config (.env, .bashrc, etc.) and lets users comment freely.
# NOTE: a config file is trusted input the user creates themselves, sourced
# the same way a .bashrc is — don't point --config at a file you didn't
# write, same as you wouldn't source an untrusted .bashrc.
load_config_file() {
    local file="$1"
    if [[ ! -f "$file" ]]; then
        log_error "Config file not found: $file"
        return 1
    fi
    # shellcheck disable=SC1090
    if ! source "$file"; then
        log_error "Failed to load config file: $file"
        return 1
    fi
    log_debug "Loaded config: $file"
    return 0
}

validate_config() {
    local key val ok=1
    for key in "${CFG_INT_KEYS[@]}"; do
        val="${!key}"
        if ! [[ "$val" =~ ^[0-9]+$ ]] || [[ "$val" -lt 1 ]]; then
            log_error "Config ${key}='${val}' must be a positive integer — using default."
            ok=0
        fi
    done
    [[ "$ok" -eq 1 ]] || return 1
    return 0
}

# Write the effective config actually used for this run into .state/, so a
# resumed or re-run scan is auditable ("what settings produced this data").
snapshot_config() {
    local outfile="$1" key
    {
        printf '# Effective configuration — %s\n' "$(date '+%Y-%m-%d %H:%M:%S')"
        for key in "${!CFG_@}"; do
            printf '%s=%s\n' "$key" "${!key}"
        done
    } > "$outfile" 2>/dev/null || true
    return 0
}
# ══════════════════════════════════════════════════════════════════════════
#  COLORS, LOGGING, TERMINAL PRIMITIVES
# ══════════════════════════════════════════════════════════════════════════

# ── Color resolution: CFG_COLOR (auto/always/never) + TTY + NO_COLOR ──────
_color_enabled() {
    case "$CFG_COLOR" in
        never) return 1 ;;
        always) return 0 ;;
    esac
    [[ -n "${NO_COLOR:-}" ]] && return 1
    [[ -t 1 ]] || return 1
    return 0
}

if _color_enabled; then
    RED=$'\e[1;91m'; GREEN=$'\e[1;92m'; YELLOW=$'\e[1;93m'
    BLUE=$'\e[1;94m'; MAGENTA=$'\e[1;95m'; CYAN=$'\e[1;96m'
    DIM=$'\e[2m'; BOLD=$'\e[1m'; RESET=$'\e[0m'
    COLOR_ENABLED=true
else
    RED=""; GREEN=""; YELLOW=""; BLUE=""; MAGENTA=""; CYAN=""; DIM=""; BOLD=""; RESET=""
    COLOR_ENABLED=false
fi

# ── Log level: quiet=0 normal=1 verbose=2 debug=3 ──────────────────────────
_log_level_num() {
    case "$CFG_LOG_LEVEL" in
        quiet) echo 0 ;;
        verbose) echo 2 ;;
        debug) echo 3 ;;
        *) echo 1 ;;
    esac
}
LOG_LEVEL_NUM="$(_log_level_num)"

# Set to real paths once OUTDIR exists (see setup_output_dirs); safe no-ops
# before that so early CLI-parsing errors can still call these.
SESSION_LOG=""
ERROR_LOG_PATH=""

_ts() { date '+%Y-%m-%d %H:%M:%S'; }

_log_to_session() {
    [[ -n "$SESSION_LOG" ]] || return 0
    printf '[%s] %s\n' "$(_ts)" "$1" >> "$SESSION_LOG" 2>/dev/null || true
    return 0
}

log_info() {
    _log_to_session "INFO  $1"
    [[ "$LOG_LEVEL_NUM" -ge 1 ]] || return 0
    clear_live_status_line
    printf '%s[i]%s %s\n' "$CYAN" "$RESET" "$1"
    return 0
}

log_warn() {
    _log_to_session "WARN  $1"
    [[ "$LOG_LEVEL_NUM" -ge 1 ]] || return 0
    clear_live_status_line
    printf '%s[!]%s %s\n' "$YELLOW" "$RESET" "$1" >&2
    return 0
}

log_error() {
    _log_to_session "ERROR $1"
    if [[ -n "$ERROR_LOG_PATH" ]]; then
        printf '[%s] %s\n' "$(_ts)" "$1" >> "$ERROR_LOG_PATH" 2>/dev/null || true
    fi
    clear_live_status_line
    printf '%s[✗]%s %s\n' "$RED" "$RESET" "$1" >&2
    return 0
}

log_debug() {
    _log_to_session "DEBUG $1"
    [[ "$LOG_LEVEL_NUM" -ge 3 ]] || return 0
    clear_live_status_line
    printf '%s[~] %s%s\n' "$DIM" "$1" "$RESET"
    return 0
}

log_ok() {
    _log_to_session "OK    $1"
    [[ "$LOG_LEVEL_NUM" -ge 1 ]] || return 0
    clear_live_status_line
    printf '%s[✓]%s %s\n' "$GREEN" "$RESET" "$1"
    return 0
}

# Real implementation is defined later (dashboard section) and overwrites
# this stub before anything ever calls it in earnest; the stub just keeps
# early log_* calls safe under `set -u` if something logs before that
# section of the script has executed.
clear_live_status_line() { return 0; }

# ── Terminal geometry ───────────────────────────────────────────────────
TERM_COLS=80
if have_cmd tput && [[ -t 1 ]]; then
    _tc="$(tput cols 2>/dev/null || echo 80)"
    if [[ "$_tc" =~ ^[0-9]+$ ]]; then
        TERM_COLS="$_tc"
    fi
fi
# Clip the dashboard/report console width to something safe on both narrow
# terminals and ultra-wide ones (very long lines are just as hard to scan).
PANEL_WIDTH=$(( TERM_COLS < 60 ? TERM_COLS : (TERM_COLS > 100 ? 100 : TERM_COLS) ))
[[ "$PANEL_WIDTH" -lt 40 ]] && PANEL_WIDTH=40

# Truncate-and-pad a string to exactly N columns (keeps dashboard redraws
# aligned even when a label or value's length varies between frames).
clip() {
    local s="$1" w="$2"
    printf '%-*.*s' "$w" "$w" "$s"
    return 0
}

# UI_MODE is resolved once, after CLI parsing, in resolve_ui_mode (part09/main)
# because it depends on both CFG_LOG_LEVEL and whether stdout is a TTY.
UI_MODE="plain"

SPIN_FRAMES=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')
SPIN_INDEX=0
next_spin_frame() {
    local f="${SPIN_FRAMES[$SPIN_INDEX]}"
    SPIN_INDEX=$(( (SPIN_INDEX + 1) % ${#SPIN_FRAMES[@]} ))
    echo "$f"
    return 0
}

status_icon() {
    local status="$1"
    case "$status" in
        done)    printf '%s✓%s' "$GREEN" "$RESET" ;;
        failed)  printf '%s✗%s' "$RED" "$RESET" ;;
        running) printf '%s%s%s' "$YELLOW" "$(next_spin_frame)" "$RESET" ;;
        skipped) printf '%s-%s' "$DIM" "$RESET" ;;
        *)       printf '%s %s' "$DIM" "$RESET" ;;
    esac
    return 0
}
# ══════════════════════════════════════════════════════════════════════════
#  UTILITIES
# ══════════════════════════════════════════════════════════════════════════

# (have_cmd is defined at the very top of the script — part02/UI needs it
# before this section loads.)

# Locate a tool even if it's only in a Go bin dir that isn't on PATH yet.
find_tool_path() {
    local tool="$1"
    if have_cmd "$tool"; then
        command -v "$tool"
        return 0
    fi
    local candidate
    for candidate in "$HOME/go/bin/$tool" "/usr/local/go/bin/$tool"; do
        if [[ -x "$candidate" ]]; then
            echo "$candidate"
            return 0
        fi
    done
    return 1
}

is_ip_address() {
    local s="$1"
    [[ "$s" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    local IFS='.' octet
    for octet in $s; do
        [[ "$octet" -le 255 ]] || return 1
    done
    return 0
}

is_valid_hostname() {
    local h="$1"
    [[ "${#h}" -le 253 ]] || return 1
    [[ "$h" =~ ^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$ ]]
}

is_valid_url() {
    local u="$1"
    [[ "$u" =~ ^https?://[a-zA-Z0-9.-]+(:[0-9]{1,5})?(/[^[:space:]]*)?$ ]]
}

# True if $1 is the target itself or a subdomain of it.
belongs_to_domain() {
    local host="$1" domain="$2"
    [[ "$host" == "$domain" || "$host" == *".${domain}" ]]
}

# Retry a command up to N times with linear backoff. Used for network calls
# that occasionally hiccup (crt.sh, ip-api.com) rather than tools that fail
# deterministically (a missing binary won't succeed on attempt 2).
retry_cmd() {
    local max="$1"; shift
    local attempt=1 rc=0
    while true; do
        set +e
        "$@"
        rc=$?
        set -e
        if [[ "$rc" -eq 0 ]]; then
            return 0
        fi
        if [[ "$attempt" -ge "$max" ]]; then
            return "$rc"
        fi
        sleep "$attempt"
        attempt=$(( attempt + 1 ))
    done
}

# Blank-line strip + whitespace trim + sort -u, in place. Safe on missing
# or empty files (recon commonly produces zero-result files).
clean_list_file() {
    local file="$1"
    [[ -f "$file" ]] || return 0
    local tmp
    tmp="$(mktemp)"
    grep -v '^[[:space:]]*$' "$file" 2>/dev/null \
        | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//' \
        | sort -u > "$tmp" || true
    mv "$tmp" "$file"
    return 0
}

# Filter a raw subdomain candidate list down to entries that are valid
# hostnames AND actually belong to the target domain (drops garbage lines
# tool output sometimes mixes in — banners, "[INF]" prefixes, etc.).
filter_valid_subdomains() {
    local infile="$1" outfile="$2" domain="$3"
    : > "$outfile"
    [[ -s "$infile" ]] || return 0
    local line
    while IFS= read -r line; do
        line="${line#\*.}"
        line="${line,,}"
        if is_valid_hostname "$line" && belongs_to_domain "$line" "$domain"; then
            echo "$line" >> "$outfile"
        fi
    done < "$infile"
    clean_list_file "$outfile"
    return 0
}

# Filter a raw URL candidate list down to well-formed http(s) URLs.
filter_valid_urls() {
    local infile="$1" outfile="$2"
    : > "$outfile"
    [[ -s "$infile" ]] || return 0
    local line
    while IFS= read -r line; do
        if is_valid_url "$line"; then
            echo "$line" >> "$outfile"
        fi
    done < "$infile"
    clean_list_file "$outfile"
    return 0
}

extract_emails_from_dir() {
    local dir="$1" outfile="$2"
    grep -rhEo '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' "$dir" 2>/dev/null \
        | sort -u > "$outfile" || true
    return 0
}

# Best-effort internet reachability check. Tries a couple of independent
# endpoints so a single provider's outage doesn't produce a false negative.
check_connectivity() {
    local ok=1
    if have_cmd curl; then
        if curl -s --max-time 5 -o /dev/null -w '%{http_code}' https://1.1.1.1 2>/dev/null | grep -qE '^[23]'; then
            ok=0
        elif curl -s --max-time 5 -o /dev/null https://dns.google 2>/dev/null; then
            ok=0
        fi
    fi
    return "$ok"
}

# Resolve a hostname to its first A record; if the target is already an IP,
# echo it straight back. Used by target_info / security_headers tasks.
resolve_to_ip() {
    local target="$1"
    if is_ip_address "$target"; then
        echo "$target"
        return 0
    fi
    if have_cmd dig; then
        local ip
        ip="$(dig +short "$target" A 2>/dev/null | grep -E '^[0-9]+\.' | head -1 || true)"
        if [[ -n "$ip" ]]; then
            echo "$ip"
            return 0
        fi
    fi
    if have_cmd getent; then
        local ip
        ip="$(getent ahostsv4 "$target" 2>/dev/null | head -1 | awk '{print $1}' || true)"
        if [[ -n "$ip" ]]; then
            echo "$ip"
            return 0
        fi
    fi
    return 1
}

human_duration() {
    local secs="$1" m s
    secs="${secs%.*}"
    [[ "$secs" =~ ^[0-9]+$ ]] || secs=0
    m=$(( secs / 60 ))
    s=$(( secs % 60 ))
    printf '%02dm %02ds' "$m" "$s"
    return 0
}

# Minimal dependency-free JSON string-field extractor (flat JSON only —
# enough for ip-api.com style responses without requiring jq).
json_field() {
    local json="$1" field="$2"
    echo "$json" | grep -oE "\"${field}\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" \
        | head -1 | sed -E 's/.*:[[:space:]]*"([^"]*)"/\1/' || true
    return 0
}
# ══════════════════════════════════════════════════════════════════════════
#  DEPENDENCY CHECKING + INSTALLATION
# ══════════════════════════════════════════════════════════════════════════

# Maps a config toggle to the tool it needs. Only enabled modules are
# checked/installed — no point nagging about nuclei if CFG_NUCLEI=false.
declare -A MODULE_TOOL_MAP=(
    [CFG_WHOIS]="whois"
    [CFG_DNS]="dig"
    [CFG_THEHARVESTER]="theHarvester"
    [CFG_ASSETFINDER]="assetfinder"
    [CFG_AMASS]="amass"
    [CFG_DNSRECON]="dnsrecon"
    [CFG_WAF_DETECT]="wafw00f"
    [CFG_TECH_DETECT]="whatweb"
    [CFG_PORT_SCAN]="nmap"
    [CFG_WAYBACK]="waybackurls"
    [CFG_NUCLEI]="nuclei"
)
# Always useful regardless of module toggles; degrade gracefully, not required.
declare -a OPTIONAL_TOOLS=(httpx httprobe jq figlet openssl parallel)

install_single_tool() {
    local tool="$1" rc=0
    set +e
    case "$tool" in
        nmap)         sudo apt-get install -y -qq nmap         2>/dev/null ;;
        whois)        sudo apt-get install -y -qq whois        2>/dev/null ;;
        dig)          sudo apt-get install -y -qq dnsutils     2>/dev/null ;;
        theHarvester|theharvester)
                      sudo apt-get install -y -qq theharvester 2>/dev/null ;;
        amass)        sudo apt-get install -y -qq amass        2>/dev/null ;;
        whatweb)      sudo apt-get install -y -qq whatweb      2>/dev/null ;;
        wafw00f)      sudo apt-get install -y -qq wafw00f      2>/dev/null ;;
        dnsrecon)     sudo apt-get install -y -qq dnsrecon     2>/dev/null ;;
        figlet)       sudo apt-get install -y -qq figlet       2>/dev/null ;;
        curl)         sudo apt-get install -y -qq curl         2>/dev/null ;;
        jq)           sudo apt-get install -y -qq jq           2>/dev/null ;;
        parallel)     sudo apt-get install -y -qq parallel     2>/dev/null ;;
        subfinder)    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null ;;
        httpx)        go install github.com/projectdiscovery/httpx/cmd/httpx@latest            2>/dev/null ;;
        httprobe)     go install github.com/tomnomnom/httprobe@latest                          2>/dev/null ;;
        nuclei)       go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest       2>/dev/null ;;
        waybackurls)  go install github.com/tomnomnom/waybackurls@latest                       2>/dev/null ;;
        assetfinder)  go install github.com/tomnomnom/assetfinder@latest                       2>/dev/null ;;
        *)            false ;;
    esac
    rc=$?
    set -e
    return "$rc"
}

ensure_go_path_exported() {
    if have_cmd go; then
        local gopath
        gopath="$(go env GOPATH 2>/dev/null || echo "$HOME/go")"
        export PATH="$PATH:${gopath}/bin:$HOME/go/bin"
    fi
    return 0
}

# Returns the list of tool names required by currently-enabled modules
# (deduplicated) on stdout, one per line.
required_tools_for_enabled_modules() {
    local key tool
    for key in "${!MODULE_TOOL_MAP[@]}"; do
        if [[ "${!key}" == "true" ]]; then
            tool="${MODULE_TOOL_MAP[$key]}"
            echo "$tool"
        fi
    done | sort -u
    return 0
}

# For each enabled module whose tool is STILL missing after the install
# step (or install was declined), flip its CFG_ flag off so downstream
# task registration marks it "skipped" instead of letting it fail later.
disable_modules_with_missing_tools() {
    local key tool
    for key in "${!MODULE_TOOL_MAP[@]}"; do
        [[ "${!key}" == "true" ]] || continue
        tool="${MODULE_TOOL_MAP[$key]}"
        if ! find_tool_path "$tool" >/dev/null 2>&1; then
            printf -v "$key" '%s' "false"
            log_warn "${tool} not available — disabling this module for this run."
        fi
    done
    return 0
}

check_tools() {
    local -a required missing=()
    mapfile -t required < <(required_tools_for_enabled_modules)

    if [[ "$UI_MODE" != "plain" ]]; then
        printf '%s[!] Checking required tools...%s\n\n' "$YELLOW" "$RESET"
    fi

    local tool current=0 total="${#required[@]}"
    for tool in "${required[@]}"; do
        current=$(( current + 1 ))
        if find_tool_path "$tool" >/dev/null 2>&1; then
            if [[ "$UI_MODE" != "plain" ]]; then
                printf "  [%2d/%2d] %-20s %sfound%s\n" "$current" "$total" "$tool" "$GREEN" "$RESET"
            fi
        else
            if [[ "$UI_MODE" != "plain" ]]; then
                printf "  [%2d/%2d] %-20s %smissing%s\n" "$current" "$total" "$tool" "$RED" "$RESET"
            fi
            missing+=("$tool")
        fi
    done

    if [[ "$UI_MODE" != "plain" ]]; then
        printf '\n%s  Optional tools:%s\n' "$CYAN" "$RESET"
        for tool in "${OPTIONAL_TOOLS[@]}"; do
            if find_tool_path "$tool" >/dev/null 2>&1; then
                printf "    %-20s %savailable%s\n" "$tool" "$GREEN" "$RESET"
            else
                printf "    %-20s %snot installed (optional)%s\n" "$tool" "$YELLOW" "$RESET"
            fi
        done
        echo
    fi

    if [[ "${#missing[@]}" -eq 0 ]]; then
        log_ok "All required tools for enabled modules are present."
        return 0
    fi

    log_warn "Missing (${#missing[@]}): ${missing[*]}"

    local do_install=false
    case "$CFG_AUTO_INSTALL" in
        yes) do_install=true ;;
        no)  do_install=false ;;
        *)
            if [[ "$ASSUME_YES" == "true" || "$UI_MODE" == "plain" ]]; then
                do_install=true
            else
                local yn
                read -rp "  Install missing tools now? [Y/n]: " yn
                yn="${yn:-Y}"
                if [[ "$yn" =~ ^[Yy]$ ]]; then
                    do_install=true
                fi
            fi
            ;;
    esac

    if [[ "$do_install" != "true" ]]; then
        log_warn "Skipping install. Affected modules will be disabled for this run."
        disable_modules_with_missing_tools
        return 0
    fi

    if ! have_cmd go; then
        log_info "Installing golang-go (prerequisite for Go-based tools)"
        sudo apt-get update -qq 2>/dev/null || true
        sudo apt-get install -y -qq golang-go 2>/dev/null || true
        hash -r 2>/dev/null || true
    fi
    ensure_go_path_exported
    sudo apt-get update -qq 2>/dev/null || true

    local count=0 total_m="${#missing[@]}"
    for tool in "${missing[@]}"; do
        count=$(( count + 1 ))
        printf "  [%d/%d] Installing %-18s ... " "$count" "$total_m" "$tool"
        if install_single_tool "$tool"; then
            printf '%s✓%s\n' "$GREEN" "$RESET"
        else
            printf '%s✗ (no install rule / failed — may need manual install)%s\n' "$RED" "$RESET"
        fi
    done
    hash -r 2>/dev/null || true
    log_ok "Installation step complete."

    local nuclei_bin
    nuclei_bin="$(find_tool_path nuclei || true)"
    if [[ -n "$nuclei_bin" ]]; then
        log_info "Fetching nuclei template updates"
        "$nuclei_bin" -update-templates -silent >/dev/null 2>&1 || true
    fi

    disable_modules_with_missing_tools
    return 0
}
# ══════════════════════════════════════════════════════════════════════════
#  TASK ENGINE  —  dependency-graph scheduler + live dashboard
#
#  Convention followed throughout this section (see header comment for the
#  full "why"): every function that runs in the main shell either (a) never
#  ends on a bare `cond && action` / `cond || action` whose action might be
#  its last executed statement, or (b) is a deliberate boolean predicate
#  ALWAYS called from an if/while/&&/|| condition, never bare. Functions in
#  category (a) end with an explicit `return 0`.
# ══════════════════════════════════════════════════════════════════════════

declare -a TASK_ORDER=()
declare -A TASK_LABEL=() TASK_DEPS=() TASK_ENABLED=() TASK_FUNC=() TASK_OUTFILE=()
declare -A TASK_STATUS=() TASK_PID=() TASK_START=() TASK_END=() TASK_ATTEMPTS=()
declare -A TASK_PREV_STATUS=()

STATUS_DIR=""       # $OUTDIR/.state/exit_codes  (per-task exit-code files)
TASK_LOG_DIR=""      # $OUTDIR/logs/tasks         (per-task wrapper logs)
STATE_FILE=""        # $OUTDIR/.state/tasks.state (persisted for --resume)
LOCK_FILE=""
LIVE_STATUS_ACTIVE=false
RUN_START_TS=""
CURRENT_TARGET=""

now_ts() { date +%s.%N; }

# ── Registration ─────────────────────────────────────────────────────────
# outfile is the task's primary output file, used both to sanity-check a
# resumed "done" status (file must exist and be non-empty) and by report
# generation. Pass "" for tasks with no single canonical output file.
register_task() {
    local name="$1" label="$2" deps="$3" func="$4" outfile="$5" enabled="${6:-1}"
    TASK_ORDER+=("$name")
    TASK_LABEL["$name"]="$label"
    TASK_DEPS["$name"]="$deps"
    TASK_FUNC["$name"]="$func"
    TASK_OUTFILE["$name"]="$outfile"
    TASK_ENABLED["$name"]="$enabled"
    TASK_STATUS["$name"]="pending"
    return 0
}

# Every dep must reference a registered task, and the graph must be acyclic.
# Both are programmer errors (in this script, not user input), so they abort
# immediately with a clear message rather than deadlocking silently.
declare -A _VISIT_STATE=()
_dfs_check_cycle() {
    local name="$1" dep
    case "${_VISIT_STATE[$name]:-white}" in
        gray)  log_error "Dependency cycle detected involving task '${name}'."; return 1 ;;
        black) return 0 ;;
    esac
    _VISIT_STATE["$name"]="gray"
    for dep in ${TASK_DEPS[$name]}; do
        if ! _dfs_check_cycle "$dep"; then
            return 1
        fi
    done
    _VISIT_STATE["$name"]="black"
    return 0
}

validate_task_graph() {
    local name dep
    for name in "${TASK_ORDER[@]}"; do
        for dep in ${TASK_DEPS[$name]}; do
            if [[ -z "${TASK_LABEL[$dep]:-}" ]]; then
                log_error "Internal error: task '${name}' depends on unknown task '${dep}'."
                exit 1
            fi
        done
    done
    for name in "${TASK_ORDER[@]}"; do
        if ! _dfs_check_cycle "$name"; then
            log_error "Internal error: task graph has a cycle. Aborting."
            exit 1
        fi
    done
    return 0
}

deps_satisfied() {
    local name="$1" dep
    for dep in ${TASK_DEPS[$name]}; do
        case "${TASK_STATUS[$dep]:-missing}" in
            done|failed|skipped) : ;;
            *) return 1 ;;
        esac
    done
    return 0
}

# ── State persistence (resume support) ─────────────────────────────────
persist_state() {
    if [[ -z "$STATE_FILE" ]]; then
        return 0
    fi
    local tmp name
    tmp="$(mktemp)"
    for name in "${TASK_ORDER[@]}"; do
        printf '%s=%s\n' "$name" "${TASK_STATUS[$name]}" >> "$tmp"
    done
    mv "$tmp" "$STATE_FILE" 2>/dev/null || true
    return 0
}

load_state_for_resume() {
    local file="$1"
    if [[ ! -f "$file" ]]; then
        return 0
    fi
    local name status outfile
    while IFS='=' read -r name status; do
        if [[ -z "$name" || -z "${TASK_LABEL[$name]:-}" ]]; then
            continue
        fi
        if [[ "$status" == "done" && "${TASK_ENABLED[$name]}" == "1" ]]; then
            outfile="${TASK_OUTFILE[$name]:-}"
            if [[ -z "$outfile" || -s "$outfile" ]]; then
                TASK_STATUS["$name"]="done"
                log_debug "Resume: '${name}' already complete — skipping."
            else
                log_debug "Resume: '${name}' was marked done but output is missing — will re-run."
            fi
        fi
    done < "$file"
    return 0
}

# ── Scheduling ────────────────────────────────────────────────────────────
launch_task() {
    local name="$1"
    TASK_STATUS["$name"]="running"
    TASK_START["$name"]="$(now_ts)"
    if [[ -z "${TASK_ATTEMPTS[$name]:-}" ]]; then
        TASK_ATTEMPTS["$name"]=1
    fi
    (
        set +e
        trap - ERR
        "${TASK_FUNC[$name]}" "$name" > "${TASK_LOG_DIR}/${name}.log" 2>&1
        rc=$?
        echo "$rc" > "${STATUS_DIR}/${name}.exit"
        exit 0
    ) &
    TASK_PID["$name"]=$!
    persist_state
    return 0
}

reap_tasks() {
    local name rc attempts
    for name in "${TASK_ORDER[@]}"; do
        if [[ "${TASK_STATUS[$name]}" != "running" ]]; then
            continue
        fi
        if [[ -f "${STATUS_DIR}/${name}.exit" ]]; then
            rc="$(<"${STATUS_DIR}/${name}.exit")"
        elif ! kill -0 "${TASK_PID[$name]}" 2>/dev/null; then
            # The subshell process is gone but never wrote its exit marker —
            # it died abnormally (e.g. a nounset/-u fatal error before
            # reaching the marker write). Without this check the scheduler
            # would wait forever on a task that can never report in.
            rc=199
            log_debug "Task '${name}' subshell exited without reporting a status — treating as failed."
        else
            continue
        fi
        wait "${TASK_PID[$name]}" 2>/dev/null || true
        rm -f "${STATUS_DIR}/${name}.exit" 2>/dev/null || true
        TASK_END["$name"]="$(now_ts)"
        if [[ "$rc" -eq 0 ]]; then
            TASK_STATUS["$name"]="done"
        else
            attempts="${TASK_ATTEMPTS[$name]:-1}"
            if [[ "$attempts" -lt "$CFG_RETRY_COUNT" ]]; then
                TASK_ATTEMPTS["$name"]=$(( attempts + 1 ))
                TASK_STATUS["$name"]="pending"
                log_debug "Task '${name}' failed (exit $rc) — retrying (attempt $(( attempts + 1 ))/${CFG_RETRY_COUNT})"
            else
                TASK_STATUS["$name"]="failed"
                log_error "Task '${name}' failed after ${attempts} attempt(s) (exit $rc) — see logs/tasks/${name}.log"
            fi
        fi
        persist_state
    done
    return 0
}

current_running_count() {
    local name c=0
    for name in "${TASK_ORDER[@]}"; do
        if [[ "${TASK_STATUS[$name]}" == "running" ]]; then
            c=$(( c + 1 ))
        fi
    done
    echo "$c"
    return 0
}

schedule_ready_tasks() {
    local name running_count
    running_count="$(current_running_count)"
    for name in "${TASK_ORDER[@]}"; do
        if [[ "$running_count" -ge "$CFG_MAX_PARALLEL" ]]; then
            break
        fi
        if [[ "${TASK_STATUS[$name]}" != "pending" ]]; then
            continue
        fi
        if [[ "${TASK_ENABLED[$name]}" != "1" ]]; then
            TASK_STATUS["$name"]="skipped"
            persist_state
            continue
        fi
        if deps_satisfied "$name"; then
            launch_task "$name"
            running_count=$(( running_count + 1 ))
        fi
    done
    return 0
}

all_terminal() {
    local name
    for name in "${TASK_ORDER[@]}"; do
        case "${TASK_STATUS[$name]}" in
            done|failed|skipped) : ;;
            *) return 1 ;;
        esac
    done
    return 0
}

run_task_graph() {
    RUN_START_TS="$(now_ts)"
    while true; do
        reap_tasks
        schedule_ready_tasks
        render_dashboard
        if all_terminal; then
            break
        fi
        sleep "$CFG_DASHBOARD_TICK"
    done
    render_dashboard
    return 0
}

# ── Dashboard ─────────────────────────────────────────────────────────────
human_task_duration() {
    local name="$1" start end
    start="${TASK_START[$name]:-}"
    if [[ -z "$start" ]]; then
        echo "--"
        return 0
    fi
    if [[ -n "${TASK_END[$name]:-}" ]]; then
        end="${TASK_END[$name]}"
    else
        end="$(now_ts)"
    fi
    awk -v s="$start" -v e="$end" 'BEGIN{d=e-s; if(d<0)d=0; if(d<10) printf "%.1fs", d; else printf "%ds", d}'
    return 0
}

render_dashboard() {
    if [[ "$UI_MODE" == "plain" ]]; then
        render_dashboard_plain
    else
        render_dashboard_live
    fi
    return 0
}

render_dashboard_plain() {
    local name st
    for name in "${TASK_ORDER[@]}"; do
        st="${TASK_STATUS[$name]}"
        if [[ "${TASK_PREV_STATUS[$name]:-}" != "$st" ]]; then
            case "$st" in
                running) log_info  "${TASK_LABEL[$name]} — started" ;;
                done)    log_ok    "${TASK_LABEL[$name]} — done ($(human_task_duration "$name"))" ;;
                failed)  log_error "${TASK_LABEL[$name]} — failed" ;;
                skipped) log_debug "${TASK_LABEL[$name]} — skipped" ;;
            esac
            TASK_PREV_STATUS["$name"]="$st"
        fi
    done
    return 0
}

# Live-mode redraw strategy, deliberately NOT using multi-line cursor
# positioning (tput cuu/ed): that requires the terminal's line-count math to
# stay perfectly in sync with what was actually printed, and plenty of real
# terminals (this is what happened on Windows/Git-Bash) don't honor it the
# same way — instead of redrawing in place, the whole panel just reprints
# itself every tick. Instead:
#   - each task prints exactly ONE permanent line, once, when it reaches a
#     final state (done/failed/skipped) — plain scrolling output, which
#     works identically on every terminal ever made.
#   - a single ticking summary line (progress bar + counts + elapsed) is
#     redrawn in place using only `\r` + `tput el` (erase-to-end-of-line),
#     a single-line operation that's supported essentially everywhere,
#     unlike multi-line cursor repositioning.
clear_live_status_line() {
    if [[ "$LIVE_STATUS_ACTIVE" == "true" ]]; then
        printf '\r'
        tput el 2>/dev/null || printf '%*s\r' "$PANEL_WIDTH" ''
        LIVE_STATUS_ACTIVE=false
    fi
    return 0
}

render_dashboard_live() {
    local name st label_p dur_p icon_char

    for name in "${TASK_ORDER[@]}"; do
        st="${TASK_STATUS[$name]}"
        if [[ "${TASK_PREV_STATUS[$name]:-}" == "$st" ]]; then
            continue
        fi
        TASK_PREV_STATUS["$name"]="$st"
        case "$st" in
            done|failed|skipped) : ;;
            *) continue ;;   # only print a permanent line once a task is final
        esac

        clear_live_status_line
        label_p="$(clip "${TASK_LABEL[$name]}" 42)"
        case "$st" in
            done)    dur_p="$(human_task_duration "$name")"; icon_char="${GREEN}✓${RESET}" ;;
            failed)  dur_p="failed";                          icon_char="${RED}✗${RESET}" ;;
            skipped) dur_p="skipped";                         icon_char="${DIM}-${RESET}" ;;
        esac
        printf '  [%s] %s %s\n' "$icon_char" "$label_p" "$dur_p"
    done

    local done_n=0 failed_n=0 running_n=0 skipped_n=0 total="${#TASK_ORDER[@]}"
    local -a running_names=()
    for name in "${TASK_ORDER[@]}"; do
        case "${TASK_STATUS[$name]}" in
            done)    done_n=$(( done_n + 1 )) ;;
            failed)  failed_n=$(( failed_n + 1 )) ;;
            skipped) skipped_n=$(( skipped_n + 1 )) ;;
            running) running_n=$(( running_n + 1 )); running_names+=("${TASK_LABEL[$name]}") ;;
        esac
    done

    local resolved_n=$(( done_n + failed_n + skipped_n ))
    local pct=0
    if [[ "$total" -gt 0 ]]; then
        pct=$(( resolved_n * 100 / total ))
    fi
    local filled=$(( pct * 30 / 100 ))
    local bar="" i
    for (( i = 0; i < 30; i++ )); do
        if [[ "$i" -lt "$filled" ]]; then
            bar+="█"
        else
            bar+="░"
        fi
    done

    local elapsed_s
    elapsed_s="$(awk -v s="$RUN_START_TS" -v n="$(now_ts)" 'BEGIN{printf "%d", n-s}')"

    local running_desc=""
    if [[ "$running_n" -gt 0 ]]; then
        running_desc="  $(next_spin_frame) ${running_names[0]}"
        if [[ "$running_n" -gt 1 ]]; then
            running_desc+=" (+$(( running_n - 1 )) more)"
        fi
    fi

    local status_line
    status_line="$(printf '  [%s] %d%%  %d/%d done   Elapsed %s%s' \
        "$bar" "$pct" "$done_n" "$total" "$(human_duration "$elapsed_s")" "$running_desc")"
    status_line="$(clip "$status_line" "$PANEL_WIDTH")"

    printf '\r%s' "$status_line"
    LIVE_STATUS_ACTIVE=true
    return 0
}

# ── Process-tree termination + signal handling ─────────────────────────
kill_tree() {
    local pid="$1" child
    if have_cmd pgrep; then
        for child in $(pgrep -P "$pid" 2>/dev/null || true); do
            kill_tree "$child"
        done
    fi
    kill -TERM "$pid" 2>/dev/null || true
    return 0
}

kill_all_running_tasks() {
    local name
    for name in "${TASK_ORDER[@]}"; do
        if [[ "${TASK_STATUS[$name]:-}" == "running" && -n "${TASK_PID[$name]:-}" ]]; then
            kill_tree "${TASK_PID[$name]}"
        fi
    done
    return 0
}

acquire_lock() {
    local dir="$1" old_pid
    LOCK_FILE="${dir}/.state/lock"
    mkdir -p "${dir}/.state" 2>/dev/null || true
    if [[ -f "$LOCK_FILE" ]]; then
        old_pid="$(cat "$LOCK_FILE" 2>/dev/null || true)"
        if [[ -n "$old_pid" ]] && kill -0 "$old_pid" 2>/dev/null; then
            log_error "Another instance is already running against this output dir (PID ${old_pid})."
            log_error "If that's stale, remove: ${LOCK_FILE}"
            return 1
        fi
        log_warn "Found a stale lock file — continuing."
    fi
    echo "$$" > "$LOCK_FILE"
    return 0
}

remove_lock() {
    if [[ -n "$LOCK_FILE" && -f "$LOCK_FILE" ]]; then
        rm -f "$LOCK_FILE" 2>/dev/null || true
    fi
    return 0
}

on_exit() {
    kill_all_running_tasks
    remove_lock
    return 0
}

on_interrupt() {
    clear_live_status_line
    printf '\n%s[!] Interrupted — terminating running tasks...%s\n' "$YELLOW" "$RESET"
    local name
    for name in "${TASK_ORDER[@]}"; do
        if [[ "${TASK_STATUS[$name]:-}" == "running" ]]; then
            TASK_STATUS["$name"]="pending"
        fi
    done
    persist_state
    if [[ -n "${OUTDIR:-}" ]]; then
        printf '%s[i] Progress saved. Resume with:%s\n    %s --resume "%s"\n' "$CYAN" "$RESET" "$SCRIPT_PATH" "$OUTDIR"
    fi
    exit 130
}

trap on_exit EXIT
trap on_interrupt INT TERM
trap 'log_error "Unexpected error at line $LINENO: $BASH_COMMAND"' ERR
# ══════════════════════════════════════════════════════════════════════════
#  TASK FUNCTIONS — LEVEL 0 (independent, target-only)
#  Each runs inside a `set +e` background subshell (see launch_task), so a
#  failing tool call inside these just ends that task's own exit code —
#  it can't crash the main script. They still return 0/1 meaningfully so
#  the dashboard and report reflect real success/failure.
# ══════════════════════════════════════════════════════════════════════════

write_section() {
    local file="$1" label="$2"
    {
        echo "============================================================"
        echo "  $label"
        echo "  Timestamp : $(date '+%Y-%m-%d %H:%M:%S')"
        echo "============================================================"
    } >> "$file"
    return 0
}

task_target_info() {
    local out="${RAW_DIR}/target_info.txt" parsed="${PARSED_DIR}/target_info.txt"
    write_section "$out" "TARGET INFO — ${TARGET}"

    local ip; ip="$(resolve_to_ip "$TARGET" || true)"
    if [[ -z "$ip" ]]; then
        echo "Could not resolve target to an IP address." >> "$out"
        : > "$parsed"
        return 0
    fi
    echo "Resolved IP: $ip" >> "$out"

    local geo=""
    if have_cmd curl; then
        geo="$(retry_cmd 2 curl -s --max-time 10 \
            "http://ip-api.com/json/${ip}?fields=status,country,city,isp,org,as,reverse" 2>/dev/null || true)"
        echo "$geo" >> "$out"
    fi

    local ptr=""
    if have_cmd dig; then
        ptr="$(dig +short -x "$ip" 2>/dev/null | sed 's/\.$//' || true)"
    fi
    echo "Reverse DNS (PTR): ${ptr:-none}" >> "$out"

    local cdn="none detected" hdrs=""
    if have_cmd curl; then
        hdrs="$(curl -sI --max-time 10 "https://${TARGET}" 2>/dev/null || true)"
        if echo "$hdrs" | grep -qi 'cf-ray\|cloudflare'; then
            cdn="Cloudflare"
        elif echo "$hdrs" | grep -qi 'x-amz-cf-id'; then
            cdn="Amazon CloudFront"
        elif echo "$hdrs" | grep -qi 'akamai'; then
            cdn="Akamai"
        elif echo "$hdrs" | grep -qi 'fastly'; then
            cdn="Fastly"
        fi
    fi
    echo "CDN: $cdn" >> "$out"

    {
        echo "IP: ${ip}"
        echo "ASN: $(json_field "$geo" "as")"
        echo "Organization: $(json_field "$geo" "org")"
        echo "ISP: $(json_field "$geo" "isp")"
        echo "Country: $(json_field "$geo" "country")"
        echo "City: $(json_field "$geo" "city")"
        echo "Reverse DNS: ${ptr:-none}"
        echo "CDN: ${cdn}"
    } > "$parsed"
    return 0
}

task_whois() {
    local out="${RAW_DIR}/whois.txt"
    local bin; bin="$(find_tool_path whois || true)"
    if [[ -z "$bin" ]]; then
        return 1
    fi
    write_section "$out" "WHOIS — ${TARGET}"
    {
        "$bin" "$TARGET" 2>/dev/null \
            | grep -iE 'Domain Name|Registrar( URL)?:|Updated Date|Creation Date|Expir|Registry Expiry|Domain Status|Name Server|DNSSEC|Registrant|Admin|Technical|Abuse|Organization|Country|Phone|Email|NetRange|CIDR|OriginAS|NetName|Organization' \
            | grep -iEv '^(#|%|>|$)' \
            | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//' \
            | sort -u || true
    } >> "$out"
    return 0
}

task_dns() {
    local out="${RAW_DIR}/dns.txt" parsed="${PARSED_DIR}/dns_records.txt"
    local bin; bin="$(find_tool_path dig || true)"
    if [[ -z "$bin" ]]; then
        return 1
    fi
    write_section "$out" "DNS — ${TARGET}"
    : > "$parsed"

    if [[ "$IS_IP" == "true" ]]; then
        local ptr
        ptr="$("$bin" +short -x "$TARGET" +time=5 +tries=2 2>/dev/null | sed 's/\.$//' || true)"
        echo "PTR ${ptr:-<none>}" >> "$out"
        echo "PTR ${ptr:-<none>}" >> "$parsed"
        return 0
    fi

    local rtype val
    for rtype in A AAAA MX NS TXT SOA CNAME CAA; do
        val="$("$bin" "$TARGET" "$rtype" +short +time=5 +tries=2 2>/dev/null || true)"
        {
            echo "--- $rtype ---"
            if [[ -n "$val" ]]; then echo "$val"; else echo "(none)"; fi
        } >> "$out"
        if [[ -n "$val" ]]; then
            while IFS= read -r v; do
                [[ -n "$v" ]] && echo "${rtype} ${v}" >> "$parsed"
            done <<< "$val"
        fi
    done

    write_section "$out" "DNS AXFR attempt"
    local ns
    for ns in $("$bin" "$TARGET" NS +short +time=5 +tries=2 2>/dev/null | sed 's/\.$//' || true); do
        [[ -z "$ns" ]] && continue
        echo "[*] Trying NS: $ns" >> "$out"
        "$bin" "@${ns}" "$TARGET" AXFR +time=10 +tries=1 >> "$out" 2>&1 || true
    done
    return 0
}

task_security_headers() {
    local out="${RAW_DIR}/security_headers.txt" parsed="${PARSED_DIR}/security_headers.txt"
    if ! have_cmd curl; then
        return 1
    fi
    write_section "$out" "SECURITY HEADERS — ${TARGET}"

    local url="https://${TARGET}" hdrs
    hdrs="$(curl -sI --max-time 10 -L "$url" 2>/dev/null || true)"
    if [[ -z "$hdrs" ]]; then
        url="http://${TARGET}"
        hdrs="$(curl -sI --max-time 10 -L "$url" 2>/dev/null || true)"
    fi
    echo "$hdrs" >> "$out"

    {
        for h in Server Strict-Transport-Security Content-Security-Policy \
                 X-Frame-Options X-XSS-Protection X-Content-Type-Options \
                 Referrer-Policy Permissions-Policy Set-Cookie; do
            local line
            line="$(echo "$hdrs" | grep -i "^${h}:" | head -1 || true)"
            if [[ -n "$line" ]]; then
                echo "$line" | sed -E 's/[[:space:]]+$//'
            else
                echo "${h}: (not set)"
            fi
        done
    } > "$parsed"

    write_section "$out" "robots.txt"
    curl -s --max-time 10 "${url%/}/robots.txt" 2>/dev/null | head -50 >> "$out" || true

    write_section "$out" "sitemap.xml (head)"
    curl -s --max-time 10 "${url%/}/sitemap.xml" 2>/dev/null | head -20 >> "$out" || true

    if have_cmd openssl && [[ "$url" == https://* ]]; then
        write_section "$out" "TLS certificate summary"
        {
            echo | timeout 10 openssl s_client -connect "${TARGET}:443" -servername "${TARGET}" 2>/dev/null \
                | openssl x509 -noout -subject -issuer -dates -ext subjectAltName 2>/dev/null \
                || echo "(could not establish TLS connection)"
        } >> "$out"
    fi
    return 0
}

task_theharvester() {
    local out="${RAW_DIR}/theharvester.txt" subsout="${PARSED_DIR}/theharvester_subs.txt"
    local bin; bin="$(find_tool_path theHarvester || find_tool_path theharvester || true)"
    if [[ -z "$bin" || "$IS_IP" == "true" ]]; then
        return 1
    fi
    write_section "$out" "theHarvester — ${TARGET}"
    local src
    for src in crtsh hackertarget dnsdumpster; do
        {
            echo "--- source: ${src} ---"
            timeout "$TOOL_TIMEOUT" "$bin" -d "$TARGET" -b "$src" -l 500 2>&1 || true
        } >> "$out"
    done
    grep -oE "[a-zA-Z0-9_-]+(\\.[a-zA-Z0-9_-]+)*\\.${TARGET_ESC}" "$out" 2>/dev/null \
        | sort -u > "$subsout" || true
    extract_emails_from_dir "$RAW_DIR" "${PARSED_DIR}/emails_partial_harvester.txt"
    return 0
}

task_crtsh() {
    local out="${RAW_DIR}/crtsh.txt" subsout="${PARSED_DIR}/crtsh_subs.txt"
    if ! have_cmd curl || [[ "$IS_IP" == "true" ]]; then
        return 1
    fi
    write_section "$out" "crt.sh certificate transparency — ${TARGET}"
    local raw
    raw="$(retry_cmd 2 curl -s --max-time 30 "https://crt.sh/?q=%.${TARGET}&output=json" 2>/dev/null || true)"
    echo "$raw" \
        | grep -oE '"name_value":"[^"]*"' \
        | cut -d'"' -f4 \
        | tr ',' '\n' \
        | sed 's/^\*\.//' \
        | grep -vE '^\*|^[[:space:]]*$' > "$subsout" 2>/dev/null || true
    clean_list_file "$subsout"
    if [[ -s "$subsout" ]]; then
        cat "$subsout" >> "$out"
    else
        echo "(no results from crt.sh)" >> "$out"
    fi
    return 0
}

task_assetfinder() {
    local out="${RAW_DIR}/assetfinder.txt"
    local bin; bin="$(find_tool_path assetfinder || true)"
    if [[ -z "$bin" || "$IS_IP" == "true" ]]; then
        return 1
    fi
    write_section "$out" "assetfinder — ${TARGET}"
    timeout "$TOOL_TIMEOUT" "$bin" --subs-only "$TARGET" >> "$out" 2>/dev/null || true
    return 0
}

task_amass() {
    local out="${RAW_DIR}/amass.txt"
    local bin; bin="$(find_tool_path amass || true)"
    if [[ -z "$bin" || "$IS_IP" == "true" ]]; then
        return 1
    fi
    write_section "$out" "amass (passive) — ${TARGET}"
    if [[ "$CFG_AMASS_ACTIVE_BRUTE" == "true" && -n "$CFG_WORDLIST" && -f "$CFG_WORDLIST" ]]; then
        timeout "$TOOL_TIMEOUT" "$bin" enum -active -brute -w "$CFG_WORDLIST" -d "$TARGET" >> "$out" 2>/dev/null || true
    else
        timeout "$TOOL_TIMEOUT" "$bin" enum -passive -d "$TARGET" >> "$out" 2>/dev/null || true
    fi
    return 0
}

task_dnsrecon() {
    local out="${RAW_DIR}/dnsrecon.txt"
    local bin; bin="$(find_tool_path dnsrecon || true)"
    if [[ -z "$bin" || "$IS_IP" == "true" ]]; then
        return 1
    fi
    write_section "$out" "dnsrecon — ${TARGET}"
    timeout "$TOOL_TIMEOUT" "$bin" -d "$TARGET" -t std >> "$out" 2>&1 || true
    return 0
}

task_wafw00f() {
    local out="${RAW_DIR}/wafw00f.txt" parsed="${PARSED_DIR}/waf.txt"
    local bin; bin="$(find_tool_path wafw00f || true)"
    if [[ -z "$bin" ]]; then
        return 1
    fi
    write_section "$out" "wafw00f — ${TARGET}"
    "$bin" -a "https://${TARGET}" >> "$out" 2>&1 || true
    grep -iE '(is behind|detected|No WAF|identified)' "$out" 2>/dev/null | sort -u > "$parsed" || true
    return 0
}

task_whatweb() {
    local out="${RAW_DIR}/whatweb.txt" parsed="${PARSED_DIR}/technologies.txt"
    local bin; bin="$(find_tool_path whatweb || true)"
    if [[ -z "$bin" ]]; then
        return 1
    fi
    local ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    write_section "$out" "whatweb (HTTPS, HTTP fallback) — ${TARGET}"
    timeout "$TOOL_TIMEOUT" "$bin" -a 3 --user-agent "$ua" "https://${TARGET}" >> "$out" 2>&1 || true
    if ! grep -qiE 'HTTP/[12]' "$out" 2>/dev/null; then
        timeout "$TOOL_TIMEOUT" "$bin" -a 3 --user-agent "$ua" "http://${TARGET}" >> "$out" 2>&1 || true
    fi
    grep -oE 'Server\[[^]]+\]|X-Powered-By\[[^]]+\]|PHP\[[^]]+\]|Apache\[[^]]+\]|Nginx\[[^]]+\]|IIS\[[^]]+\]|WordPress\[[^]]+\]|Drupal\[[^]]+\]|Joomla\[[^]]+\]|Laravel\[[^]]+\]|Django\[[^]]+\]|Rails\[[^]]+\]|jQuery\[[^]]+\]|Bootstrap\[[^]]+\]|React\[[^]]+\]|Angular\[[^]]+\]|Title\[[^]]+\]|MetaGenerator\[[^]]+\]' \
        "$out" 2>/dev/null | sort -u > "$parsed" || true
    return 0
}

task_nmap() {
    local out="${PORTS_DIR}/nmap_raw.txt" parsed="${PORTS_DIR}/open_ports.txt"
    local bin; bin="$(find_tool_path nmap || true)"
    if [[ -z "$bin" ]]; then
        return 1
    fi
    local common_ports="21,22,23,25,53,80,110,143,389,443,445,465,587,993,995,1433,1521,3306,3389,5432,5900,6379,8080,8443,8888,9200,27017"
    write_section "$out" "nmap — top-1000 (fast) — ${TARGET}"
    timeout "$TOOL_TIMEOUT" "$bin" -Pn -T4 --open "$TARGET" >> "$out" 2>&1 || true
    if [[ "$CFG_SCAN_MODE" != "fast" ]]; then
        write_section "$out" "nmap — service/version (common ports)"
        timeout "$TOOL_TIMEOUT" "$bin" -Pn -sV --version-intensity 5 -T3 --open -p "$common_ports" "$TARGET" >> "$out" 2>&1 || true
    fi
    if [[ "$IS_IP" == "true" ]]; then
        local cidr="${TARGET%.*}.0/24"
        write_section "$out" "nmap — /24 ping sweep (${cidr})"
        timeout "$TOOL_TIMEOUT" "$bin" -sn -T4 "$cidr" >> "$out" 2>&1 || true
    fi
    grep -E '^[0-9]+/(tcp|udp)[[:space:]]+open' "$out" 2>/dev/null | sort -u > "$parsed" || true
    return 0
}
# ══════════════════════════════════════════════════════════════════════════
#  TASK FUNCTIONS — LEVELS 1-4 (dependent on earlier tasks)
# ══════════════════════════════════════════════════════════════════════════

task_merge_subdomains() {
    local raw="${OUTDIR}/subdomains_raw.txt" clean="${PARSED_DIR}/subdomains.txt"
    : > "$raw"
    if [[ "$IS_IP" == "true" ]]; then
        : > "$clean"
        return 0
    fi
    local f
    for f in "${RAW_DIR}/assetfinder.txt" "${PARSED_DIR}/theharvester_subs.txt" "${PARSED_DIR}/crtsh_subs.txt"; do
        if [[ -s "$f" ]]; then
            cat "$f" >> "$raw"
        fi
    done
    # amass writes plain subdomain lines mixed with other passive-enum text;
    # grep down to token-looking lines that end in the target domain.
    if [[ -s "${RAW_DIR}/amass.txt" ]]; then
        grep -oE "[a-zA-Z0-9._-]+\.${TARGET_ESC}" "${RAW_DIR}/amass.txt" >> "$raw" 2>/dev/null || true
    fi
    filter_valid_subdomains "$raw" "$clean" "$TARGET"
    return 0
}

task_probe_alive() {
    local clean="${PARSED_DIR}/subdomains.txt" alive="${PARSED_DIR}/alive_hosts.txt"
    : > "$alive"
    local targets_file
    targets_file="$(mktemp)"
    if [[ "$IS_IP" == "true" ]]; then
        echo "$TARGET" > "$targets_file"
    elif [[ -s "$clean" ]]; then
        cp "$clean" "$targets_file"
    else
        echo "$TARGET" > "$targets_file"
    fi

    local httpx_bin; httpx_bin="$(find_tool_path httpx || true)"
    local httprobe_bin; httprobe_bin="$(find_tool_path httprobe || true)"

    if [[ -n "$httpx_bin" ]]; then
        "$httpx_bin" -silent -l "$targets_file" -status-code -title -tech-detect \
            -threads "$CFG_THREADS" -o "${RAW_DIR}/httpx_probe.txt" 2>/dev/null || true
        awk '{print $1}' "${RAW_DIR}/httpx_probe.txt" 2>/dev/null >> "$alive" || true
        grep -oE '\[[A-Za-z0-9_.:, -]+\]$' "${RAW_DIR}/httpx_probe.txt" 2>/dev/null \
            | tr -d '[]' | tr ',' '\n' | sed -E 's/^[[:space:]]+//;s/[[:space:]]+$//' \
            | grep -v '^[0-9]*$' | sort -u > "${PARSED_DIR}/technologies_httpx.txt" || true
    elif [[ -n "$httprobe_bin" ]]; then
        "$httprobe_bin" < "$targets_file" >> "$alive" 2>/dev/null || true
    else
        # Last-resort fallback: bounded-concurrency curl probing via xargs -P.
        while IFS= read -r h; do
            [[ -n "$h" ]] || continue
            echo "https://${h}"
            echo "http://${h}"
        done < "$targets_file" \
        | xargs -P "$CFG_THREADS" -I{} sh -c \
            'curl -s -o /dev/null --max-time 6 -w "%{http_code} {}\n" "{}" 2>/dev/null' \
        | awk '$1 ~ /^[23]/{print $2}' >> "$alive" || true
    fi

    clean_list_file "$alive"
    rm -f "$targets_file" 2>/dev/null || true
    return 0
}

task_waybackurls() {
    local clean="${PARSED_DIR}/subdomains.txt" out="${OUTDIR}/wayback_raw.txt"
    local bin; bin="$(find_tool_path waybackurls || true)"
    if [[ -z "$bin" || "$IS_IP" == "true" ]]; then
        return 1
    fi
    : > "$out"
    {
        echo "$TARGET"
        if [[ -s "$clean" ]]; then
            cat "$clean"
        fi
    } | timeout "$TOOL_TIMEOUT" "$bin" 2>/dev/null | sort -u >> "$out" || true
    return 0
}

task_screenshots() {
    local alive="${PARSED_DIR}/alive_hosts.txt"
    local bin; bin="$(find_tool_path httpx || true)"
    if [[ -z "$bin" ]]; then
        return 1
    fi
    if [[ ! -s "$alive" ]]; then
        return 0
    fi
    timeout "$TOOL_TIMEOUT" "$bin" -silent -l "$alive" -screenshot -srd "$SHOTS_DIR" -silent \
        >> "${RAW_DIR}/screenshots_httpx.txt" 2>&1 || true
    return 0
}

task_nuclei() {
    local out="${NUCLEI_DIR}/nuclei_raw.txt" parsed="${NUCLEI_DIR}/findings.txt"
    local bin; bin="$(find_tool_path nuclei || true)"
    if [[ -z "$bin" ]]; then
        return 1
    fi
    local alive="${PARSED_DIR}/alive_hosts.txt" target_list
    target_list="$(mktemp)"
    if [[ -s "$alive" ]]; then
        cp "$alive" "$target_list"
    else
        echo "https://${TARGET}" > "$target_list"
    fi
    timeout "$TOOL_TIMEOUT" "$bin" -l "$target_list" -severity "$CFG_NUCLEI_SEVERITY" \
        -rate-limit "$CFG_NUCLEI_RATE_LIMIT" -silent -no-color \
        > "$out" 2>>"${LOGS_DIR}/errors.log" || true
    grep -iE '\[(critical|high|medium)\]' "$out" 2>/dev/null | sort -u > "$parsed" || true
    grep -iE '\[low\]|\[info\]' "$out" 2>/dev/null | sort -u > "${NUCLEI_DIR}/findings_low_info.txt" || true
    rm -f "$target_list" 2>/dev/null || true
    return 0
}

# Categorize a URL list by keyword patterns in the path/query.
categorize_urls() {
    local infile="$1" dir="$2"
    : > "${dir}/admin.txt"; : > "${dir}/login.txt"; : > "${dir}/api.txt"
    : > "${dir}/upload.txt"; : > "${dir}/backup.txt"; : > "${dir}/sensitive.txt"
    : > "${dir}/js.txt"; : > "${dir}/archive.txt"; : > "${dir}/interesting.txt"
    [[ -s "$infile" ]] || return 0

    grep -iE '/(admin|administrator|wp-admin|cpanel|manage|dashboard)(/|$|\?)' "$infile" 2>/dev/null | sort -u > "${dir}/admin.txt" || true
    grep -iE '/(login|signin|sign-in|auth|sso)(/|$|\?)' "$infile" 2>/dev/null | sort -u > "${dir}/login.txt" || true
    grep -iE '/(api|v[0-9]+|graphql|swagger|openapi)(/|$|\?)' "$infile" 2>/dev/null | sort -u > "${dir}/api.txt" || true
    grep -iE '/(upload|import|file-upload)(/|$|\?)' "$infile" 2>/dev/null | sort -u > "${dir}/upload.txt" || true
    grep -iE '\.(bak|old|backup|zip|tar|tar\.gz|sql|dump)$|/backup(/|$)' "$infile" 2>/dev/null | sort -u > "${dir}/backup.txt" || true
    grep -iE '\.env$|\.git/|\.svn/|wp-config\.php|id_rsa|\.pem$|\.htpasswd$|config\.(json|yml|yaml|xml)$' "$infile" 2>/dev/null | sort -u > "${dir}/sensitive.txt" || true
    grep -iE '\.js($|\?)' "$infile" 2>/dev/null | sort -u > "${dir}/js.txt" || true
    grep -iE 'web\.archive\.org' "$infile" 2>/dev/null | sort -u > "${dir}/archive.txt" || true

    cat "${dir}/admin.txt" "${dir}/login.txt" "${dir}/api.txt" "${dir}/upload.txt" \
        "${dir}/backup.txt" "${dir}/sensitive.txt" 2>/dev/null | sort -u > "${dir}/interesting.txt" || true
    return 0
}

task_url_filter() {
    local wb="${OUTDIR}/wayback_raw.txt" valid="${OUTDIR}/urls_valid.txt" live="${URLS_DIR}/all_live.txt"
    if [[ ! -s "$wb" ]]; then
        : > "$live"
        categorize_urls "$live" "$URLS_DIR"
        return 0
    fi
    filter_valid_urls "$wb" "$valid"

    if [[ "$CFG_KEEP_ALL_URLS" == "true" ]]; then
        cp "$valid" "$live"
        categorize_urls "$live" "$URLS_DIR"
        return 0
    fi

    local httpx_bin; httpx_bin="$(find_tool_path httpx || true)"
    local fc="404,400,410"
    if [[ "$CFG_FILTER_403" == "true" ]]; then
        fc="${fc},403"
    fi

    if [[ -n "$httpx_bin" ]]; then
        "$httpx_bin" -silent -l "$valid" -fc "$fc" -mc "200,201,202,204,206,301,302,303,307,308" \
            -threads "$CFG_THREADS" -o "$live" 2>/dev/null || true
    else
        # curl + xargs -P fallback: bounded-concurrency liveness check.
        : > "$live"
        xargs -P "$CFG_THREADS" -I{} sh -c \
            'code=$(curl -s -o /dev/null --max-time 6 -w "%{http_code}" "{}" 2>/dev/null); echo "$code {}"' \
            < "$valid" 2>/dev/null \
        | awk -v fc="$fc" '
            BEGIN { n = split(fc, bad, ","); for (i=1;i<=n;i++) badset[bad[i]]=1 }
            { if ($1 ~ /^[23]/ && !($1 in badset)) print $2 }
        ' >> "$live" || true
    fi
    clean_list_file "$live"
    categorize_urls "$live" "$URLS_DIR"
    return 0
}

task_js_extract() {
    local jsfile="${URLS_DIR}/js.txt" out="${OUTDIR}/js_endpoints_raw.txt" parsed="${PARSED_DIR}/js_endpoints.txt"
    if ! have_cmd curl; then
        return 1
    fi
    : > "$parsed"
    if [[ ! -s "$jsfile" ]]; then
        return 0
    fi
    : > "$out"
    local url body
    local count=0
    while IFS= read -r url; do
        count=$(( count + 1 ))
        [[ "$count" -gt 200 ]] && break   # sane upper bound so one huge JS list can't run forever
        body="$(curl -s --max-time 8 "$url" 2>/dev/null || true)"
        echo "$body" >> "$out"
    done < "$jsfile"

    grep -oE "[\"'][/][a-zA-Z0-9_./?=&%-]{2,}[\"']" "$out" 2>/dev/null \
        | tr -d "\"'" | sort -u > "$parsed" || true
    return 0
}
# ══════════════════════════════════════════════════════════════════════════
#  REPORT GENERATION — reads only from parsed/ports/urls/nuclei (never raw/)
# ══════════════════════════════════════════════════════════════════════════

json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/ }"
    s="${s//$'\r'/}"
    s="${s//$'\t'/ }"
    printf '%s' "$s"
    return 0
}

file_lines_as_json_array() {
    local file="$1" first=true line
    printf '['
    if [[ -s "$file" ]]; then
        while IFS= read -r line; do
            if [[ "$first" == "true" ]]; then
                first=false
            else
                printf ','
            fi
            printf '"%s"' "$(json_escape "$line")"
        done < "$file"
    fi
    printf ']'
    return 0
}

cat_or_none() {
    local file="$1" label="${2:-(none found)}"
    if [[ -s "$file" ]]; then
        cat "$file"
    else
        echo "  $label"
    fi
    return 0
}

count_or_zero() {
    local file="$1"
    if [[ -s "$file" ]]; then
        wc -l < "$file" | tr -d '[:space:]'
    else
        echo 0
    fi
    return 0
}

generate_report_txt() {
    local out="${REPORTS_DIR}/target-recon.txt"
    local cat_name f n
    {
        echo "════════════════════════════════════════════════════════════"
        echo "  RECONQUEROR — RECON REPORT"
        echo "  Target   : ${TARGET}"
        echo "  Date     : $(date '+%Y-%m-%d %H:%M:%S')"
        echo "  Duration : $(human_duration "$(( $(date +%s) - SCAN_START_EPOCH ))")"
        echo "════════════════════════════════════════════════════════════"
        echo
        echo "# TARGET INFORMATION"
        echo
        cat_or_none "${PARSED_DIR}/target_info.txt"
        echo
        echo "────────────────────────────────────────────────────────────"
        echo "# DNS INFORMATION"
        echo
        cat_or_none "${PARSED_DIR}/dns_records.txt"
        echo
        echo "────────────────────────────────────────────────────────────"
        echo "# WHOIS (summary)"
        echo
        cat_or_none "${RAW_DIR}/whois.txt" "(no data)"
        echo
        echo "────────────────────────────────────────────────────────────"
        echo "# OPEN PORTS"
        echo
        cat_or_none "${PORTS_DIR}/open_ports.txt"
        echo
        echo "────────────────────────────────────────────────────────────"
        echo "# TECHNOLOGIES"
        echo
        cat "${PARSED_DIR}/technologies.txt" "${PARSED_DIR}/technologies_httpx.txt" 2>/dev/null \
            | sort -u | grep -v '^$' || echo "  (none detected)"
        echo
        echo "────────────────────────────────────────────────────────────"
        echo "# SECURITY"
        echo
        echo "-- WAF Detection --"
        cat_or_none "${PARSED_DIR}/waf.txt"
        echo
        echo "-- Headers --"
        cat_or_none "${PARSED_DIR}/security_headers.txt"
        echo
        echo "────────────────────────────────────────────────────────────"
        echo "# SUBDOMAINS ($(count_or_zero "${PARSED_DIR}/subdomains.txt") unique)"
        echo
        cat_or_none "${PARSED_DIR}/subdomains.txt"
        echo
        echo "────────────────────────────────────────────────────────────"
        echo "# LIVE HOSTS ($(count_or_zero "${PARSED_DIR}/alive_hosts.txt") unique)"
        echo
        cat_or_none "${PARSED_DIR}/alive_hosts.txt"
        echo
        echo "────────────────────────────────────────────────────────────"
        echo "# URLS (categorized, live only unless --keep-all)"
        echo
        for cat_name in interesting admin login api upload backup sensitive js archive; do
            f="${URLS_DIR}/${cat_name}.txt"
            n="$(count_or_zero "$f")"
            if [[ "$n" -gt 0 ]]; then
                echo "-- ${cat_name^} (${n}) --"
                cat "$f"
                echo
            fi
        done
        if [[ "$(count_or_zero "${URLS_DIR}/all_live.txt")" -eq 0 ]]; then
            echo "  (no live URLs found)"
        fi
        echo "────────────────────────────────────────────────────────────"
        echo "# JAVASCRIPT ENDPOINTS"
        echo
        cat_or_none "${PARSED_DIR}/js_endpoints.txt"
        echo
        echo "────────────────────────────────────────────────────────────"
        echo "# INTERESTING FINDINGS"
        echo
        cat_or_none "${URLS_DIR}/interesting.txt" "(none flagged)"
        echo
        echo "────────────────────────────────────────────────────────────"
        echo "# SCREENSHOTS"
        echo
        if [[ -d "$SHOTS_DIR" ]] && find "$SHOTS_DIR" -type f 2>/dev/null | grep -q .; then
            echo "  $(find "$SHOTS_DIR" -type f 2>/dev/null | wc -l | tr -d '[:space:]') screenshot(s) saved in: ${SHOTS_DIR}"
        else
            echo "  (not captured — enable CFG_SCREENSHOTS=true)"
        fi
        echo
        echo "────────────────────────────────────────────────────────────"
        echo "# NUCLEI — VULNERABILITY FINDINGS (medium/high/critical)"
        echo
        cat_or_none "${NUCLEI_DIR}/findings.txt" "(no medium/high/critical findings)"
        echo
        echo "════════════════════════════════════════════════════════════"
        echo "  Full data: ${OUTDIR}/"
        echo "════════════════════════════════════════════════════════════"
    } > "$out"
    return 0
}

generate_report_md() {
    local out="${REPORTS_DIR}/target-recon.md"
    local cat_name f n
    {
        echo "# Reconqueror Report — ${TARGET}"
        echo
        echo "- **Date:** $(date '+%Y-%m-%d %H:%M:%S')"
        echo "- **Duration:** $(human_duration "$(( $(date +%s) - SCAN_START_EPOCH ))")"
        echo
        echo "## Target Information"
        echo '```'
        cat_or_none "${PARSED_DIR}/target_info.txt"
        echo '```'
        echo
        echo "## DNS Records"
        echo '```'
        cat_or_none "${PARSED_DIR}/dns_records.txt"
        echo '```'
        echo
        echo "## Open Ports"
        echo '```'
        cat_or_none "${PORTS_DIR}/open_ports.txt"
        echo '```'
        echo
        echo "## Technologies"
        cat "${PARSED_DIR}/technologies.txt" "${PARSED_DIR}/technologies_httpx.txt" 2>/dev/null \
            | sort -u | grep -v '^$' | sed 's/^/- /' || echo "_(none detected)_"
        echo
        echo "## Security"
        echo "**WAF:**"
        echo '```'
        cat_or_none "${PARSED_DIR}/waf.txt"
        echo '```'
        echo "**Headers:**"
        echo '```'
        cat_or_none "${PARSED_DIR}/security_headers.txt"
        echo '```'
        echo
        echo "## Subdomains ($(count_or_zero "${PARSED_DIR}/subdomains.txt"))"
        echo '```'
        cat_or_none "${PARSED_DIR}/subdomains.txt"
        echo '```'
        echo
        echo "## Live Hosts ($(count_or_zero "${PARSED_DIR}/alive_hosts.txt"))"
        echo '```'
        cat_or_none "${PARSED_DIR}/alive_hosts.txt"
        echo '```'
        echo
        echo "## URLs by Category"
        for cat_name in interesting admin login api upload backup sensitive js archive; do
            f="${URLS_DIR}/${cat_name}.txt"
            n="$(count_or_zero "$f")"
            if [[ "$n" -gt 0 ]]; then
                echo "### ${cat_name^} (${n})"
                echo '```'
                cat "$f"
                echo '```'
            fi
        done
        echo
        echo "## Nuclei Findings (medium/high/critical)"
        echo '```'
        cat_or_none "${NUCLEI_DIR}/findings.txt" "(none)"
        echo '```'
    } > "$out"
    return 0
}

generate_report_json() {
    local out="${REPORTS_DIR}/target-recon.json"
    local tech_merged_file="${PARSED_DIR}/_tech_merged.txt"
    cat "${PARSED_DIR}/technologies.txt" "${PARSED_DIR}/technologies_httpx.txt" 2>/dev/null \
        | sort -u | grep -v '^$' > "$tech_merged_file" || true
    {
        printf '{\n'
        printf '  "target": "%s",\n' "$(json_escape "$TARGET")"
        printf '  "generated_at": "%s",\n' "$(date '+%Y-%m-%dT%H:%M:%S%z')"
        printf '  "duration_seconds": %d,\n' "$(( $(date +%s) - SCAN_START_EPOCH ))"
        printf '  "subdomains": %s,\n' "$(file_lines_as_json_array "${PARSED_DIR}/subdomains.txt")"
        printf '  "alive_hosts": %s,\n' "$(file_lines_as_json_array "${PARSED_DIR}/alive_hosts.txt")"
        printf '  "open_ports": %s,\n' "$(file_lines_as_json_array "${PORTS_DIR}/open_ports.txt")"
        printf '  "technologies": %s,\n' "$(file_lines_as_json_array "$tech_merged_file")"
        printf '  "waf": %s,\n' "$(file_lines_as_json_array "${PARSED_DIR}/waf.txt")"
        printf '  "urls": {\n'
        local cat_name first_cat=true
        for cat_name in interesting admin login api upload backup sensitive js archive; do
            if [[ "$first_cat" == "true" ]]; then
                first_cat=false
            else
                printf ',\n'
            fi
            printf '    "%s": %s' "$cat_name" "$(file_lines_as_json_array "${URLS_DIR}/${cat_name}.txt")"
        done
        printf '\n  },\n'
        printf '  "nuclei_findings": %s\n' "$(file_lines_as_json_array "${NUCLEI_DIR}/findings.txt")"
        printf '}\n'
    } > "$out"
    rm -f "$tech_merged_file" 2>/dev/null || true
    return 0
}

generate_report_html() {
    local out="${REPORTS_DIR}/target-recon.html"
    local tech_merged
    tech_merged="$(cat "${PARSED_DIR}/technologies.txt" "${PARSED_DIR}/technologies_httpx.txt" 2>/dev/null | sort -u | grep -v '^$' || true)"
    local cat_name
    {
        cat <<HTML_HEAD
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Recon Report — ${TARGET}</title>
<style>
  body { font-family: -apple-system, Segoe UI, Roboto, sans-serif; max-width: 960px; margin: 2rem auto; padding: 0 1rem; color: #1a1a1a; background: #fafafa; }
  h1 { border-bottom: 3px solid #2563eb; padding-bottom: .5rem; }
  h2 { color: #2563eb; margin-top: 2rem; border-bottom: 1px solid #ddd; padding-bottom: .3rem; }
  pre { background: #1e1e1e; color: #d4d4d4; padding: 1rem; border-radius: 6px; overflow-x: auto; font-size: .85rem; white-space: pre-wrap; word-break: break-word; }
  .meta { color: #666; font-size: .9rem; }
  .badge { display:inline-block; background:#e0e7ff; color:#3730a3; padding:.15rem .6rem; border-radius:999px; font-size:.8rem; margin:.15rem; }
  table { border-collapse: collapse; width: 100%; margin: 1rem 0; }
  td, th { border: 1px solid #ddd; padding: .5rem; text-align: left; font-size: .9rem; }
  th { background: #f0f0f0; }
</style>
</head>
<body>
<h1>Recon Report — $(json_escape "$TARGET")</h1>
<p class="meta">Generated $(date '+%Y-%m-%d %H:%M:%S') · Duration $(human_duration "$(( $(date +%s) - SCAN_START_EPOCH ))")</p>

<h2>Target Information</h2>
<pre>$(cat_or_none "${PARSED_DIR}/target_info.txt")</pre>

<h2>DNS Records</h2>
<pre>$(cat_or_none "${PARSED_DIR}/dns_records.txt")</pre>

<h2>Open Ports</h2>
<pre>$(cat_or_none "${PORTS_DIR}/open_ports.txt")</pre>

<h2>Technologies</h2>
<div>
HTML_HEAD
        if [[ -n "$tech_merged" ]]; then
            while IFS= read -r t; do
                printf '<span class="badge">%s</span>\n' "$(json_escape "$t")"
            done <<< "$tech_merged"
        else
            echo "<em>(none detected)</em>"
        fi
        cat <<HTML_MID
</div>

<h2>Security</h2>
<pre>$(cat_or_none "${PARSED_DIR}/waf.txt")
$(cat_or_none "${PARSED_DIR}/security_headers.txt")</pre>

<h2>Subdomains ($(count_or_zero "${PARSED_DIR}/subdomains.txt"))</h2>
<pre>$(cat_or_none "${PARSED_DIR}/subdomains.txt")</pre>

<h2>Live Hosts ($(count_or_zero "${PARSED_DIR}/alive_hosts.txt"))</h2>
<pre>$(cat_or_none "${PARSED_DIR}/alive_hosts.txt")</pre>

<h2>URLs by Category</h2>
<table>
<tr><th>Category</th><th>Count</th></tr>
HTML_MID
        for cat_name in interesting admin login api upload backup sensitive js archive; do
            printf '<tr><td>%s</td><td>%s</td></tr>\n' "$cat_name" "$(count_or_zero "${URLS_DIR}/${cat_name}.txt")"
        done
        cat <<HTML_TAIL
</table>

<h2>Nuclei Findings (medium/high/critical)</h2>
<pre>$(cat_or_none "${NUCLEI_DIR}/findings.txt" "(none)")</pre>

</body>
</html>
HTML_TAIL
    } > "$out"
    return 0
}

task_generate_report() {
    generate_report_txt
    if [[ "$CFG_REPORT_MD" == "true" ]]; then
        generate_report_md
    fi
    if [[ "$CFG_REPORT_JSON" == "true" ]]; then
        generate_report_json
    fi
    if [[ "$CFG_REPORT_HTML" == "true" ]]; then
        generate_report_html
    fi
    return 0
}
# ══════════════════════════════════════════════════════════════════════════
#  CLI, BANNER, HELP
# ══════════════════════════════════════════════════════════════════════════

declare -A MODULE_NAME_TO_CFG=(
    [whois]=CFG_WHOIS [dns]=CFG_DNS [target_info]=CFG_TARGET_INFO
    [security_headers]=CFG_SECURITY_HEADERS [theharvester]=CFG_THEHARVESTER
    [crtsh]=CFG_CRTSH [assetfinder]=CFG_ASSETFINDER [amass]=CFG_AMASS
    [dnsrecon]=CFG_DNSRECON [waf]=CFG_WAF_DETECT [tech]=CFG_TECH_DETECT
    [portscan]=CFG_PORT_SCAN [nmap]=CFG_PORT_SCAN [wayback]=CFG_WAYBACK
    [screenshots]=CFG_SCREENSHOTS [nuclei]=CFG_NUCLEI [js]=CFG_JS_SCAN
    [md]=CFG_REPORT_MD [json]=CFG_REPORT_JSON [html]=CFG_REPORT_HTML
)

apply_module_toggle() {
    local list="$1" value="$2" name cfgvar
    local -a names=()
    IFS=',' read -ra names <<< "$list"
    for name in "${names[@]}"; do
        name="$(echo "$name" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]' || true)"
        [[ -z "$name" ]] && continue
        cfgvar="${MODULE_NAME_TO_CFG[$name]:-}"
        if [[ -n "$cfgvar" ]]; then
            printf -v "$cfgvar" '%s' "$value"
        else
            log_warn "Unknown module name '${name}' — ignoring."
        fi
    done
    return 0
}

resolve_ui_mode() {
    if [[ "$CFG_LOG_LEVEL" == "quiet" ]]; then
        UI_MODE="plain"
    elif [[ -t 1 ]]; then
        UI_MODE="live"
    else
        UI_MODE="plain"
    fi
    return 0
}

show_help() {
    cat <<EOF
${SCRIPT_NAME} — Parallel Recon Framework
Authorized security testing use only.

USAGE:
  $(basename "$SCRIPT_PATH") [OPTIONS]

TARGET SELECTION:
  -t, --target <host>      Domain or IPv4 target (skips the interactive prompt)
  -l, --list <file>        File of targets, one per line (multi-target run)

OUTPUT & RESUME:
  -o, --outdir <dir>       Output root (default: ./output)
  -r, --resume [dir]       Resume the latest incomplete run for the target,
                            or a specific run directory if given
  -c, --config <file>      Load module/performance settings from a config file

PERFORMANCE:
  -j, --parallel <n>       Max concurrent tasks (default: ${CFG_MAX_PARALLEL})
      --threads <n>        Thread hint passed to httpx/nuclei/curl (default: ${CFG_THREADS})
      --fast                 Skip nuclei/wayback/JS-extraction, short per-tool
                              timeout (${CFG_FAST_TOOL_TIMEOUT}s) — a few minutes on most targets
      --full                 Every enabled module, ${CFG_TOOL_TIMEOUT}s cap per tool (default)
                              Without --fast/--full, asks interactively unless -y is given

MODULES:
      --enable  <a,b,c>    Force-enable modules (comma-separated)
      --disable <a,b,c>    Force-disable modules (comma-separated)
                            Names: whois,dns,target_info,security_headers,
                            theharvester,crtsh,assetfinder,amass,dnsrecon,
                            waf,tech,portscan,wayback,screenshots,nuclei,js,
                            md,json,html (report formats)

OUTPUT FILTERING:
      --keep-all            Skip dead/invalid URL filtering, keep everything

BEHAVIOUR:
  -y, --yes                 Assume "yes" to prompts (non-interactive)
      --no-install           Never attempt tool installation, just skip
  -q, --quiet                Minimal output
  -v, --verbose               Extra detail
      --debug                 Verbose + keeps everything for troubleshooting
      --no-color               Disable ANSI colors

  -h, --help                 Show this help
      --version               Show version

EXAMPLES:
  $(basename "$SCRIPT_PATH") -t example.com
  $(basename "$SCRIPT_PATH") -t example.com -j 12 --disable screenshots,nuclei
  $(basename "$SCRIPT_PATH") -l targets.txt -y
  $(basename "$SCRIPT_PATH") --resume output/example.com/20260101_120000
EOF
    return 0
}

show_banner() {
    if [[ "$UI_MODE" == "plain" ]]; then
        return 0
    fi
    local figlet_bin; figlet_bin="$(find_tool_path figlet || true)"
    printf '%s' "$RED"
    if [[ -n "$figlet_bin" ]]; then
        "$figlet_bin" -f slant "Reconqueror" 2>/dev/null || echo "  R E C O N Q U E R O R"
    else
        cat <<'BANNER'
  ██████╗ ███████╗ ██████╗ ██████╗ ███╗  ██╗
  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗ ██║
  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗██║
  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚████║
  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚███║
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚══╝
BANNER
    fi
    printf '%s\n' "$RESET"
    printf '%s   Parallel Recon Framework  |  Authorized use only%s\n\n' "$BLUE" "$RESET"
    return 0
}

parse_cli_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -t|--target)
                if [[ -z "${2:-}" ]]; then log_error "Option $1 requires a value."; exit 1; fi
                TARGET="$2"; shift 2 ;;
            -l|--list)
                if [[ -z "${2:-}" ]]; then log_error "Option $1 requires a value."; exit 1; fi
                TARGET_LIST_FILE="$2"; shift 2 ;;
            -o|--outdir)
                if [[ -z "${2:-}" ]]; then log_error "Option $1 requires a value."; exit 1; fi
                EXPLICIT_OUTDIR="$2"; shift 2 ;;
            -c|--config)
                if [[ -z "${2:-}" ]]; then log_error "Option $1 requires a value."; exit 1; fi
                CONFIG_FILE="$2"; shift 2 ;;
            -r|--resume)
                RESUME_REQUESTED=true
                local _next="${2:-}"
                if [[ -n "$_next" && "${_next:0:1}" != "-" ]]; then
                    RESUME_DIR="$2"; shift 2
                else
                    shift 1
                fi
                ;;
            -j|--parallel)
                if [[ -z "${2:-}" ]]; then log_error "Option $1 requires a value."; exit 1; fi
                CFG_MAX_PARALLEL="$2"; shift 2 ;;
            --threads)
                if [[ -z "${2:-}" ]]; then log_error "Option $1 requires a value."; exit 1; fi
                CFG_THREADS="$2"; shift 2 ;;
            --enable)
                if [[ -z "${2:-}" ]]; then log_error "Option $1 requires a value."; exit 1; fi
                apply_module_toggle "$2" "true"; shift 2 ;;
            --disable)
                if [[ -z "${2:-}" ]]; then log_error "Option $1 requires a value."; exit 1; fi
                apply_module_toggle "$2" "false"; shift 2 ;;
            --keep-all)   CFG_KEEP_ALL_URLS=true; shift 1 ;;
            --fast)       CFG_SCAN_MODE="fast"; shift 1 ;;
            --full)       CFG_SCAN_MODE="full"; shift 1 ;;
            --no-install) CFG_AUTO_INSTALL="no"; shift 1 ;;
            -y|--yes)     ASSUME_YES=true; shift 1 ;;
            -q|--quiet)   CFG_LOG_LEVEL="quiet"; shift 1 ;;
            -v|--verbose) CFG_LOG_LEVEL="verbose"; shift 1 ;;
            --debug)      CFG_LOG_LEVEL="debug"; shift 1 ;;
            --no-color)   CFG_COLOR="never"; shift 1 ;;
            -h|--help)    show_help; exit 0 ;;
            --version)    echo "${SCRIPT_NAME}"; exit 0 ;;
            *)
                log_error "Unknown argument: $1"
                show_help
                exit 1
                ;;
        esac
    done
    return 0
}
# ══════════════════════════════════════════════════════════════════════════
#  MAIN ORCHESTRATION
# ══════════════════════════════════════════════════════════════════════════

# Globals populated per-target in run_single_target (deliberately NOT
# `local` — task functions run in background subshells forked from here
# and need to see them; a `( )` subshell inherits all shell variables,
# not just exported ones, since it's the same interpreter forking).
TARGET=""; TARGET_ESC=""; IS_IP="false"; OUTDIR=""
RAW_DIR=""; PARSED_DIR=""; PORTS_DIR=""; URLS_DIR=""; NUCLEI_DIR=""
SHOTS_DIR=""; REPORTS_DIR=""; LOGS_DIR=""; STATE_DIR=""; SCAN_START_EPOCH=0

setup_output_dirs() {
    local target="$1" resume_dir="${2:-}"
    if [[ -n "$resume_dir" ]]; then
        OUTDIR="$resume_dir"
    else
        local root="${EXPLICIT_OUTDIR:-$CFG_OUTPUT_ROOT}"
        local ts; ts="$(date '+%Y%m%d_%H%M%S')"
        OUTDIR="${root}/${target}/${ts}"
    fi
    RAW_DIR="${OUTDIR}/raw"; PARSED_DIR="${OUTDIR}/parsed"; PORTS_DIR="${OUTDIR}/ports"
    URLS_DIR="${OUTDIR}/urls"; NUCLEI_DIR="${OUTDIR}/nuclei"; SHOTS_DIR="${OUTDIR}/screenshots"
    REPORTS_DIR="${OUTDIR}/reports"; LOGS_DIR="${OUTDIR}/logs"; STATE_DIR="${OUTDIR}/.state"

    mkdir -p "$RAW_DIR" "$PARSED_DIR" "$PORTS_DIR" "$URLS_DIR" "$NUCLEI_DIR" \
             "$SHOTS_DIR" "$REPORTS_DIR" "${LOGS_DIR}/tasks" "$STATE_DIR"

    STATUS_DIR="${STATE_DIR}/exit_codes"; mkdir -p "$STATUS_DIR"
    TASK_LOG_DIR="${LOGS_DIR}/tasks"
    STATE_FILE="${STATE_DIR}/tasks.state"
    SESSION_LOG="${LOGS_DIR}/session.log"
    ERROR_LOG_PATH="${LOGS_DIR}/errors.log"

    if [[ -z "$resume_dir" ]]; then
        local target_root; target_root="$(dirname "$OUTDIR")"
        ln -sfn "$(basename "$OUTDIR")" "${target_root}/latest" 2>/dev/null || true
    fi
    return 0
}

find_previous_run_for_resume() {
    local target="$1" root="${EXPLICIT_OUTDIR:-$CFG_OUTPUT_ROOT}"
    local target_dir="${root}/${target}"
    if [[ ! -d "$target_dir" ]]; then
        return 1
    fi
    local latest
    latest="$(find "$target_dir" -mindepth 1 -maxdepth 1 -type d ! -name latest 2>/dev/null | sort -r | head -1 || true)"
    if [[ -z "$latest" ]]; then
        return 1
    fi
    echo "$latest"
    return 0
}

_b() {
    if [[ "$1" == "true" ]]; then echo 1; else echo 0; fi
    return 0
}

register_all_tasks() {
    register_task target_info "Target Info & ASN Lookup" "" \
        task_target_info "${PARSED_DIR}/target_info.txt" "$(_b "$CFG_TARGET_INFO")"
    register_task whois "WHOIS" "" \
        task_whois "${RAW_DIR}/whois.txt" "$(_b "$CFG_WHOIS")"
    register_task dns "DNS Records" "" \
        task_dns "${PARSED_DIR}/dns_records.txt" "$(_b "$CFG_DNS")"
    register_task security_headers "Security Headers / TLS / robots.txt" "" \
        task_security_headers "${PARSED_DIR}/security_headers.txt" "$(_b "$CFG_SECURITY_HEADERS")"
    register_task theharvester "theHarvester (3 sources)" "" \
        task_theharvester "${PARSED_DIR}/theharvester_subs.txt" "$(_b "$CFG_THEHARVESTER")"
    register_task crtsh "Certificate Transparency (crt.sh)" "" \
        task_crtsh "${PARSED_DIR}/crtsh_subs.txt" "$(_b "$CFG_CRTSH")"
    register_task assetfinder "Subdomains — assetfinder" "" \
        task_assetfinder "${RAW_DIR}/assetfinder.txt" "$(_b "$CFG_ASSETFINDER")"
    register_task amass "Subdomains — amass (passive)" "" \
        task_amass "${RAW_DIR}/amass.txt" "$(_b "$CFG_AMASS")"
    register_task dnsrecon "DNSRecon (standard)" "" \
        task_dnsrecon "${RAW_DIR}/dnsrecon.txt" "$(_b "$CFG_DNSRECON")"
    register_task wafw00f "WAF Detection" "" \
        task_wafw00f "${PARSED_DIR}/waf.txt" "$(_b "$CFG_WAF_DETECT")"
    register_task whatweb "Technology Fingerprint" "" \
        task_whatweb "${PARSED_DIR}/technologies.txt" "$(_b "$CFG_TECH_DETECT")"
    register_task nmap "Port Scan (nmap)" "" \
        task_nmap "${PORTS_DIR}/open_ports.txt" "$(_b "$CFG_PORT_SCAN")"

    register_task merge_subdomains "Merge & Deduplicate Subdomains" \
        "theharvester crtsh assetfinder amass" \
        task_merge_subdomains "${PARSED_DIR}/subdomains.txt" 1

    register_task probe_alive "Live Host Probe" "merge_subdomains" \
        task_probe_alive "${PARSED_DIR}/alive_hosts.txt" 1
    register_task waybackurls "Historical URLs (wayback)" "merge_subdomains" \
        task_waybackurls "${OUTDIR}/wayback_raw.txt" "$(_b "$CFG_WAYBACK")"

    register_task screenshots "Screenshots" "probe_alive" \
        task_screenshots "" "$(_b "$CFG_SCREENSHOTS")"
    register_task nuclei "Nuclei Vulnerability Scan" "probe_alive" \
        task_nuclei "${NUCLEI_DIR}/findings.txt" "$(_b "$CFG_NUCLEI")"
    register_task url_filter "URL Filtering & Categorization" "waybackurls" \
        task_url_filter "${URLS_DIR}/all_live.txt" 1

    register_task js_extract "JS Endpoint Extraction" "url_filter" \
        task_js_extract "${PARSED_DIR}/js_endpoints.txt" "$(_b "$CFG_JS_SCAN")"

    register_task generate_report "Generate Report" \
        "target_info whois dns security_headers dnsrecon wafw00f whatweb nmap nuclei screenshots js_extract url_filter" \
        task_generate_report "${REPORTS_DIR}/target-recon.txt" 1
    return 0
}

print_final_summary() {
    local dur=$(( $(date +%s) - SCAN_START_EPOCH ))
    local name
    local -a failed_list=()
    for name in "${TASK_ORDER[@]}"; do
        if [[ "${TASK_STATUS[$name]}" == "failed" ]]; then
            failed_list+=("${TASK_LABEL[$name]}")
        fi
    done
    clear_live_status_line
    printf '\n%s══════════════════════════════════════════════════════════%s\n' "$GREEN" "$RESET"
    printf '  RECON COMPLETE — %s\n' "$TARGET"
    printf '%s══════════════════════════════════════════════════════════%s\n' "$GREEN" "$RESET"
    printf '  Duration : %s\n' "$(human_duration "$dur")"
    printf '  Output   : %s/\n' "$OUTDIR"
    printf '  Report   : %s/reports/target-recon.txt\n' "$OUTDIR"
    if [[ "${#failed_list[@]}" -gt 0 ]]; then
        printf '  %sFailed (see logs/errors.log):%s %s\n' "$YELLOW" "$RESET" "${failed_list[*]}"
    fi
    printf '\n'
    return 0
}

run_single_target() {
    local target="$1"
    TARGET="${target,,}"
    CURRENT_TARGET="$TARGET"
    TARGET_ESC="${TARGET//./\\.}"
    IS_IP="false"
    if is_ip_address "$TARGET"; then
        IS_IP="true"
    fi

    local resume_dir=""
    if [[ "$RESUME_REQUESTED" == "true" ]]; then
        if [[ -n "$RESUME_DIR" ]]; then
            resume_dir="$RESUME_DIR"
        else
            resume_dir="$(find_previous_run_for_resume "$TARGET" || true)"
            if [[ -z "$resume_dir" ]]; then
                log_warn "No previous run found for '${TARGET}' — starting fresh."
            fi
        fi
    fi

    setup_output_dirs "$TARGET" "$resume_dir"

    if ! acquire_lock "$OUTDIR"; then
        return 1
    fi

    SCAN_START_EPOCH="$(date +%s)"
    log_info "Target: ${TARGET}  |  Output: ${OUTDIR}"
    snapshot_config "${STATE_DIR}/config_snapshot.conf"

    # Fresh engine state per target (matters for multi-target / -l runs).
    TASK_ORDER=(); TASK_LABEL=(); TASK_DEPS=(); TASK_ENABLED=(); TASK_FUNC=(); TASK_OUTFILE=()
    TASK_STATUS=(); TASK_PID=(); TASK_START=(); TASK_END=(); TASK_ATTEMPTS=(); TASK_PREV_STATUS=()
    _VISIT_STATE=()
    LIVE_STATUS_ACTIVE=false

    register_all_tasks
    validate_task_graph

    if [[ -n "$resume_dir" ]]; then
        load_state_for_resume "$STATE_FILE"
    fi

    run_task_graph
    print_final_summary
    return 0
}

resolve_scan_mode() {
    if [[ -z "$CFG_SCAN_MODE" ]]; then
        if [[ "$UI_MODE" != "plain" && "$ASSUME_YES" != "true" ]]; then
            printf '%s[?] Scan mode:%s\n' "$CYAN" "$RESET"
            printf '    1) Full  — every module, thorough, can take 10-20+ min on a big target\n'
            printf '    2) Fast  — skips nuclei/wayback, short per-tool timeouts, usually a few minutes\n'
            local choice=""
            read -rp "  >>> [1/2, default 1]: " choice
            if [[ "$choice" == "2" ]]; then
                CFG_SCAN_MODE="fast"
            else
                CFG_SCAN_MODE="full"
            fi
        else
            CFG_SCAN_MODE="full"
        fi
    fi

    if [[ "$CFG_SCAN_MODE" == "fast" ]]; then
        TOOL_TIMEOUT="$CFG_FAST_TOOL_TIMEOUT"
        CFG_NUCLEI=false
        CFG_WAYBACK=false
        CFG_JS_SCAN=false
        log_info "Fast scan mode: nuclei/wayback/JS-extraction disabled, ${TOOL_TIMEOUT}s cap per tool."
    else
        TOOL_TIMEOUT="$CFG_TOOL_TIMEOUT"
        log_info "Full scan mode: ${TOOL_TIMEOUT}s cap per tool (use --fast for a quicker pass)."
    fi
    return 0
}

main() {
    parse_cli_args "$@"

    if [[ -n "$CONFIG_FILE" ]]; then
        if ! load_config_file "$CONFIG_FILE"; then
            exit 1
        fi
    elif [[ -f "./recon.conf" ]]; then
        load_config_file "./recon.conf" || true
    fi
    validate_config || true

    resolve_ui_mode
    show_banner
    resolve_scan_mode

    if [[ "$CFG_CONNECTIVITY_CHECK" == "true" ]]; then
        if ! check_connectivity; then
            log_warn "Could not verify internet connectivity."
            if [[ "$ASSUME_YES" != "true" && "$UI_MODE" != "plain" ]]; then
                local yn=""
                read -rp "  Continue anyway? [y/N]: " yn
                if ! [[ "$yn" =~ ^[Yy]$ ]]; then
                    exit 1
                fi
            fi
        fi
    fi

    check_tools

    local -a targets=()
    if [[ -n "$TARGET_LIST_FILE" ]]; then
        if [[ ! -f "$TARGET_LIST_FILE" ]]; then
            log_error "Target list file not found: $TARGET_LIST_FILE"
            exit 1
        fi
        local line
        while IFS= read -r line; do
            line="$(echo "$line" | tr -d '[:space:]' || true)"
            if [[ -n "$line" ]]; then
                targets+=("$line")
            fi
        done < "$TARGET_LIST_FILE"
    elif [[ -n "$TARGET" ]]; then
        targets+=("$TARGET")
    elif [[ "$RESUME_REQUESTED" == "true" && -n "$RESUME_DIR" ]]; then
        # Infer target from output/<target>/<timestamp> — the whole point of
        # `--resume DIR` is not having to retype the target.
        local inferred; inferred="$(basename "$(dirname "$RESUME_DIR")")"
        if [[ -z "$inferred" ]]; then
            log_error "Could not infer target from --resume path: $RESUME_DIR"
            exit 1
        fi
        log_info "Resuming target '${inferred}' (inferred from ${RESUME_DIR})"
        targets+=("$inferred")
    else
        printf '%s[?] Enter target (domain or IPv4):%s\n' "$CYAN" "$RESET"
        local t=""
        read -r -p "  >>> " t
        t="${t//[[:space:]]/}"
        targets+=("$t")
    fi

    local t
    for t in "${targets[@]}"; do
        t="${t,,}"
        if [[ -z "$t" ]]; then
            log_error "Empty target — skipping."
            continue
        fi
        if ! [[ "$t" =~ ^[a-z0-9._-]+$ ]]; then
            log_error "Invalid target '${t}' (allowed: a-z 0-9 . - _) — skipping."
            continue
        fi
        run_single_target "$t"
    done
    return 0
}

main "$@"
