#!/bin/bash
# ============================================================
#  recon_subdomains.sh — Subdomain Recon Script v2.6
#  Uso: ./recon_subdomains.sh -d <dominio> [--passive|--bruteforce|--all]
# ============================================================

set -uo pipefail

# ─── Estilos ────────────────────────────────────────────────
BOLD='\033[1m'
DIM='\033[2m'
RED='\033[0;31m'
YEL='\033[1;33m'
GRN='\033[0;32m'
CYA='\033[0;36m'
MAG='\033[0;35m'
BLU='\033[0;34m'
NC='\033[0m'

ICO_OK="✔"
ICO_FAIL="✘"
ICO_SKIP="○"
ICO_RUN="›"
ICO_KEY="⚿"
ICO_WARN="!"

# ─── Valores por defecto ────────────────────────────────────
DOMAIN=""
OUTPUT_DIR=""
MODE_PASSIVE=false
MODE_BRUTEFORCE=false
SKIP_ACTIVE=false
FORCE=false
VERBOSE=false
NO_CONFIRM=false
TAKEOVER=false
DIFF=false           # --diff: comparar con run anterior
NOTIFY=false         # --notify: notificación de escritorio al terminar
DEBUG=false          # --debug: traza en tiempo real de cada fuente
STEP_TIMEOUT=300
BRUTE_TIMEOUT=3600      # timeout específico para DNS bruteforce (puede tardar)
LOG=""
START_TIME=0
PROGRESS_DIR=""
SPINNER_PID=""
RAW_DIR=""           # $OUTPUT_DIR/raw  — datos intermedios (no tocar normalmente)
PASSIVE_DIR=""       # $RAW_DIR/passive
BRUTEFORCE_DIR=""    # $RAW_DIR/bruteforce

# ─── Opciones de fuerza bruta ───────────────────────────────
WORDLIST=""             # ruta personalizada (opcional)
WORDLIST_SIZE="med"     # small=5k | med=100k | big=2M
RESOLVERS_FILE=""       # ruta personalizada (opcional)
CACHE_DIR="$HOME/.recon_subdomains"   # caché de wordlists y resolvers
RECURSIVE_DEPTH=1               # niveles de recursión (0 = desactivado)
CRAWL_DEPTH=3                   # profundidad de crawling (katana -d)
CRAWL_MAX_SUBS=30               # máx. subdominios vivos a crawlear además del raíz

# ─── Herramientas ───────────────────────────────────────────
REQUIRED_TOOLS=(curl)
PASSIVE_TOOLS=(subfinder assetfinder findomain amass github-subdomains chaos jq)
BRUTEFORCE_TOOLS=(puredns shuffledns dnsx amass alterx gotator katana gospider gau subjs unfurl httpx)
COMMON_TOOLS=(httpx jq dig subzy nuclei)

# ─── Claves API necesarias en modo pasivo (para mostrar estado) ──
# SECURITYTRAILS_KEY   SecurityTrails API
# CENSYS_PAT                 Censys v2 Personal Access Token  (preferido)
# CENSYS_ID / CENSYS_SECRET  Censys v2 App ID + Secret        (alternativa)
# BINARYEDGE_KEY       BinaryEdge API
# BEVIGIL_KEY          BeVigil OSINT API
# FULLHUNT_KEY         FullHunt API
# NETLAS_KEY           Netlas API
# SHODAN_API_KEY       Shodan DNS API
# FB_TOKEN             Facebook CT (opcional; funciona sin él)

declare -A TOOL_OK=()
declare -A KEY_OK=()

# ============================================================
# UI — Banner, fases, estados
# ============================================================

_mode_label() {
    if $MODE_PASSIVE && $MODE_BRUTEFORCE; then
        echo -e "${MAG}${BOLD}Completo (pasivo + fuerza bruta)${NC}"
    elif $MODE_PASSIVE; then
        echo -e "${BLU}${BOLD}Pasivo${NC} ${DIM}(OSINT, sin tocar el target)${NC}"
    elif $MODE_BRUTEFORCE; then
        echo -e "${RED}${BOLD}Fuerza bruta${NC} ${DIM}(envía tráfico al target)${NC}"
    else
        echo "(sin modo)"
    fi
}

# Devuelve color del marco según el modo activo
_banner_color() {
    if $MODE_PASSIVE && $MODE_BRUTEFORCE; then echo "$MAG"
    elif $MODE_BRUTEFORCE; then echo "$RED"
    else echo "$BLU"; fi
}

# Estimación de duración orientativa basada en modo + wordlist size
_estimate_duration() {
    local mins=0
    if $MODE_PASSIVE; then
        local keys_active=0
        for _k in github virustotal chaos securitytrails censys binaryedge \
                   bevigil fullhunt netlas shodan; do
            [[ "${KEY_OK[$_k]:-false}" == true ]] && (( keys_active++ )) || true
        done
        (( mins += 3 + keys_active ))   # base 3 min + ~1 min por API de pago
    fi
    if $MODE_BRUTEFORCE; then
        case "$WORDLIST_SIZE" in
            small) (( mins +=  5 ))  ;;
            med)   (( mins += 25 ))  ;;
            big)   (( mins += 120 )) ;;
        esac
        (( RECURSIVE_DEPTH > 0 )) && (( mins += 10 * RECURSIVE_DEPTH )) || true
        (( CRAWL_DEPTH > 0 ))     && (( mins += 5 )) || true
    fi
    if   (( mins == 0 )); then echo "< 1 min"
    elif (( mins <  60 )); then echo "~${mins} min"
    else printf "~%dh %02dmin" $(( mins / 60 )) $(( mins % 60 ))
    fi
}

banner() {
    local c; c=$(_banner_color)
    local est; est=$(_estimate_duration)

    echo ""
    echo -e "${c}${BOLD}  ╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${c}${BOLD}  ║${NC}${BOLD}        RECON SUBDOMAINS  v2.6                        ${c}${BOLD}║${NC}"
    echo -e "${c}${BOLD}  ║${NC}${DIM}        Subdomain Discovery & Recon Automation        ${c}${BOLD}║${NC}"
    echo -e "${c}${BOLD}  ╠══════════════════════════════════════════════════════╣${NC}"
    printf "${c}${BOLD}  ║${NC}  ${BOLD}%-10s${NC}  %-40s${c}${BOLD}║${NC}\n" "Target:"  "$DOMAIN"
    printf "${c}${BOLD}  ║${NC}  ${BOLD}%-10s${NC}  %-40s${c}${BOLD}║${NC}\n" "Output:"  "$OUTPUT_DIR/"
    printf "${c}${BOLD}  ║${NC}  ${BOLD}%-10s${NC}  %-40s${c}${BOLD}║${NC}\n" "Timeout:" "${STEP_TIMEOUT}s/tool"
    printf "${c}${BOLD}  ║${NC}  ${BOLD}%-10s${NC}  %-40s${c}${BOLD}║${NC}\n" "ETA:"     "$est"
    # La línea de "Modo" lleva escape codes; sin padding exacto
    echo -e "${c}${BOLD}  ║${NC}  ${BOLD}Modo:${NC}       $(_mode_label)"
    echo -e "${c}${BOLD}  ╚══════════════════════════════════════════════════════╝${NC}"
    echo ""
}

phase() {
    local label="$1" color="${2:-$BLU}"
    echo ""
    echo -e "${BOLD}${color}  ┌─ $label ${NC}${DIM}$(printf '─%.0s' {1..40})${NC}"
    $DEBUG && printf "${DIM}[$(date '+%H:%M:%S')] FASE  %s${NC}\n" "$label" >&2 || true
    echo ""
}

phase_end() {
    echo -e "${DIM}  └$(printf '─%.0s' {1..54})${NC}"
}

tool_badge() {
    local name="$1"
    if [[ "${TOOL_OK[$name]:-false}" == true ]]; then
        printf "${GRN}${ICO_OK}${NC} %-18s" "$name"
    else
        printf "${DIM}${ICO_SKIP} %-18s${NC}" "$name"
    fi
}

key_badge() {
    local name="$1" label="$2"
    if [[ "${KEY_OK[$name]:-false}" == true ]]; then
        printf "${GRN}${ICO_KEY}${NC} %-20s" "$label"
    else
        printf "${DIM}${ICO_SKIP} %-20s${NC}" "$label"
    fi
}

_status_line() {
    local icon="$1" color="$2" tag="$3" name="$4" detail="$5"
    printf "${color}  %s ${BOLD}%-6s${NC}  %-22s %s\n" \
        "$icon" "$tag" "$name" "$detail" | tee -a "$LOG"
}

ok_msg()   { _status_line "$ICO_OK"   "$GRN" "[OK]"   "$1" "$2"; }
fail_msg() { _status_line "$ICO_FAIL" "$RED" "[FAIL]" "$1" "$2"; }
skip_msg() { _status_line "$ICO_SKIP" "$DIM" "[SKIP]" "$1" "$2"; }
info_msg() { printf "${CYA}  ${ICO_RUN}${NC}  %s\n" "$*" | tee -a "$LOG"; }
die()      { echo -e "\n${RED}  ${ICO_FAIL} ERROR: $*${NC}" >&2; exit 1; }

elapsed_fmt() {
    local secs=$1
    if (( secs < 60 )); then
        echo "${secs}s"
    else
        printf "%dm%02ds" $(( secs/60 )) $(( secs%60 ))
    fi
}

# ─── Spinner ────────────────────────────────────────────────
# Monitor de debug: cada 5 s imprime qué fuentes siguen pendientes
_debug_monitor() {
    local total="${1:-0}"
    local expected_file="$PROGRESS_DIR/.expected"
    while true; do
        sleep 5
        [[ -d "$PROGRESS_DIR" ]] || break
        local done_count
        done_count=$(ls "$PROGRESS_DIR"/*.done 2>/dev/null | wc -l || echo 0)
        (( done_count >= total && total > 0 )) && break
        local pending=()
        if [[ -f "$expected_file" ]]; then
            while IFS= read -r _src; do
                [[ -f "$PROGRESS_DIR/${_src}.done" ]] || pending+=("$_src")
            done < "$expected_file"
        fi
        local ela=$(( SECONDS - START_TIME ))
        printf "${YEL}[$(date '+%H:%M:%S')] ⏳  %d/%d completadas — pendientes: %s  [%s]${NC}\n" \
            "$done_count" "$total" "${pending[*]:-?}" "$(elapsed_fmt "$ela")" >&2
    done
}

start_spinner() {
    local msg="$1" total="${2:-0}"

    # En modo debug: sustituimos el spinner por el monitor de texto
    if $DEBUG; then
        printf "${CYA}[$(date '+%H:%M:%S')] ▶  %s (%d fuentes)${NC}\n" "$msg" "$total" >&2
        _debug_monitor "$total" &
        SPINNER_PID=$!
        return
    fi

    (
        local frames='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
        local i=0
        while true; do
            local done_count=0
            [[ -d "$PROGRESS_DIR" ]] && done_count=$(ls "$PROGRESS_DIR"/*.done 2>/dev/null | wc -l || echo 0)
            local fi=$(( i % 10 ))
            local frame="${frames:$fi:1}"
            if (( total > 0 )); then
                printf "\r  ${CYA}%s${NC}  %s  ${BOLD}%d/%d${NC} completadas..." \
                    "$frame" "$msg" "$done_count" "$total"
            else
                printf "\r  ${CYA}%s${NC}  %s..." "$frame" "$msg"
            fi
            (( i++ )) || true
            sleep 0.12
        done
    ) &
    SPINNER_PID=$!
}

stop_spinner() {
    if [[ -n "$SPINNER_PID" ]]; then
        kill "$SPINNER_PID" 2>/dev/null
        wait "$SPINNER_PID" 2>/dev/null || true
        SPINNER_PID=""
    fi
    printf "\r%80s\r" ""
}

log_only() { echo -e "[$(date '+%H:%M:%S')] $*" >> "$LOG"; }

# Imprime solo en modo --debug (va a stderr para no contaminar tuberías)
dbg() {
    $DEBUG || return 0
    printf "${DIM}[$(date '+%H:%M:%S')] DBG  %s${NC}\n" "$*" >&2
}

# ============================================================
# Helpers
# ============================================================
safe_curl() {
    dbg "curl → $1"
    curl --retry 3 --retry-delay 3 --max-time 60 -fsSL "$@"
}

normalize_and_filter() {
    local file="$1"
    [[ -s "$file" ]] || return 0
    sed -e 's|https\?://||g' -e 's|/.*||g' -e 's/\*\.//g' -e 's/[[:space:]]//g' "$file" \
        | tr '[:upper:]' '[:lower:]' \
        | grep -E "(^|\.)${DOMAIN}$" \
        | sort -u > "${file}.tmp" && mv "${file}.tmp" "$file"
}

report_done() {
    local name="$1" status="$2" count="$3" elapsed="$4"
    log_only "[${status^^}] $name — ${count} líneas (${elapsed}s)"
    echo "${status}|${count}|${elapsed}" > "$PROGRESS_DIR/${name}.done"
    if $DEBUG; then
        local _icon _color
        case "$status" in
            ok)   _icon="$ICO_OK"   _color="$GRN" ;;
            fail) _icon="$ICO_FAIL" _color="$RED" ;;
            skip) _icon="$ICO_SKIP" _color="$DIM" ;;
            *)    _icon="?"         _color="$NC"  ;;
        esac
        printf "${_color}[$(date '+%H:%M:%S')] %s  %-24s %-6s  %s resultados  %ss${NC}\n" \
            "$_icon" "$name" "$status" "$count" "$elapsed" >&2
    fi
}

_src_run() {
    local name="$1" outfile="$2"; shift 2
    if [[ "$FORCE" == false && -s "$outfile" ]]; then
        report_done "$name" "skip" "$(wc -l < "$outfile")" "0"; return 0
    fi
    dbg "→ STARTING  $name"
    touch "$outfile"
    local start=$SECONDS
    if timeout "$STEP_TIMEOUT" "$@" >> "$outfile" 2>>"$LOG"; then
        normalize_and_filter "$outfile"
        local count; count=$(wc -l < "$outfile" 2>/dev/null || echo 0)
        report_done "$name" "ok" "$count" "$(( SECONDS - start ))"
    else
        local code=$? elapsed=$(( SECONDS - start ))
        report_done "$name" "fail" "0" "$elapsed"
        touch "$outfile"
    fi
}

print_source_table() {
    local sources=("$@")
    echo ""
    printf "  ${DIM}%-24s  %-10s  %-10s  %s${NC}\n" "FUENTE" "ESTADO" "HALLAZGOS" "TIEMPO"
    printf "  ${DIM}%-24s  %-10s  %-10s  %s${NC}\n" \
        "────────────────────────" "──────────" "──────────" "───────"
    for name in "${sources[@]}"; do
        local donefile="$PROGRESS_DIR/${name}.done"
        if [[ -f "$donefile" ]]; then
            IFS='|' read -r status count elapsed < "$donefile"
            case "$status" in
                ok)
                    local color="$GRN" icon="$ICO_OK" tag="ok"
                    (( count == 0 )) && { color="$DIM"; icon="$ICO_SKIP"; tag="empty"; }
                    printf "  ${color}%-24s  %s %-8s  %-10s  %s${NC}\n" \
                        "$name" "$icon" "$tag" "$count" "$(elapsed_fmt "$elapsed")" ;;
                fail)
                    printf "  ${RED}%-24s  %s %-8s  %-10s  %s${NC}\n" \
                        "$name" "$ICO_FAIL" "fail" "$count" "$(elapsed_fmt "$elapsed")" ;;
                skip)
                    printf "  ${DIM}%-24s  %s %-8s  %-10s  %s${NC}\n" \
                        "$name" "$ICO_SKIP" "skip" "-" "-" ;;
            esac
        else
            printf "  ${DIM}%-24s  %s %-8s${NC}\n" "$name" "?" "no-run"
        fi
    done
    echo ""
}

# ============================================================
# Parseo de argumentos + menú interactivo
# ============================================================
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -d|--domain)      DOMAIN="${2:?'Falta el dominio'}"; shift 2 ;;
            -o|--output)      OUTPUT_DIR="${2:?'Falta el directorio'}"; shift 2 ;;
            --passive)          MODE_PASSIVE=true; shift ;;
            --bruteforce)       MODE_BRUTEFORCE=true; shift ;;
            --all)              MODE_PASSIVE=true; MODE_BRUTEFORCE=true; shift ;;
            --skip-active)      SKIP_ACTIVE=true; shift ;;
            -f|--force)         FORCE=true; shift ;;
            -v|--verbose)       VERBOSE=true; shift ;;
            --no-confirm)       NO_CONFIRM=true; shift ;;
            --takeover)         TAKEOVER=true; shift ;;
            --diff)             DIFF=true; shift ;;
            --notify)           NOTIFY=true; shift ;;
            --debug)            DEBUG=true; shift ;;
            -t|--timeout)       STEP_TIMEOUT="${2:?'Falta el timeout'}"; shift 2 ;;
            --brute-timeout)    BRUTE_TIMEOUT="${2:?'Falta el timeout'}"; shift 2 ;;
            -w|--wordlist)      WORDLIST="${2:?'Falta la ruta de la wordlist'}"; shift 2 ;;
            --wordlist-size)    WORDLIST_SIZE="${2:?'Falta el tamaño (small|med|big)'}"; shift 2 ;;
            -r|--resolvers)     RESOLVERS_FILE="${2:?'Falta la ruta de resolvers'}"; shift 2 ;;
            --recursive-depth)  RECURSIVE_DEPTH="${2:?'Falta el nivel (0-5)'}"; shift 2 ;;
            --crawl-depth)      CRAWL_DEPTH="${2:?'Falta la profundidad'}"; shift 2 ;;
            --skip-crawl)       CRAWL_DEPTH=0; shift ;;
            -h|--help)          usage; exit 0 ;;
            -*)               die "Argumento desconocido: $1" ;;
            *)                [[ -z "$DOMAIN" ]] && DOMAIN="$1" || die "Argumento inesperado: $1"; shift ;;
        esac
    done

    [[ -z "$DOMAIN" ]] && { usage; echo ""; die "Debes especificar un dominio con -d <dominio>"; }

    if ! echo "$DOMAIN" | grep -qE '^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'; then
        die "Formato de dominio inválido: '$DOMAIN'"
    fi

    OUTPUT_DIR="${OUTPUT_DIR:-output_${DOMAIN}}"
}

interactive_menu() {
    # Solo mostrar menú si ningún modo fue elegido y hay TTY
    if $MODE_PASSIVE || $MODE_BRUTEFORCE; then return; fi
    if [[ ! -t 0 ]]; then
        die "No se especificó modo (--passive / --bruteforce / --all) y no hay TTY para menú interactivo"
    fi

    echo ""
    echo -e "${CYA}${BOLD}  ╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYA}${BOLD}  ║${NC}${BOLD}  Selecciona el modo de reconocimiento                ${CYA}║${NC}"
    echo -e "${CYA}${BOLD}  ╠══════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYA}${BOLD}  ║${NC}                                                      ${CYA}║${NC}"
    echo -e "${CYA}${BOLD}  ║${NC}   ${BOLD}[1]${NC}  ${BLU}${BOLD}PASIVO${NC}        OSINT puro, sigiloso            ${CYA}║${NC}"
    echo -e "${CYA}${BOLD}  ║${NC}                       ${DIM}~13 fuentes, sin tocar target  ${NC}${CYA}║${NC}"
    echo -e "${CYA}${BOLD}  ║${NC}                       ${DIM}⚡ rápido  (2-5 min)           ${NC}${CYA}║${NC}"
    echo -e "${CYA}${BOLD}  ║${NC}                                                      ${CYA}║${NC}"
    echo -e "${CYA}${BOLD}  ║${NC}   ${BOLD}[2]${NC}  ${RED}${BOLD}FUERZA BRUTA${NC}  Permutaciones + enum activo      ${CYA}║${NC}"
    echo -e "${CYA}${BOLD}  ║${NC}                       ${DIM}Envía consultas DNS al target  ${NC}${CYA}║${NC}"
    echo -e "${CYA}${BOLD}  ║${NC}                       ${DIM}🔥 exhaustivo (10-30 min)      ${NC}${CYA}║${NC}"
    echo -e "${CYA}${BOLD}  ║${NC}                                                      ${CYA}║${NC}"
    echo -e "${CYA}${BOLD}  ║${NC}   ${BOLD}[3]${NC}  ${MAG}${BOLD}COMPLETO${NC}      Pasivo + Fuerza bruta            ${CYA}║${NC}"
    echo -e "${CYA}${BOLD}  ║${NC}                       ${DIM}Máximo recall                  ${NC}${CYA}║${NC}"
    echo -e "${CYA}${BOLD}  ║${NC}                                                      ${CYA}║${NC}"
    echo -e "${CYA}${BOLD}  ║${NC}   ${BOLD}[q]${NC}  Cancelar                                       ${CYA}║${NC}"
    echo -e "${CYA}${BOLD}  ║${NC}                                                      ${CYA}║${NC}"
    echo -e "${CYA}${BOLD}  ╚══════════════════════════════════════════════════════╝${NC}"
    echo ""

    local choice
    while true; do
        read -r -p "  Elige [1/2/3/q]: " choice
        case "$choice" in
            1) MODE_PASSIVE=true;                            break ;;
            2) MODE_BRUTEFORCE=true;                         break ;;
            3) MODE_PASSIVE=true; MODE_BRUTEFORCE=true;      break ;;
            q|Q) echo -e "${YEL}  Cancelado.${NC}"; exit 0 ;;
            *) echo -e "${RED}  Opción inválida${NC}" ;;
        esac
    done
}

usage() {
    echo ""
    echo -e "${BOLD}  RECON SUBDOMAINS v2.6${NC}"
    echo -e "${DIM}  Subdomain discovery automatizado con múltiples fuentes${NC}"
    echo ""
    echo -e "${BOLD}  Uso:${NC}  $0 -d <dominio> [--passive|--bruteforce|--all] [opciones]"
    echo ""
    echo -e "${BOLD}  Modos:${NC}"
    echo -e "    ${BLU}--passive${NC}         OSINT puro (CT logs, APIs, archive) — sin tocar target"
    echo -e "    ${RED}--bruteforce${NC}      Permutaciones + enumeración activa — envía tráfico"
    echo -e "    ${MAG}--all${NC}             Ambos (máximo recall)"
    echo -e "    ${DIM}Si no se especifica modo, se muestra menú interactivo${NC}"
    echo ""
    echo -e "${BOLD}  Opciones generales:${NC}"
    echo -e "    ${CYA}-d, --domain${NC} <dom>         Dominio objetivo ${BOLD}(requerido)${NC}"
    echo -e "    ${CYA}-o, --output${NC} <dir>         Directorio de salida ${DIM}(default: output_<dominio>)${NC}"
    echo -e "    ${CYA}--skip-active${NC}              Saltar sondeo HTTP final (httpx)"
    echo -e "    ${CYA}-f, --force${NC}                Re-ejecutar aunque ya existan resultados"
    echo -e "    ${CYA}-t, --timeout${NC} <seg>        Timeout por herramienta ${DIM}(default: 300)${NC}"
    echo -e "    ${CYA}--no-confirm${NC}               No pedir confirmación para wordlists grandes"
    echo -e "    ${CYA}--takeover${NC}                 Ejecutar detección de subdomain takeover"
    echo -e "    ${CYA}--diff${NC}                     Comparar resultados con el run anterior (genera diff_new/gone.txt)"
    echo -e "    ${CYA}--notify${NC}                   Enviar notificación de escritorio al finalizar"
    echo -e "    ${CYA}--debug${NC}                    Traza en tiempo real: inicio/fin de cada fuente, URLs y pendientes cada 5 s"
    echo -e "    ${CYA}-v, --verbose${NC}              Modo verbose"
    echo -e "    ${CYA}-h, --help${NC}                 Mostrar esta ayuda"
    echo ""
    echo -e "${BOLD}  Opciones de fuerza bruta:${NC}"
    echo -e "    ${RED}-w, --wordlist${NC} <path>     Wordlist personalizada"
    echo -e "    ${RED}--wordlist-size${NC} <s>       Tamaño preset: ${BOLD}small${NC}=5k  ${BOLD}med${NC}=100k  ${BOLD}big${NC}=2M  ${DIM}(default: med)${NC}"
    echo -e "    ${RED}-r, --resolvers${NC} <path>    Fichero de resolvers DNS personalizado"
    echo -e "    ${RED}--brute-timeout${NC} <seg>     Timeout DNS bruteforce ${DIM}(default: 3600)${NC}"
    echo -e "    ${RED}--recursive-depth${NC} <n>    Niveles de recursión permutaciones ${DIM}(default: 1, 0=off)${NC}"
    echo -e "    ${RED}--crawl-depth${NC} <n>        Profundidad de crawling katana/gospider ${DIM}(default: 3)${NC}"
    echo -e "    ${RED}--skip-crawl${NC}              Desactivar fase de crawling"
    echo ""
    echo -e "${BOLD}  Variables de entorno:${NC}"
    echo -e "    ${MAG}GITHUB_TOKEN${NC}          Token de GitHub (github-subdomains)"
    echo -e "    ${MAG}VT_APIKEY${NC}             API key de VirusTotal"
    echo -e "    ${MAG}PDCP_API_KEY${NC}          API key de ProjectDiscovery (chaos)"
    echo -e "    ${MAG}SECURITYTRAILS_KEY${NC}    API key de SecurityTrails"
    echo -e "    ${MAG}CENSYS_PAT${NC}            Censys v2 Personal Access Token ${DIM}(preferido)${NC}"
    echo -e "    ${MAG}CENSYS_ID${NC}             Censys v2 App ID ${DIM}(alternativa a PAT)${NC}"
    echo -e "    ${MAG}CENSYS_SECRET${NC}         Censys v2 App Secret ${DIM}(alternativa a PAT)${NC}"
    echo -e "    ${MAG}BINARYEDGE_KEY${NC}        API key de BinaryEdge"
    echo -e "    ${MAG}BEVIGIL_KEY${NC}           API key de BeVigil OSINT"
    echo -e "    ${MAG}FULLHUNT_KEY${NC}          API key de FullHunt"
    echo -e "    ${MAG}NETLAS_KEY${NC}            API key de Netlas"
    echo -e "    ${MAG}SHODAN_API_KEY${NC}        API key de Shodan (DNS lookup)"
    echo -e "    ${MAG}FB_TOKEN${NC}              Facebook Graph token ${DIM}(opcional, aumenta límite CT)${NC}"
    echo ""
    echo -e "${BOLD}  Ejemplos:${NC}"
    echo -e "    ${DIM}./recon_subdomains.sh -d example.com --passive${NC}"
    echo -e "    ${DIM}./recon_subdomains.sh -d example.com --bruteforce${NC}"
    echo -e "    ${DIM}./recon_subdomains.sh -d example.com --all${NC}"
    echo -e "    ${DIM}GITHUB_TOKEN=ghp_xxx VT_APIKEY=yyy ./recon_subdomains.sh -d example.com --all${NC}"
    echo ""
}

# ============================================================
# Verificación de herramientas y claves
# ============================================================
check_dependencies() {
    phase "Verificación de entorno"

    local missing_required=()
    for tool in "${REQUIRED_TOOLS[@]}"; do
        command -v "$tool" &>/dev/null && TOOL_OK[$tool]=true \
            || { TOOL_OK[$tool]=false; missing_required+=("$tool"); }
    done

    # Detectar todas las demás herramientas (la disponibilidad dicta qué se ejecuta)
    local all_optional=("${PASSIVE_TOOLS[@]}" "${BRUTEFORCE_TOOLS[@]}" "${COMMON_TOOLS[@]}")
    for tool in "${all_optional[@]}"; do
        command -v "$tool" &>/dev/null && TOOL_OK[$tool]=true || TOOL_OK[$tool]=false
    done

    # Grid de herramientas según el modo elegido
    if $MODE_PASSIVE; then
        echo -e "  ${BOLD}Herramientas (modo pasivo):${NC}"
        local col=0; printf "    "
        for tool in "${PASSIVE_TOOLS[@]}"; do
            printf "$(tool_badge "$tool")"
            (( ++col % 3 == 0 )) && printf "\n    "
        done
        echo ""; echo ""
    fi

    if $MODE_BRUTEFORCE; then
        echo -e "  ${BOLD}Herramientas (modo fuerza bruta):${NC}"
        local col=0; printf "    "
        for tool in "${BRUTEFORCE_TOOLS[@]}"; do
            printf "$(tool_badge "$tool")"
            (( ++col % 3 == 0 )) && printf "\n    "
        done
        echo ""; echo ""
    fi

    # Claves API (solo relevantes en modo pasivo)
    KEY_OK[github]=false
    KEY_OK[virustotal]=false
    KEY_OK[chaos]=false
    KEY_OK[securitytrails]=false
    KEY_OK[censys]=false
    KEY_OK[binaryedge]=false
    KEY_OK[bevigil]=false
    KEY_OK[fullhunt]=false
    KEY_OK[netlas]=false
    KEY_OK[shodan]=false
    KEY_OK[facebook]=false
    [[ -n "${GITHUB_TOKEN:-}" ]]          && KEY_OK[github]=true
    [[ -n "${VT_APIKEY:-}" ]]             && KEY_OK[virustotal]=true
    [[ -n "${PDCP_API_KEY:-}" ]]          && KEY_OK[chaos]=true
    [[ -n "${SECURITYTRAILS_KEY:-}" ]]    && KEY_OK[securitytrails]=true
    [[ -n "${CENSYS_PAT:-}" ]]                           && KEY_OK[censys]=true
    [[ -n "${CENSYS_ID:-}" && -n "${CENSYS_SECRET:-}" ]] && KEY_OK[censys]=true
    [[ -n "${BINARYEDGE_KEY:-}" ]]        && KEY_OK[binaryedge]=true
    [[ -n "${BEVIGIL_KEY:-}" ]]           && KEY_OK[bevigil]=true
    [[ -n "${FULLHUNT_KEY:-}" ]]          && KEY_OK[fullhunt]=true
    [[ -n "${NETLAS_KEY:-}" ]]            && KEY_OK[netlas]=true
    [[ -n "${SHODAN_API_KEY:-}" ]]        && KEY_OK[shodan]=true
    # Facebook CT funciona sin token (limit bajo); con FB_TOKEN el límite sube
    KEY_OK[facebook]=true

    if $MODE_PASSIVE; then
        echo -e "  ${BOLD}Claves API:${NC}"
        local _keys_col=0; printf "    "
        for _kpair in \
            "github:GITHUB_TOKEN" \
            "virustotal:VT_APIKEY" \
            "chaos:PDCP_API_KEY" \
            "securitytrails:SECURITYTRAILS_KEY" \
            "censys:CENSYS_PAT|ID+SECRET" \
            "binaryedge:BINARYEDGE_KEY" \
            "bevigil:BEVIGIL_KEY" \
            "fullhunt:FULLHUNT_KEY" \
            "netlas:NETLAS_KEY" \
            "shodan:SHODAN_API_KEY" \
            "facebook:FB_TOKEN(opt)"; do
            local _kname="${_kpair%%:*}" _klabel="${_kpair##*:}"
            printf "$(key_badge "$_kname" "$_klabel")"
            (( ++_keys_col % 3 == 0 )) && printf "\n    "
        done
        echo ""; echo ""
    fi

    phase_end

    if [[ ${#missing_required[@]} -gt 0 ]]; then
        echo ""
        die "Herramientas requeridas no encontradas: ${missing_required[*]}"
    fi
}

# ============================================================
# MODO PASIVO — Fuentes
# ============================================================

src_subfinder() {
    [[ "${TOOL_OK[subfinder]:-false}" == true ]] || { report_done "subfinder" "skip" "0" "0"; return; }
    _src_run "subfinder" "$PASSIVE_DIR/subfinder.txt" \
        subfinder -d "$DOMAIN" --all --recursive -silent
}

src_assetfinder() {
    [[ "${TOOL_OK[assetfinder]:-false}" == true ]] || { report_done "assetfinder" "skip" "0" "0"; return; }
    _src_run "assetfinder" "$PASSIVE_DIR/assetfinder.txt" \
        assetfinder --subs-only "$DOMAIN"
}

src_findomain() {
    [[ "${TOOL_OK[findomain]:-false}" == true ]] || { report_done "findomain" "skip" "0" "0"; return; }
    _src_run "findomain" "$PASSIVE_DIR/findomain.txt" \
        findomain --quiet -t "$DOMAIN"
}

src_amass_passive() {
    [[ "${TOOL_OK[amass]:-false}" == true ]] || { report_done "amass_passive" "skip" "0" "0"; return; }
    local out="$PASSIVE_DIR/amass_passive.txt"
    if [[ "$FORCE" == false && -s "$out" ]]; then
        report_done "amass_passive" "skip" "$(wc -l < "$out")" "0"; return
    fi
    touch "$out"
    local start=$SECONDS
    timeout "$STEP_TIMEOUT" amass enum -passive -d "$DOMAIN" 2>>"$LOG" \
        | grep -oE "[a-zA-Z0-9._-]+\.${DOMAIN}" | sort -u >> "$out" || true
    normalize_and_filter "$out"
    report_done "amass_passive" "ok" "$(wc -l < "$out")" "$(( SECONDS - start ))"
}

src_github() {
    [[ "${KEY_OK[github]}" == true && "${TOOL_OK[github-subdomains]:-false}" == true ]] \
        || { report_done "github" "skip" "0" "0"; return; }
    _src_run "github" "$PASSIVE_DIR/github.txt" \
        github-subdomains -d "$DOMAIN" -t "$GITHUB_TOKEN" -raw
}

src_chaos() {
    [[ "${KEY_OK[chaos]}" == true && "${TOOL_OK[chaos]:-false}" == true ]] \
        || { report_done "chaos" "skip" "0" "0"; return; }
    _src_run "chaos" "$PASSIVE_DIR/chaos.txt" \
        chaos -d "$DOMAIN" -silent
}

src_crtsh() {
    [[ "${TOOL_OK[curl]:-false}" == true && "${TOOL_OK[jq]:-false}" == true ]] \
        || { report_done "crtsh" "skip" "0" "0"; return; }
    local out="$PASSIVE_DIR/crtsh.txt"
    [[ "$FORCE" == false && -s "$out" ]] && { report_done "crtsh" "skip" "$(wc -l < "$out")" "0"; return; }
    touch "$out"
    local start=$SECONDS
    local resp
    resp=$(safe_curl "https://crt.sh?q=${DOMAIN}&output=json" 2>>"$LOG" || echo "[]")
    if echo "$resp" | jq -e '.[0]' &>/dev/null 2>&1; then
        echo "$resp" | jq -r '.[].name_value' \
            | tr ',' '\n' | sed 's/^\*\.//' \
            | tr '[:upper:]' '[:lower:]' \
            | grep -E "(^|\.)${DOMAIN}$" \
            | sort -u >> "$out" 2>>"$LOG" || true
        report_done "crtsh" "ok" "$(wc -l < "$out")" "$(( SECONDS - start ))"
    else
        report_done "crtsh" "fail" "0" "$(( SECONDS - start ))"
    fi
}

src_wayback() {
    [[ "${TOOL_OK[curl]:-false}" == true ]] || { report_done "wayback" "skip" "0" "0"; return; }
    local out="$PASSIVE_DIR/wayback.txt"
    [[ "$FORCE" == false && -s "$out" ]] && { report_done "wayback" "skip" "$(wc -l < "$out")" "0"; return; }
    touch "$out"
    local start=$SECONDS
    safe_curl "http://web.archive.org/cdx/search/cdx?url=*.${DOMAIN}/*&output=text&fl=original&collapse=urlkey" \
        2>>"$LOG" \
        | sed -e 's|https\?://||' -e 's|/.*||' \
        | tr '[:upper:]' '[:lower:]' \
        | grep -E "(^|\.)${DOMAIN}$" \
        | sort -u >> "$out" || true
    report_done "wayback" "ok" "$(wc -l < "$out")" "$(( SECONDS - start ))"
}

src_virustotal() {
    [[ "${KEY_OK[virustotal]}" == true && "${TOOL_OK[curl]:-false}" == true && "${TOOL_OK[jq]:-false}" == true ]] \
        || { report_done "virustotal" "skip" "0" "0"; return; }
    local out="$PASSIVE_DIR/virustotal.txt"
    [[ "$FORCE" == false && -s "$out" ]] && { report_done "virustotal" "skip" "$(wc -l < "$out")" "0"; return; }
    touch "$out"
    local start=$SECONDS
    local resp
    resp=$(safe_curl "https://www.virustotal.com/vtapi/v2/domain/report?apikey=${VT_APIKEY}&domain=${DOMAIN}" \
        2>>"$LOG" || echo "{}")
    { echo "$resp" | jq -r '.domain_siblings[]?' 2>/dev/null || true; } >> "$out"
    { echo "$resp" | jq -r '.subdomains[]?'      2>/dev/null || true; } >> "$out"
    normalize_and_filter "$out"
    report_done "virustotal" "ok" "$(wc -l < "$out")" "$(( SECONDS - start ))"
}

src_alienvault() {
    [[ "${TOOL_OK[curl]:-false}" == true && "${TOOL_OK[jq]:-false}" == true ]] \
        || { report_done "alienvault" "skip" "0" "0"; return; }
    local out="$PASSIVE_DIR/alienvault.txt"
    [[ "$FORCE" == false && -s "$out" ]] && { report_done "alienvault" "skip" "$(wc -l < "$out")" "0"; return; }
    touch "$out"
    local start=$SECONDS
    safe_curl "https://otx.alienvault.com/api/v1/indicators/hostname/${DOMAIN}/passive_dns" 2>>"$LOG" \
        | jq -r '.passive_dns[]?.hostname // empty' 2>/dev/null \
        | tr '[:upper:]' '[:lower:]' \
        | grep -E "(^|\.)${DOMAIN}$" \
        | sort -u >> "$out" || true
    report_done "alienvault" "ok" "$(wc -l < "$out")" "$(( SECONDS - start ))"
}

src_urlscan() {
    [[ "${TOOL_OK[curl]:-false}" == true && "${TOOL_OK[jq]:-false}" == true ]] \
        || { report_done "urlscan" "skip" "0" "0"; return; }
    local out="$PASSIVE_DIR/urlscan.txt"
    [[ "$FORCE" == false && -s "$out" ]] && { report_done "urlscan" "skip" "$(wc -l < "$out")" "0"; return; }
    touch "$out"
    local start=$SECONDS
    safe_curl "https://urlscan.io/api/v1/search/?q=domain:${DOMAIN}&size=10000" 2>>"$LOG" \
        | jq -r '.results[].page?.domain // empty' 2>/dev/null \
        | tr '[:upper:]' '[:lower:]' \
        | grep -E "(^|\.)${DOMAIN}$" \
        | sort -u >> "$out" || true
    report_done "urlscan" "ok" "$(wc -l < "$out")" "$(( SECONDS - start ))"
}

src_hackertarget() {
    [[ "${TOOL_OK[curl]:-false}" == true ]] || { report_done "hackertarget" "skip" "0" "0"; return; }
    local out="$PASSIVE_DIR/hackertarget.txt"
    [[ "$FORCE" == false && -s "$out" ]] && { report_done "hackertarget" "skip" "$(wc -l < "$out")" "0"; return; }
    touch "$out"
    local start=$SECONDS
    safe_curl "https://api.hackertarget.com/hostsearch/?q=${DOMAIN}" 2>>"$LOG" \
        | cut -d',' -f1 \
        | tr '[:upper:]' '[:lower:]' \
        | grep -E "(^|\.)${DOMAIN}$" \
        | sort -u >> "$out" || true
    report_done "hackertarget" "ok" "$(wc -l < "$out")" "$(( SECONDS - start ))"
}

src_rapiddns() {
    [[ "${TOOL_OK[curl]:-false}" == true ]] || { report_done "rapiddns" "skip" "0" "0"; return; }
    local out="$PASSIVE_DIR/rapiddns.txt"
    [[ "$FORCE" == false && -s "$out" ]] && { report_done "rapiddns" "skip" "$(wc -l < "$out")" "0"; return; }
    touch "$out"
    local start=$SECONDS
    safe_curl "https://rapiddns.io/subdomain/${DOMAIN}?full=1#result" 2>>"$LOG" \
        | grep -oE "[a-zA-Z0-9._-]+\.${DOMAIN}" \
        | tr '[:upper:]' '[:lower:]' \
        | sort -u >> "$out" || true
    report_done "rapiddns" "ok" "$(wc -l < "$out")" "$(( SECONDS - start ))"
}

# ── Fuentes adicionales (Fase 2) ─────────────────────────────

src_securitytrails() {
    [[ "${KEY_OK[securitytrails]:-false}" == true && "${TOOL_OK[curl]:-false}" == true && "${TOOL_OK[jq]:-false}" == true ]] \
        || { report_done "securitytrails" "skip" "0" "0"; return; }
    local out="$PASSIVE_DIR/securitytrails.txt"
    [[ "$FORCE" == false && -s "$out" ]] && { report_done "securitytrails" "skip" "$(wc -l < "$out")" "0"; return; }
    touch "$out"
    local start=$SECONDS
    safe_curl "https://api.securitytrails.com/v1/domain/${DOMAIN}/subdomains?children_only=false&include_inactive=true" \
        -H "APIKEY: ${SECURITYTRAILS_KEY:-}" 2>>"$LOG" \
        | jq -r '.subdomains[]?' 2>/dev/null \
        | sed "s/\$/.${DOMAIN}/" \
        | tr '[:upper:]' '[:lower:]' \
        | grep -E "(^|\.)${DOMAIN//./\\.}$" \
        | sort -u >> "$out" || true
    normalize_and_filter "$out"
    report_done "securitytrails" "ok" "$(wc -l < "$out")" "$(( SECONDS - start ))"
}

src_censys() {
    [[ "${KEY_OK[censys]:-false}" == true && "${TOOL_OK[curl]:-false}" == true && "${TOOL_OK[jq]:-false}" == true ]] \
        || { report_done "censys" "skip" "0" "0"; return; }
    local out="$PASSIVE_DIR/censys.txt"
    [[ "$FORCE" == false && -s "$out" ]] && { report_done "censys" "skip" "$(wc -l < "$out")" "0"; return; }
    touch "$out"
    local start=$SECONDS

    # Elegir método de autenticación:
    #   PAT  → Authorization: Bearer <token>
    #   ID+Secret → HTTP Basic (-u id:secret)
    local -a _censys_auth=()
    if [[ -n "${CENSYS_PAT:-}" ]]; then
        _censys_auth=(-H "Authorization: Bearer ${CENSYS_PAT}")
    else
        _censys_auth=(-u "${CENSYS_ID:-}:${CENSYS_SECRET:-}")
    fi

    # Censys v2 — búsqueda en certificados TLS
    local cursor="" page=0
    while :; do
        local url="https://search.censys.io/api/v2/certificates/search?q=parsed.names%3A${DOMAIN}&per_page=100"
        [[ -n "$cursor" ]] && url+="&cursor=${cursor}"
        local resp
        resp=$(safe_curl "$url" \
            "${_censys_auth[@]}" \
            -H "Accept: application/json" 2>>"$LOG" || echo "{}")
        echo "$resp" | jq -r '.result.hits[]?.parsed?.names[]?' 2>/dev/null \
            | tr '[:upper:]' '[:lower:]' \
            | grep -E "(^|\.)${DOMAIN//./\\.}$" >> "$out" || true
        cursor=$(echo "$resp" | jq -r '.result.links.next // empty' 2>/dev/null || true)
        (( ++page >= 5 )) && break   # máx 5 páginas (500 resultados) para no agotar cuota
        [[ -z "$cursor" ]] && break
    done
    normalize_and_filter "$out"
    report_done "censys" "ok" "$(wc -l < "$out")" "$(( SECONDS - start ))"
}

src_binaryedge() {
    [[ "${KEY_OK[binaryedge]:-false}" == true && "${TOOL_OK[curl]:-false}" == true && "${TOOL_OK[jq]:-false}" == true ]] \
        || { report_done "binaryedge" "skip" "0" "0"; return; }
    local out="$PASSIVE_DIR/binaryedge.txt"
    [[ "$FORCE" == false && -s "$out" ]] && { report_done "binaryedge" "skip" "$(wc -l < "$out")" "0"; return; }
    touch "$out"
    local start=$SECONDS
    local page=1
    while :; do
        local resp
        resp=$(safe_curl "https://api.binaryedge.io/v2/query/domains/subdomain/${DOMAIN}?page=${page}" \
            -H "X-Key: ${BINARYEDGE_KEY:-}" 2>>"$LOG" || echo "{}")
        local count
        count=$(echo "$resp" | jq '.total // 0' 2>/dev/null || echo 0)
        (( count == 0 )) && break
        echo "$resp" | jq -r '.events[]?' 2>/dev/null \
            | tr '[:upper:]' '[:lower:]' \
            | grep -E "(^|\.)${DOMAIN//./\\.}$" >> "$out" || true
        local pagesize=100
        (( page * pagesize >= count )) && break
        (( page >= 5 )) && break   # máx 5 páginas
        (( page++ ))
    done
    normalize_and_filter "$out"
    report_done "binaryedge" "ok" "$(wc -l < "$out")" "$(( SECONDS - start ))"
}

src_bevigil() {
    [[ "${KEY_OK[bevigil]:-false}" == true && "${TOOL_OK[curl]:-false}" == true && "${TOOL_OK[jq]:-false}" == true ]] \
        || { report_done "bevigil" "skip" "0" "0"; return; }
    local out="$PASSIVE_DIR/bevigil.txt"
    [[ "$FORCE" == false && -s "$out" ]] && { report_done "bevigil" "skip" "$(wc -l < "$out")" "0"; return; }
    touch "$out"
    local start=$SECONDS
    safe_curl "https://osint.bevigil.com/api/${DOMAIN}/subdomains/" \
        -H "X-Access-Token: ${BEVIGIL_KEY:-}" 2>>"$LOG" \
        | jq -r '.subdomains[]?' 2>/dev/null \
        | tr '[:upper:]' '[:lower:]' \
        | grep -E "(^|\.)${DOMAIN//./\\.}$" \
        | sort -u >> "$out" || true
    normalize_and_filter "$out"
    report_done "bevigil" "ok" "$(wc -l < "$out")" "$(( SECONDS - start ))"
}

src_fullhunt() {
    [[ "${KEY_OK[fullhunt]:-false}" == true && "${TOOL_OK[curl]:-false}" == true && "${TOOL_OK[jq]:-false}" == true ]] \
        || { report_done "fullhunt" "skip" "0" "0"; return; }
    local out="$PASSIVE_DIR/fullhunt.txt"
    [[ "$FORCE" == false && -s "$out" ]] && { report_done "fullhunt" "skip" "$(wc -l < "$out")" "0"; return; }
    touch "$out"
    local start=$SECONDS
    safe_curl "https://fullhunt.io/api/v1/domain/${DOMAIN}/subdomains" \
        -H "X-API-KEY: ${FULLHUNT_KEY:-}" 2>>"$LOG" \
        | jq -r '.hosts[]?' 2>/dev/null \
        | tr '[:upper:]' '[:lower:]' \
        | grep -E "(^|\.)${DOMAIN//./\\.}$" \
        | sort -u >> "$out" || true
    normalize_and_filter "$out"
    report_done "fullhunt" "ok" "$(wc -l < "$out")" "$(( SECONDS - start ))"
}

src_netlas() {
    [[ "${KEY_OK[netlas]:-false}" == true && "${TOOL_OK[curl]:-false}" == true && "${TOOL_OK[jq]:-false}" == true ]] \
        || { report_done "netlas" "skip" "0" "0"; return; }
    local out="$PASSIVE_DIR/netlas.txt"
    [[ "$FORCE" == false && -s "$out" ]] && { report_done "netlas" "skip" "$(wc -l < "$out")" "0"; return; }
    touch "$out"
    local start=$SECONDS
    safe_curl "https://app.netlas.io/api/domains/?q=%2A.${DOMAIN}&source_type=include&start=0&fields=domain" \
        -H "X-API-Key: ${NETLAS_KEY:-}" 2>>"$LOG" \
        | jq -r '.items[].data.domain? // empty' 2>/dev/null \
        | tr '[:upper:]' '[:lower:]' \
        | grep -E "(^|\.)${DOMAIN//./\\.}$" \
        | sort -u >> "$out" || true
    normalize_and_filter "$out"
    report_done "netlas" "ok" "$(wc -l < "$out")" "$(( SECONDS - start ))"
}

src_bufferover() {
    [[ "${TOOL_OK[curl]:-false}" == true && "${TOOL_OK[jq]:-false}" == true ]] \
        || { report_done "bufferover" "skip" "0" "0"; return; }
    local out="$PASSIVE_DIR/bufferover.txt"
    [[ "$FORCE" == false && -s "$out" ]] && { report_done "bufferover" "skip" "$(wc -l < "$out")" "0"; return; }
    touch "$out"
    local start=$SECONDS
    # TLS endpoint
    safe_curl "https://tls.bufferover.run/dns?q=.${DOMAIN}" 2>>"$LOG" \
        | jq -r '(.FDNS_A // .Results // [])[]?' 2>/dev/null \
        | cut -d',' -f2 \
        | tr '[:upper:]' '[:lower:]' \
        | grep -E "(^|\.)${DOMAIN//./\\.}$" >> "$out" || true
    # DNS endpoint (fallback, retorna plain text)
    safe_curl "https://dns.bufferover.run/dns?q=.${DOMAIN}" 2>>"$LOG" \
        | jq -r '(.FDNS_A // .Results // [])[]?' 2>/dev/null \
        | cut -d',' -f2 \
        | tr '[:upper:]' '[:lower:]' \
        | grep -E "(^|\.)${DOMAIN//./\\.}$" >> "$out" || true
    normalize_and_filter "$out"
    report_done "bufferover" "ok" "$(wc -l < "$out")" "$(( SECONDS - start ))"
}

src_shodan_dns() {
    [[ "${KEY_OK[shodan]:-false}" == true && "${TOOL_OK[curl]:-false}" == true && "${TOOL_OK[jq]:-false}" == true ]] \
        || { report_done "shodan_dns" "skip" "0" "0"; return; }
    local out="$PASSIVE_DIR/shodan_dns.txt"
    [[ "$FORCE" == false && -s "$out" ]] && { report_done "shodan_dns" "skip" "$(wc -l < "$out")" "0"; return; }
    touch "$out"
    local start=$SECONDS
    safe_curl "https://api.shodan.io/dns/domain/${DOMAIN}?key=${SHODAN_API_KEY:-}" 2>>"$LOG" \
        | jq -r '.subdomains[]?' 2>/dev/null \
        | sed "s/\$/.${DOMAIN}/" \
        | tr '[:upper:]' '[:lower:]' \
        | grep -E "(^|\.)${DOMAIN//./\\.}$" \
        | sort -u >> "$out" || true
    normalize_and_filter "$out"
    report_done "shodan_dns" "ok" "$(wc -l < "$out")" "$(( SECONDS - start ))"
}

src_facebook_ct() {
    [[ "${TOOL_OK[curl]:-false}" == true && "${TOOL_OK[jq]:-false}" == true ]] \
        || { report_done "facebook_ct" "skip" "0" "0"; return; }
    local out="$PASSIVE_DIR/facebook_ct.txt"
    [[ "$FORCE" == false && -s "$out" ]] && { report_done "facebook_ct" "skip" "$(wc -l < "$out")" "0"; return; }
    touch "$out"
    local start=$SECONDS
    local url="https://graph.facebook.com/certificates?query=${DOMAIN}&fields=domains&limit=10000"
    [[ -n "${FB_TOKEN:-}" ]] && url+="&access_token=${FB_TOKEN}"
    safe_curl "$url" 2>>"$LOG" \
        | jq -r '.data[].domains[]?' 2>/dev/null \
        | tr '[:upper:]' '[:lower:]' \
        | grep -E "(^|\.)${DOMAIN//./\\.}$" \
        | sort -u >> "$out" || true
    normalize_and_filter "$out"
    report_done "facebook_ct" "ok" "$(wc -l < "$out")" "$(( SECONDS - start ))"
}

# ============================================================
# MODO FUERZA BRUTA — B1: Resolvers, Wildcard, DNS bruteforce
# ============================================================

# Descarga/valida resolvers DNS confiables
prepare_resolvers() {
    local resolvers_dir="$CACHE_DIR/resolvers"
    mkdir -p "$resolvers_dir"

    # Si el usuario pasó --resolvers, usarlo directamente
    if [[ -n "$RESOLVERS_FILE" ]]; then
        [[ -f "$RESOLVERS_FILE" ]] || die "Fichero de resolvers no encontrado: $RESOLVERS_FILE"
        info_msg "Resolvers: usando fichero personalizado ($(wc -l < "$RESOLVERS_FILE") entradas)"
        return
    fi

    RESOLVERS_FILE="$resolvers_dir/resolvers.txt"
    local resolver_url="https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt"

    # Refrescar si no existe o tiene más de 24h
    local needs_download=false
    if [[ ! -f "$RESOLVERS_FILE" ]]; then
        needs_download=true
    else
        local age=$(( $(date +%s) - $(date -r "$RESOLVERS_FILE" +%s 2>/dev/null || echo 0) ))
        (( age > 86400 )) && needs_download=true
    fi

    if $needs_download; then
        info_msg "Descargando resolvers DNS actualizados..."
        if safe_curl "$resolver_url" -o "$RESOLVERS_FILE" 2>>"$LOG"; then
            ok_msg "Resolvers" "$(wc -l < "$RESOLVERS_FILE") cargados desde trickest/resolvers"
        else
            warn "No se pudieron descargar resolvers — usando 8.8.8.8,1.1.1.1 como fallback"
            printf '8.8.8.8\n1.1.1.1\n8.8.4.4\n1.0.0.1\n' > "$RESOLVERS_FILE"
        fi
    else
        local age_min=$(( ( $(date +%s) - $(date -r "$RESOLVERS_FILE" +%s 2>/dev/null || echo 0) ) / 60 ))
        info_msg "Resolvers en caché: $(wc -l < "$RESOLVERS_FILE") entradas (actualizados hace ${age_min}min)"
    fi
}

# Descarga/selecciona la wordlist según --wordlist-size
prepare_wordlist() {
    local wordlists_dir="$CACHE_DIR/wordlists"
    mkdir -p "$wordlists_dir"

    # Wordlist personalizada (--wordlist)
    if [[ -n "$WORDLIST" ]]; then
        [[ -f "$WORDLIST" ]] || die "Wordlist no encontrada: $WORDLIST"
        info_msg "Wordlist: personalizada — $(wc -l < "$WORDLIST") entradas"
        return
    fi

    # Validar tamaño elegido
    case "$WORDLIST_SIZE" in
        small) ;;
        med|medium) WORDLIST_SIZE="med" ;;
        big) ;;
        *) die "Tamaño de wordlist inválido: '$WORDLIST_SIZE'. Usa: small | med | big" ;;
    esac

    local wl_file url label
    case "$WORDLIST_SIZE" in
        small)
            wl_file="$wordlists_dir/small_5k.txt"
            url="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt"
            label="5k entradas (SecLists top-5000)" ;;
        med)
            wl_file="$wordlists_dir/medium_100k.txt"
            url="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt"
            label="100k entradas (SecLists top-110000)" ;;
        big)
            wl_file="$wordlists_dir/big_2m.txt"
            url="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/dns-Jhaddix.all.txt"
            label="~2M entradas (Jhaddix all.txt)" ;;
    esac

    WORDLIST="$wl_file"

    # Confirmar antes de descargar/usar wordlist grande
    if [[ "$WORDLIST_SIZE" == "big" && "$NO_CONFIRM" == false && -t 0 ]]; then
        echo ""
        echo -e "${YEL}  ${ICO_WARN} ATENCIÓN — Wordlist grande${NC}"
        echo -e "  La wordlist ${BOLD}big (~2M)${NC} puede tardar ${BOLD}5-20 min${NC} y genera tráfico DNS intenso."
        echo -e "  Usa ${DIM}--no-confirm${NC} para omitir este aviso en el futuro."
        read -r -p "  ¿Continuar? [s/N]: " confirm
        [[ "$confirm" =~ ^[sS]$ ]] || { echo -e "${YEL}  Cancelado.${NC}"; exit 0; }
        echo ""
    fi

    if [[ ! -f "$WORDLIST" ]]; then
        info_msg "Descargando wordlist ${BOLD}${WORDLIST_SIZE}${NC} ($label)..."
        if safe_curl "$url" -o "$WORDLIST" 2>>"$LOG"; then
            ok_msg "Wordlist" "$(wc -l < "$WORDLIST") entradas descargadas"
        else
            die "No se pudo descargar la wordlist. Usa -w <ruta> para especificar una local."
        fi
    else
        info_msg "Wordlist en caché: ${BOLD}${WORDLIST_SIZE}${NC} — $(wc -l < "$WORDLIST") entradas"
    fi
}

# Detecta wildcards DNS antes del bruteforce.
# Un dominio con wildcard (*.$DOMAIN → IP X) envenenará los resultados.
# Guardamos las IPs wildcard para filtrarlas en post-procesado.
detect_wildcard() {
    local out="$RAW_DIR/wildcards.txt"
    touch "$out"

    info_msg "Detectando wildcard DNS en $DOMAIN..."

    # Generamos 5 subdominios aleatorios que no pueden existir
    local wildcard_ips=()
    local i resolved
    for i in {1..5}; do
        local random_sub
        random_sub="wc-test-$(tr -dc 'a-z0-9' </dev/urandom 2>/dev/null | head -c 10 || date +%s%N | md5sum | head -c 10).${DOMAIN}"
        resolved=$(dig +short +timeout=3 "$random_sub" A 2>/dev/null \
                   | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1 || true)
        [[ -n "$resolved" ]] && wildcard_ips+=("$resolved")
    done

    if [[ ${#wildcard_ips[@]} -gt 0 ]]; then
        printf '%s\n' "${wildcard_ips[@]}" | sort -u > "$out"
        local wc_ips; wc_ips=$(tr '\n' ' ' < "$out")
        echo -e "${YEL}  ${ICO_WARN} ${BOLD}Wildcard DNS detectado${NC} — IPs: ${YEL}${wc_ips}${NC}" | tee -a "$LOG"
        echo -e "  ${DIM}Los resultados serán filtrados automáticamente contra estas IPs.${NC}"
        log_only "[WILDCARD] IPs detectadas: $wc_ips"
    else
        ok_msg "Wildcard DNS" "no detectado — dominio limpio ✔"
        log_only "[WILDCARD] No detectado"
    fi
}

# Filtra de un fichero de subdomains aquellos que resuelven
# a una IP wildcard (solo se usa cuando puredns no está disponible).
_filter_wildcards_fallback() {
    local file="$1"
    local wildcard_file="$RAW_DIR/wildcards.txt"
    [[ -s "$wildcard_file" && -s "$file" ]] || return 0

    local tmp="${file}.wc_filtered"
    touch "$tmp"
    local removed=0

    while IFS= read -r sub; do
        local ip
        ip=$(dig +short +timeout=2 "$sub" A 2>/dev/null \
             | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1 || true)
        if [[ -z "$ip" ]] || ! grep -qF "$ip" "$wildcard_file"; then
            echo "$sub" >> "$tmp"
        else
            (( removed++ )) || true
        fi
    done < "$file"

    mv "$tmp" "$file"
    [[ $removed -gt 0 ]] && log_only "[WILDCARD_FILTER] $removed entradas eliminadas de $file"
}

# DNS bruteforce principal — usa puredns, shuffledns o dig como fallback
run_dns_bruteforce() {
    local out="$BRUTEFORCE_DIR/dns_bruteforce.txt"
    [[ "$FORCE" == false && -s "$out" ]] && {
        skip_msg "dns_bruteforce" "resultado previo (usa --force para re-ejecutar)"
        return
    }
    touch "$out"

    local wl_count; wl_count=$(wc -l < "$WORDLIST")
    local resolver_count; resolver_count=$(wc -l < "$RESOLVERS_FILE" 2>/dev/null || echo "?")

    info_msg "DNS bruteforce — ${BOLD}${wl_count}${NC} palabras | ${BOLD}${resolver_count}${NC} resolvers | target: ${BOLD}${DOMAIN}${NC}"
    local start=$SECONDS

    # ── puredns (primera opción — maneja wildcards internamente) ──
    if [[ "${TOOL_OK[puredns]:-false}" == true ]]; then
        info_msg "Motor: ${BOLD}puredns${NC} (recomendado)"
        local puredns_args=(
            bruteforce "$WORDLIST" "$DOMAIN"
            -r "$RESOLVERS_FILE"
            --wildcard-tests 30
            --wildcard-batch 1000000
            -t 500
            -w "$out"
        )
        if timeout "$BRUTE_TIMEOUT" puredns "${puredns_args[@]}" 2>>"$LOG"; then
            log_only "[BRUTEFORCE] puredns completado"
        else
            local code=$?
            [[ $code -eq 124 ]] \
                && fail_msg "dns_bruteforce" "timeout tras $(elapsed_fmt $BRUTE_TIMEOUT)" \
                || fail_msg "dns_bruteforce" "puredns exit $code — resultados parciales conservados"
        fi

    # ── shuffledns (segunda opción) ───────────────────────────
    elif [[ "${TOOL_OK[shuffledns]:-false}" == true ]]; then
        info_msg "Motor: ${BOLD}shuffledns${NC}"
        local shuffledns_args=(
            -d "$DOMAIN"
            -w "$WORDLIST"
            -r "$RESOLVERS_FILE"
            -o "$out"
            -t 500
        )
        if timeout "$BRUTE_TIMEOUT" shuffledns "${shuffledns_args[@]}" 2>>"$LOG"; then
            log_only "[BRUTEFORCE] shuffledns completado"
            # shuffledns no filtra wildcards — hacerlo manualmente
            _filter_wildcards_fallback "$out"
        else
            local code=$?
            [[ $code -eq 124 ]] \
                && fail_msg "dns_bruteforce" "timeout tras $(elapsed_fmt $BRUTE_TIMEOUT)" \
                || fail_msg "dns_bruteforce" "shuffledns exit $code"
        fi

    # ── dnsx (tercera opción — genera candidatos y resuelve) ─
    elif [[ "${TOOL_OK[dnsx]:-false}" == true ]]; then
        info_msg "Motor: ${BOLD}dnsx${NC} (fallback — más lento)"
        # Generar FQDNs desde wordlist
        local candidates_tmp
        candidates_tmp=$(mktemp)
        sed "s/$/.${DOMAIN}/" "$WORDLIST" > "$candidates_tmp"
        timeout "$BRUTE_TIMEOUT" dnsx \
            -l "$candidates_tmp" \
            -r "$RESOLVERS_FILE" \
            -t 200 \
            -silent \
            -o "$out" 2>>"$LOG" || true
        rm -f "$candidates_tmp"
        _filter_wildcards_fallback "$out"

    # ── dig en bucle (último recurso — muy lento) ─────────────
    elif command -v dig &>/dev/null; then
        echo ""
        echo -e "${YEL}  ${ICO_WARN} Ningún motor rápido disponible (puredns/shuffledns/dnsx).${NC}"
        echo -e "  ${DIM}Usando dig — solo recomendable para wordlists pequeñas.${NC}"
        if [[ "$WORDLIST_SIZE" != "small" && "$NO_CONFIRM" == false && -t 0 ]]; then
            read -r -p "  ¿Continuar de todos modos? [s/N]: " confirm
            [[ "$confirm" =~ ^[sS]$ ]] || { echo -e "${YEL}  Cancelado.${NC}"; return; }
        fi
        info_msg "Motor: ${BOLD}dig${NC} (último recurso)"
        while IFS= read -r word; do
            local fqdn="${word}.${DOMAIN}"
            if dig +short +timeout=2 "$fqdn" A &>/dev/null 2>&1; then
                echo "$fqdn" >> "$out"
            fi
        done < "$WORDLIST"
        _filter_wildcards_fallback "$out"

    else
        fail_msg "dns_bruteforce" "sin motor disponible — instala puredns, shuffledns o dnsx"
        return 1
    fi

    normalize_and_filter "$out"

    local count; count=$(wc -l < "$out" 2>/dev/null || echo 0)
    local elapsed=$(( SECONDS - start ))
    ok_msg "dns_bruteforce" "${count} hallazgos  $(elapsed_fmt $elapsed)  [${WORDLIST_SIZE}: ${wl_count} palabras]"
}

# ============================================================
# MODO FUERZA BRUTA — Herramientas activas
# ============================================================

run_amass_active() {
    [[ "${TOOL_OK[amass]:-false}" == true ]] || { skip_msg "amass active" "amass no disponible"; return; }
    local out="$BRUTEFORCE_DIR/amass_active.txt"
    [[ "$FORCE" == false && -s "$out" ]] && { skip_msg "amass active" "resultado previo (usa --force)"; return; }
    touch "$out"
    info_msg "amass active — enumeración DNS activa..."
    local start=$SECONDS
    timeout "$STEP_TIMEOUT" amass enum -active -d "$DOMAIN" 2>>"$LOG" \
        | grep -oE "[a-zA-Z0-9._-]+\.${DOMAIN}" | sort -u >> "$out" || true
    normalize_and_filter "$out"
    ok_msg "amass active" "$(wc -l < "$out") hallazgos  $(elapsed_fmt $(( SECONDS - start )))"
}

# ── B2: Permutaciones ─────────────────────────────────────────

# Wordlist pequeña para permutaciones (gotator y alterx -pp).
# Permutaciones multiplican: 500 seeds × 1000 palabras = 500k candidatos.
# No usar la wordlist grande de B1 aquí.
prepare_perms_wordlist() {
    local perms_file="$CACHE_DIR/wordlists/permutations.txt"
    mkdir -p "$CACHE_DIR/wordlists"
    if [[ ! -f "$perms_file" ]]; then
        info_msg "Descargando wordlist de permutaciones (gotator)..."
        if safe_curl "https://raw.githubusercontent.com/Josue87/gotator/main/permutations_list.txt" \
                -o "$perms_file" 2>>"$LOG"; then
            log_only "[PERMS_WL] $(wc -l < "$perms_file") entradas desde gotator/permutations_list.txt"
        else
            # Fallback minimalista embebido
            printf 'dev\napi\nstage\ntest\nadmin\nmail\nvpn\nstatic\ncdn\nauth\napp\nwww\nm\nmobile\nbeta\nold\nnew\nbackup\ninternal\nprod\nuat\nqa\npre\nstg\nportal\ndash\nlb\ngw\nns\nns1\nns2\nwww2\nftp\nweb\nweb2\nwebapp\n' \
                > "$perms_file"
            log_only "[PERMS_WL] Usando wordlist de permutaciones mínima (fallback)"
        fi
    fi
    echo "$perms_file"
}

# B2: genera candidatos permutando los subdomains ya conocidos
# y los verifica con DNS (puredns/shuffledns/dnsx).
run_permutations() {
    [[ "${TOOL_OK[alterx]:-false}" == true || "${TOOL_OK[gotator]:-false}" == true ]] \
        || { skip_msg "permutations" "ni alterx ni gotator disponibles"; return; }

    local out="$BRUTEFORCE_DIR/permutations.txt"
    [[ "$FORCE" == false && -s "$out" ]] && {
        skip_msg "permutations" "resultado previo (usa --force)"; return
    }
    touch "$out"

    # Construir semillas: pasivo + bruteforce previo
    local seeds_file; seeds_file=$(mktemp --suffix=.seeds)
    local merge_sources=(
        "$PASSIVE_DIR/passive_merged.txt"
        "$BRUTEFORCE_DIR/dns_bruteforce.txt"
        "$PASSIVE_DIR/subfinder.txt"    # fallback si no hay merge pasivo
    )
    for src in "${merge_sources[@]}"; do
        [[ -s "$src" ]] && cat "$src" >> "$seeds_file"
    done
    sort -u -o "$seeds_file" "$seeds_file"

    local seed_count; seed_count=$(wc -l < "$seeds_file")
    if (( seed_count == 0 )); then
        skip_msg "permutations" "sin seeds — ejecuta --passive o --bruteforce primero"
        rm -f "$seeds_file"; return
    fi

    local perms_wl; perms_wl=$(prepare_perms_wordlist)
    info_msg "Permutaciones — ${BOLD}${seed_count}${NC} seeds  |  motores: $( [[ "${TOOL_OK[alterx]:-false}" == true ]] && echo -n "alterx "; [[ "${TOOL_OK[gotator]:-false}" == true ]] && echo -n "gotator" )"
    local start=$SECONDS
    local candidates_file; candidates_file=$(mktemp --suffix=.candidates)

    # ── Motor 1: alterx ───────────────────────────────────────
    if [[ "${TOOL_OK[alterx]:-false}" == true ]]; then
        # Modo pattern: muta partes del subdomain (dev-api → dev2-api, api-dev, etc.)
        timeout "$STEP_TIMEOUT" alterx -l "$seeds_file" -silent \
            2>>"$LOG" >> "$candidates_file" || true
        # Modo enrich: añade palabras comunes al subdominio
        timeout "$STEP_TIMEOUT" alterx -l "$seeds_file" -enrich -silent \
            2>>"$LOG" >> "$candidates_file" || true
        # Modo diccionario con wordlist de permutaciones
        timeout "$STEP_TIMEOUT" alterx -l "$seeds_file" \
            -pp "word=${perms_wl}" -silent \
            2>>"$LOG" >> "$candidates_file" || true
    fi

    # ── Motor 2: gotator ──────────────────────────────────────
    if [[ "${TOOL_OK[gotator]:-false}" == true ]]; then
        timeout "$STEP_TIMEOUT" gotator \
            -sub "$seeds_file" \
            -perm "$perms_wl" \
            -depth 1 \
            -mindup \
            -adv \
            -silent \
            2>>"$LOG" >> "$candidates_file" || true
    fi

    # Limpiar y filtrar scope
    local clean_file; clean_file=$(mktemp --suffix=.clean)
    sort -u "$candidates_file" \
        | grep -E "(^|\.)${DOMAIN}$" \
        | grep -v '^\.' \
        | grep -vFf "$seeds_file" \
        > "$clean_file" 2>/dev/null || true

    local total_candidates; total_candidates=$(wc -l < "$clean_file")
    info_msg "  ${total_candidates} candidatos únicos nuevos → verificando DNS..."

    # ── Resolver candidatos DNS ───────────────────────────────
    if (( total_candidates > 0 )); then
        if [[ "${TOOL_OK[puredns]:-false}" == true && -f "${RESOLVERS_FILE:-}" ]]; then
            timeout "$BRUTE_TIMEOUT" puredns resolve "$clean_file" \
                -r "$RESOLVERS_FILE" --wildcard-tests 30 -t 300 \
                -w "$out" 2>>"$LOG" || touch "$out"
        elif [[ "${TOOL_OK[shuffledns]:-false}" == true && -f "${RESOLVERS_FILE:-}" ]]; then
            timeout "$BRUTE_TIMEOUT" shuffledns \
                -d "$DOMAIN" -list "$clean_file" \
                -r "$RESOLVERS_FILE" -o "$out" 2>>"$LOG" || touch "$out"
            _filter_wildcards_fallback "$out"
        elif [[ "${TOOL_OK[dnsx]:-false}" == true ]]; then
            timeout "$STEP_TIMEOUT" dnsx \
                -l "$clean_file" -t 200 -silent -o "$out" 2>>"$LOG" || touch "$out"
            _filter_wildcards_fallback "$out"
        else
            # Sin resolvedor: guardar candidatos sin verificar
            cp "$clean_file" "$out"
            log_only "[PERMS] Sin resolvedor — candidatos no verificados en DNS"
        fi
    fi

    normalize_and_filter "$out"
    rm -f "$seeds_file" "$candidates_file" "$clean_file"

    local found; found=$(wc -l < "$out" 2>/dev/null || echo 0)
    ok_msg "permutations" \
        "${found} verificados  ${DIM}[seeds: ${seed_count}  candidatos: ${total_candidates}]${NC}  $(elapsed_fmt $(( SECONDS - start )))"
}

# ── B5: Recursión ─────────────────────────────────────────────

# Toma los hallazgos actuales como nuevas semillas, genera
# candidatos con alterx/gotator y los verifica. Repite
# RECURSIVE_DEPTH veces o hasta que no haya hallazgos nuevos.
run_recursive() {
    (( RECURSIVE_DEPTH < 1 )) && { skip_msg "recursive" "desactivado (--recursive-depth 0)"; return; }

    local out="$BRUTEFORCE_DIR/recursive.txt"
    [[ "$FORCE" == false && -s "$out" ]] && {
        skip_msg "recursive" "resultado previo (usa --force)"; return
    }
    touch "$out"

    [[ "${TOOL_OK[alterx]:-false}" == true || "${TOOL_OK[gotator]:-false}" == true ]] \
        || { skip_msg "recursive" "ni alterx ni gotator disponibles"; return; }

    info_msg "Recursión — ${BOLD}${RECURSIVE_DEPTH}${NC} nivel(es) máx."
    local global_start=$SECONDS
    local perms_wl; perms_wl=$(prepare_perms_wordlist)

    # Base de conocimiento inicial: todo lo encontrado hasta ahora
    local known_file; known_file=$(mktemp --suffix=.known)
    cat \
        "$PASSIVE_DIR/passive_merged.txt" \
        "$BRUTEFORCE_DIR/dns_bruteforce.txt" \
        "$BRUTEFORCE_DIR/permutations.txt" \
        "$BRUTEFORCE_DIR/amass_active.txt" \
        2>/dev/null | sort -u > "$known_file"

    local total_new=0
    local prev_seeds_file="$known_file"   # primer nivel usa todos los conocidos

    for (( depth=1; depth<=RECURSIVE_DEPTH; depth++ )); do
        local seed_count; seed_count=$(wc -l < "$prev_seeds_file")
        info_msg "  Nivel ${depth}/${RECURSIVE_DEPTH} — ${BOLD}${seed_count}${NC} semillas"

        local level_raw; level_raw=$(mktemp --suffix=.raw)
        local level_clean; level_clean=$(mktemp --suffix=.clean)
        local level_resolved; level_resolved=$(mktemp --suffix=.resolved)

        # Generar candidatos con las semillas de este nivel
        if [[ "${TOOL_OK[alterx]:-false}" == true ]]; then
            timeout "$STEP_TIMEOUT" alterx -l "$prev_seeds_file" -enrich -silent \
                2>>"$LOG" >> "$level_raw" || true
        fi
        if [[ "${TOOL_OK[gotator]:-false}" == true ]]; then
            timeout "$STEP_TIMEOUT" gotator \
                -sub "$prev_seeds_file" -perm "$perms_wl" \
                -depth 1 -mindup -silent \
                2>>"$LOG" >> "$level_raw" || true
        fi

        # Filtrar scope y ya conocidos
        sort -u "$level_raw" \
            | grep -E "(^|\.)${DOMAIN}$" \
            | grep -v '^\.' \
            | grep -vFf "$known_file" \
            > "$level_clean" 2>/dev/null || true

        local new_candidates; new_candidates=$(wc -l < "$level_clean")

        if (( new_candidates == 0 )); then
            ok_msg "  Nivel ${depth}" "sin candidatos nuevos — recursión completada"
            rm -f "$level_raw" "$level_clean" "$level_resolved"
            break
        fi

        info_msg "  Nivel ${depth}: ${new_candidates} candidatos → verificando DNS..."

        # Resolver
        if [[ "${TOOL_OK[puredns]:-false}" == true && -f "${RESOLVERS_FILE:-}" ]]; then
            timeout "$BRUTE_TIMEOUT" puredns resolve "$level_clean" \
                -r "$RESOLVERS_FILE" --wildcard-tests 30 -t 300 \
                -w "$level_resolved" 2>>"$LOG" || touch "$level_resolved"
        elif [[ "${TOOL_OK[dnsx]:-false}" == true ]]; then
            timeout "$STEP_TIMEOUT" dnsx \
                -l "$level_clean" -t 200 -silent \
                -o "$level_resolved" 2>>"$LOG" || touch "$level_resolved"
            _filter_wildcards_fallback "$level_resolved"
        else
            cp "$level_clean" "$level_resolved"
        fi

        normalize_and_filter "$level_resolved"

        # Solo los realmente nuevos (verificados y no conocidos)
        local new_file; new_file=$(mktemp --suffix=.new)
        grep -vFf "$known_file" "$level_resolved" > "$new_file" 2>/dev/null || true
        local new_found; new_found=$(wc -l < "$new_file")

        if (( new_found == 0 )); then
            ok_msg "  Nivel ${depth}" "0 hallazgos nuevos — recursión completada"
            rm -f "$level_raw" "$level_clean" "$level_resolved" "$new_file"
            break
        fi

        ok_msg "  Nivel ${depth}" "${new_found} nuevos hallazgos"

        # Acumular resultados
        cat "$new_file" >> "$out"
        cat "$new_file" >> "$known_file"
        sort -u -o "$known_file" "$known_file"
        (( total_new += new_found ))

        # El siguiente nivel usa solo los nuevos como semillas
        [[ "$prev_seeds_file" != "$known_file" ]] && rm -f "$prev_seeds_file"
        prev_seeds_file="$new_file"
        new_file=""   # evitar rm doble

        rm -f "$level_raw" "$level_clean" "$level_resolved"
        [[ -n "${new_file:-}" ]] && rm -f "$new_file"
    done

    [[ "$prev_seeds_file" != "$known_file" ]] && rm -f "$prev_seeds_file"
    rm -f "$known_file"
    sort -u -o "$out" "$out"

    ok_msg "recursive" \
        "${total_new} hallazgos nuevos en total  ${DIM}[${RECURSIVE_DEPTH} nivel(es)]${NC}  $(elapsed_fmt $(( SECONDS - global_start )))"
}

# ============================================================
# Fases comunes (post-recon)
# ============================================================

consolidate() {
    info_msg "Consolidando y deduplicando..."
    local start=$SECONDS

    # Merge modo pasivo
    if $MODE_PASSIVE; then
        cat "$PASSIVE_DIR"/*.txt 2>/dev/null \
            | tr '[:upper:]' '[:lower:]' \
            | sed -e 's|https\?://||g' -e 's|/.*||g' -e 's/\*\.//g' -e 's/[[:space:]]//g' \
            | grep -E "(^|\.)${DOMAIN}$" \
            | grep -v '^\.' \
            | sort -u > "$PASSIVE_DIR/passive_merged.txt" || true
    fi

    # Merge modo fuerza bruta
    if $MODE_BRUTEFORCE; then
        cat "$BRUTEFORCE_DIR"/*.txt 2>/dev/null \
            | tr '[:upper:]' '[:lower:]' \
            | sed -e 's|https\?://||g' -e 's|/.*||g' -e 's/\*\.//g' -e 's/[[:space:]]//g' \
            | grep -E "(^|\.)${DOMAIN}$" \
            | grep -v '^\.' \
            | sort -u > "$BRUTEFORCE_DIR/bruteforce_merged.txt" || true
    fi

    # Merge final (todo)
    cat \
        "$PASSIVE_DIR/passive_merged.txt" \
        "$BRUTEFORCE_DIR/bruteforce_merged.txt" \
        2>/dev/null \
        | sort -u > "$OUTPUT_DIR/subdomains.txt" || true

    local p_count=0 b_count=0 t_count=0
    [[ -f "$PASSIVE_DIR/passive_merged.txt"       ]] && p_count=$(wc -l < "$PASSIVE_DIR/passive_merged.txt")
    [[ -f "$BRUTEFORCE_DIR/bruteforce_merged.txt" ]] && b_count=$(wc -l < "$BRUTEFORCE_DIR/bruteforce_merged.txt")
    [[ -f "$OUTPUT_DIR/subdomains.txt"                 ]] && t_count=$(wc -l < "$OUTPUT_DIR/subdomains.txt")

    ok_msg "Consolidación" "pasivo=${p_count}  bruteforce=${b_count}  ${BOLD}total=${t_count}${NC}  $(elapsed_fmt $(( SECONDS - start )))"
}

run_httpx() {
    $SKIP_ACTIVE && { skip_msg "httpx" "desactivado con --skip-active"; return; }
    [[ "${TOOL_OK[httpx]:-false}" == true ]] || { skip_msg "httpx" "httpx no disponible"; return; }

    # Preferir raw/resolved.txt (ya validado DNS) sobre subdomains.txt
    local input="$OUTPUT_DIR/subdomains.txt"
    [[ -s "$RAW_DIR/resolved.txt" ]] && input="$RAW_DIR/resolved.txt"
    local out="$OUTPUT_DIR/subdomains_alive.txt"
    local json_out="$RAW_DIR/httpx.json"

    [[ -s "$input" ]] || { skip_msg "httpx" "subdomains.txt vacío"; return; }

    info_msg "httpx — sondeando puertos 80/443/8080/8000/8888/8443..."
    local start=$SECONDS
    touch "$out" "$json_out"

    timeout "$STEP_TIMEOUT" httpx \
        -l "$input" -ports 80,443,8080,8000,8888,8443 \
        -threads 150 -rate-limit 300 \
        -title -tech-detect -status-code -cdn -silent \
        -json -o "$json_out" 2>>"$LOG" \
        | grep -oE "https?://[a-zA-Z0-9._-]+" \
        | sed 's|https\?://||' \
        | grep -E "(^|\.)${DOMAIN}$" \
        | sort -u > "$out" || true

    if [[ ! -s "$out" && -s "$json_out" && "${TOOL_OK[jq]:-false}" == true ]]; then
        jq -r '.url // empty' "$json_out" 2>/dev/null \
            | sed 's|https\?://||' | sort -u > "$out" || true
    fi

    ok_msg "httpx" "$(wc -l < "$out") vivos  $(elapsed_fmt $(( SECONDS - start )))"
}

run_ip_collection() {
    local out="$OUTPUT_DIR/ips.txt"
    touch "$out"
    info_msg "Recolectando IPs asociadas..."
    local start=$SECONDS

    if [[ "${KEY_OK[virustotal]}" == true && "${TOOL_OK[jq]:-false}" == true ]]; then
        safe_curl "https://www.virustotal.com/vtapi/v2/domain/report?domain=${DOMAIN}&apikey=${VT_APIKEY}" \
            2>>"$LOG" | jq -r '.. | .ip_address? // empty' 2>/dev/null \
            | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' >> "$out" || true
    fi

    if [[ "${TOOL_OK[jq]:-false}" == true ]]; then
        safe_curl "https://otx.alienvault.com/api/v1/indicators/hostname/${DOMAIN}/url_list?limit=500&page=1" \
            2>>"$LOG" | jq -r '.url_list[]?.result?.urlworker?.ip // empty' 2>/dev/null \
            | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' >> "$out" || true

        safe_curl "https://urlscan.io/api/v1/search/?q=domain:${DOMAIN}&size=10000" \
            2>>"$LOG" | jq -r '.results[].page?.ip // empty' 2>/dev/null \
            | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' >> "$out" || true
    fi

    sort -u -o "$out" "$out"
    ok_msg "IPs" "$(wc -l < "$out") únicas  $(elapsed_fmt $(( SECONDS - start )))"
}

# ============================================================
# FASE 4 — Calidad y postproceso
# ============================================================

# 4.1 + 4.2 — Resolución DNS final + filtrado de wildcards
# Valida que cada entrada en subdomains.txt realmente resuelve.
# Esto elimina dominios NXDOMAIN y wildcards que se cuelen de fuentes pasivas.
run_dns_resolve() {
    local input="$OUTPUT_DIR/subdomains.txt"
    local out="$RAW_DIR/resolved.txt"

    [[ -s "$input" ]] || { skip_msg "dns_resolve" "subdomains.txt vacío"; return; }

    local total; total=$(wc -l < "$input")
    info_msg "Resolución DNS final — validando ${BOLD}${total}${NC} candidatos..."
    local start=$SECONDS

    # Aplicar filtro wildcard sobre subdomains.txt antes de resolver
    # (segunda capa de seguridad además de lo que hace puredns en bruteforce)
    if [[ -s "$RAW_DIR/wildcards.txt" ]]; then
        local wc_ips; wc_ips=$(paste -sd'|' "$RAW_DIR/wildcards.txt")
        log_only "[DNS_RESOLVE] Wildcards conocidas: $wc_ips"
    fi

    if [[ "${TOOL_OK[puredns]:-false}" == true && -n "$RESOLVERS_FILE" && -f "$RESOLVERS_FILE" ]]; then
        timeout "$BRUTE_TIMEOUT" puredns resolve "$input" \
            -r "$RESOLVERS_FILE" \
            --wildcard-tests 30 \
            -t 300 \
            -w "$out" 2>>"$LOG" || touch "$out"

    elif [[ "${TOOL_OK[shuffledns]:-false}" == true && -n "$RESOLVERS_FILE" && -f "$RESOLVERS_FILE" ]]; then
        timeout "$BRUTE_TIMEOUT" shuffledns \
            -d "$DOMAIN" -list "$input" \
            -r "$RESOLVERS_FILE" \
            -o "$out" 2>>"$LOG" || touch "$out"
        _filter_wildcards_fallback "$out"

    elif [[ "${TOOL_OK[dnsx]:-false}" == true ]]; then
        timeout "$STEP_TIMEOUT" dnsx \
            -l "$input" -t 200 -silent \
            -o "$out" 2>>"$LOG" || touch "$out"
        _filter_wildcards_fallback "$out"

    else
        # Sin herramienta de resolución: copiar subdomains.txt con filtro básico de wildcard
        log_only "[DNS_RESOLVE] Sin herramienta de resolución — copiando subdomains.txt"
        cp "$input" "$out"
        _filter_wildcards_fallback "$out"
    fi

    # Normalizar y comparar contra entrada
    normalize_and_filter "$out"
    local resolved; resolved=$(wc -l < "$out" 2>/dev/null || echo 0)
    local dropped=$(( total - resolved ))
    ok_msg "dns_resolve" "${resolved} resueltos  ${DIM}(${dropped} descartados — NXDOMAIN/wildcard)${NC}  $(elapsed_fmt $(( SECONDS - start )))"
}

# 4.3 — Clasificación automática por palabras clave
classify_subdomains() {
    local input="$OUTPUT_DIR/subdomains_alive.txt"
    # Si no hay vivos, clasificar desde raw/resolved.txt / subdomains.txt
    [[ -s "$input" ]] || input="$RAW_DIR/resolved.txt"
    [[ -s "$input" ]] || input="$OUTPUT_DIR/subdomains.txt"
    [[ -s "$input" ]] || { skip_msg "classify" "sin subdomains que clasificar"; return; }

    local classified_dir="$RAW_DIR/classified"
    mkdir -p "$classified_dir"

    info_msg "Clasificando subdomains por palabras clave..."
    local start=$SECONDS

    # Definición de categorías: "nombre|patron_regex"
    local -A CATEGORIES=(
        [admin]="admin|administrator|console|panel|dashboard|manage|management|portal|cp|backstage|backoffice|webadmin"
        [dev]="dev|develop|development|staging|stage|stg|test|testing|uat|qa|sandbox|demo|preview|preprod|pre-prod|beta|alpha|canary"
        [api]="api|api2|apiv[0-9]|gateway|rest|graphql|grpc|endpoint|swagger|openapi|ws\.|wss\."
        [auth]="auth|login|sso|oauth|oidc|saml|identity|idp|accounts|account|signin|signup|register|password"
        [internal]="internal|intranet|corp|corporate|private|vpn|office|employee|staff|intra|local\."
        [monitoring]="monitor|monitoring|nagios|grafana|kibana|datadog|splunk|elk|logs|metrics|prometheus|zabbix|alertmanager|newrelic"
        [mail]="mail|smtp|imap|pop3|webmail|email|mx\.|mta\.|mxrelay"
        [cloud]="s3\.|storage|blob|bucket|cdn|assets|static|media|files|uploads|download"
        [database]="db\.|database|mysql|postgres|mongo|redis|elastic|cassandra|memcache|mariadb|sqlserver"
        [git]="git|gitlab|github|bitbucket|svn|repo|repos|code|source|vcs"
        [vpn]="vpn|remote|citrix|rdp|jump|bastion|openvpn|wireguard|proxy"
    )

    local classified_all="$classified_dir/all_classified.txt"
    local unclassified="$classified_dir/unclassified.txt"
    : > "$classified_all"

    declare -A seen_classified=()

    for category in "${!CATEGORIES[@]}"; do
        local pattern="${CATEGORIES[$category]}"
        local cat_file="$classified_dir/${category}.txt"
        grep -iE "(^|\.)(${pattern})\." "$input" \
            | sort -u > "$cat_file" 2>/dev/null || : > "$cat_file"
        local count; count=$(wc -l < "$cat_file")
        if (( count > 0 )); then
            while IFS= read -r sub; do
                echo "${category}|${sub}" >> "$classified_all"
                seen_classified["$sub"]=1
            done < "$cat_file"
        fi
    done

    # Subdomains que no cayeron en ninguna categoría
    : > "$unclassified"
    while IFS= read -r sub; do
        [[ -z "${seen_classified[$sub]:-}" ]] && echo "$sub" >> "$unclassified"
    done < "$input"

    sort -u -o "$classified_all" "$classified_all"

    local total_classified; total_classified=$(wc -l < "$classified_all" 2>/dev/null || echo 0)
    local total_unclassified; total_unclassified=$(wc -l < "$unclassified" 2>/dev/null || echo 0)
    ok_msg "classify" "${total_classified} clasificados  ${total_unclassified} sin categoría  $(elapsed_fmt $(( SECONDS - start )))"

    # Mini-tabla de categorías no vacías
    echo ""
    printf "  ${DIM}  %-14s  %s${NC}\n" "CATEGORÍA" "SUBDOMAINS"
    printf "  ${DIM}  %-14s  %s${NC}\n" "──────────────" "──────────"
    for category in admin dev api auth internal monitoring mail cloud database git vpn; do
        local cat_file="$classified_dir/${category}.txt"
        [[ -f "$cat_file" ]] || continue
        local count; count=$(wc -l < "$cat_file")
        if (( count > 0 )); then
            # Color según relevancia para pentest
            local color="$NC"
            case "$category" in
                admin|auth|internal|vpn) color="$RED" ;;
                dev|git)                 color="$YEL" ;;
                api|monitoring)          color="$CYA" ;;
            esac
            printf "  ${color}${ICO_OK} %-14s  ${BOLD}%d${NC}\n" "$category" "$count"
            # Mostrar primeros 3 ejemplos
            head -3 "$cat_file" | while IFS= read -r ex; do
                printf "  ${DIM}    └ %s${NC}\n" "$ex"
            done
        fi
    done
    echo ""
}

# 4.4 — Detección de subdomain takeover
run_takeover() {
    $TAKEOVER || return

    local input="$OUTPUT_DIR/subdomains_alive.txt"
    [[ -s "$input" ]] || input="$RAW_DIR/resolved.txt"
    [[ -s "$input" ]] || { skip_msg "takeover" "sin subdomains vivos para analizar"; return; }

    local out="$OUTPUT_DIR/takeovers.txt"
    touch "$out"

    local total; total=$(wc -l < "$input")
    info_msg "Takeover detection — analizando ${BOLD}${total}${NC} subdomains..."
    local start=$SECONDS

    # ── subzy (primera opción — especializado en takeovers) ──
    if [[ "${TOOL_OK[subzy]:-false}" == true ]]; then
        info_msg "Motor: ${BOLD}subzy${NC}"
        timeout "$STEP_TIMEOUT" subzy run \
            --targets "$input" \
            --output "$out" \
            --hide-fails \
            --concurrency 30 \
            2>>"$LOG" || true

    # ── nuclei con templates de takeover ─────────────────────
    elif [[ "${TOOL_OK[nuclei]:-false}" == true ]]; then
        info_msg "Motor: ${BOLD}nuclei${NC} (templates: takeovers)"
        timeout "$STEP_TIMEOUT" nuclei \
            -l "$input" \
            -t takeovers/ \
            -severity medium,high,critical \
            -silent \
            -o "$out" \
            2>>"$LOG" || true
    else
        skip_msg "takeover" "ni subzy ni nuclei disponibles — instala uno de ellos"
        return
    fi

    local found; found=$(wc -l < "$out" 2>/dev/null || echo 0)
    if (( found > 0 )); then
        echo ""
        echo -e "${RED}${BOLD}  ╔══════════════════════════════════════════════════════╗${NC}"
        echo -e "${RED}${BOLD}  ║  ⚠  POSIBLES TAKEOVERS ENCONTRADOS: ${found}$(printf '%*s' $(( 20 - ${#found} )) '')  ║${NC}"
        echo -e "${RED}${BOLD}  ╚══════════════════════════════════════════════════════╝${NC}"
        cat "$out" | while IFS= read -r line; do
            echo -e "  ${RED}${ICO_FAIL}${NC}  $line"
        done
        echo ""
        ok_msg "takeover" "${found} candidatos → ver ${out}  $(elapsed_fmt $(( SECONDS - start )))"
    else
        ok_msg "takeover" "ningún takeover detectado  $(elapsed_fmt $(( SECONDS - start )))"
    fi
}

# ============================================================
# FASE 3 B4 — Crawling (katana/gospider + gau + subjs)
# ============================================================

# Extrae hostnames de un fichero de URLs raw
_extract_domains_from_urls() {
    local urls_file="$1"
    [[ -s "$urls_file" ]] || return 0
    grep -oE 'https?://[^/\"'\''[:space:]]+' "$urls_file" \
        | sed -e 's|https\?://||' -e 's|[/?#:[].*||' \
        | tr '[:upper:]' '[:lower:]' \
        | grep -E "^[a-zA-Z0-9._-]+\.${DOMAIN}$" \
        | sort -u
}

# Crawling activo con katana (o gospider como fallback).
# Guarda URLs raw en $1 y dominios extraídos en $2.
_crawl_active() {
    local urls_out="$1" domains_out="$2"

    # Construir lista de targets: raíz + subdominios vivos (limitado)
    local targets_file; targets_file=$(mktemp --suffix=.targets)
    echo "https://${DOMAIN}" > "$targets_file"
    echo "http://${DOMAIN}"  >> "$targets_file"
    if [[ -s "$OUTPUT_DIR/subdomains_alive.txt" ]]; then
        head -"$CRAWL_MAX_SUBS" "$OUTPUT_DIR/subdomains_alive.txt" \
            | sed 's|^|https://|' >> "$targets_file"
    fi
    sort -u -o "$targets_file" "$targets_file"
    local target_count; target_count=$(wc -l < "$targets_file")

    # ── katana (primera opción) ───────────────────────────────
    if [[ "${TOOL_OK[katana]:-false}" == true ]]; then
        info_msg "  Motor activo: ${BOLD}katana${NC}  (depth=${CRAWL_DEPTH}  targets=${target_count})"
        timeout "$STEP_TIMEOUT" katana \
            -list "$targets_file" \
            -jc \
            -kf \
            -d "$CRAWL_DEPTH" \
            -c 15 \
            -silent \
            2>>"$LOG" >> "$urls_out" || true
        rm -f "$targets_file"
        _extract_domains_from_urls "$urls_out" >> "$domains_out"
        return 0
    fi

    # ── gospider (fallback) ───────────────────────────────────
    if [[ "${TOOL_OK[gospider]:-false}" == true ]]; then
        info_msg "  Motor activo: ${BOLD}gospider${NC}  (depth=${CRAWL_DEPTH}  targets=${target_count})"
        while IFS= read -r target; do
            timeout "$STEP_TIMEOUT" gospider \
                -s "$target" \
                -d "$CRAWL_DEPTH" \
                -t 10 \
                -q \
                2>>"$LOG" >> "$urls_out" || true
        done < "$targets_file"
        rm -f "$targets_file"
        _extract_domains_from_urls "$urls_out" >> "$domains_out"
        return 0
    fi

    rm -f "$targets_file"
    return 1
}

# URLs históricas via gau (getallurls) → extrae dominios
_crawl_gau() {
    local domains_out="$1"
    [[ "${TOOL_OK[gau]:-false}" == true ]] || return 1

    info_msg "  Motor histórico: ${BOLD}gau${NC}  (wayback + commoncrawl + otx)"
    local gau_out; gau_out=$(mktemp --suffix=.gau)

    timeout "$STEP_TIMEOUT" gau "$DOMAIN" \
        --threads 5 \
        --subs \
        --blacklist "png,jpg,gif,css,woff,woff2,ttf,svg,ico,mp4,mp3,pdf" \
        2>>"$LOG" > "$gau_out" || true

    local url_count; url_count=$(wc -l < "$gau_out")
    log_only "[GAU] ${url_count} URLs históricas recuperadas"

    if [[ "${TOOL_OK[unfurl]:-false}" == true ]]; then
        # unfurl es más preciso para extraer dominios
        unfurl domains < "$gau_out" 2>/dev/null \
            | tr '[:upper:]' '[:lower:]' \
            | grep -E "(^|\.)${DOMAIN}$" \
            | sort -u >> "$domains_out" || true
    else
        _extract_domains_from_urls "$gau_out" >> "$domains_out"
    fi

    rm -f "$gau_out"
    return 0
}

# Extrae subdomains ocultos en ficheros JavaScript.
# Input: fichero con URLs raw del crawl activo.
_crawl_subjs() {
    local urls_file="$1" domains_out="$2"
    [[ "${TOOL_OK[subjs]:-false}" == true ]] || return 1
    [[ -s "$urls_file" ]] || return 1

    # Filtrar solo URLs de JS
    local js_urls; js_urls=$(mktemp --suffix=.jsurls)
    grep -iE '\.(js)(\?[^[:space:]]*)?$' "$urls_file" \
        | sort -u > "$js_urls"

    local js_count; js_count=$(wc -l < "$js_urls")
    (( js_count == 0 )) && { rm -f "$js_urls"; return 1; }

    info_msg "  Motor JS: ${BOLD}subjs${NC}  (${js_count} ficheros JS)"
    timeout "$STEP_TIMEOUT" subjs -i "$js_urls" 2>>"$LOG" \
        | tr '[:upper:]' '[:lower:]' \
        | grep -E "(^|\.)${DOMAIN}$" \
        | sort -u >> "$domains_out" || true

    rm -f "$js_urls"
    return 0
}

# B4 — Wrapper principal de crawling
run_crawl() {
    (( CRAWL_DEPTH == 0 )) && { skip_msg "crawl" "desactivado con --skip-crawl"; return; }

    # Verificar que haya al menos una herramienta de crawling
    local has_active=false has_historical=false
    for t in katana gospider;  do [[ "${TOOL_OK[$t]:-false}" == true ]] && has_active=true; done
    [[ "${TOOL_OK[gau]:-false}" == true ]] && has_historical=true

    if ! $has_active && ! $has_historical; then
        skip_msg "crawl" "instala katana, gospider o gau para habilitar B4"
        return
    fi

    local out="$BRUTEFORCE_DIR/crawl.txt"
    [[ "$FORCE" == false && -s "$out" ]] && {
        skip_msg "crawl" "resultado previo (usa --force)"; return
    }
    touch "$out"

    local motors=""
    $has_active    && motors+="$( [[ "${TOOL_OK[katana]:-false}"   == true ]] && echo "katana" || echo "gospider" ) "
    $has_historical && motors+="gau "
    [[ "${TOOL_OK[subjs]:-false}" == true ]] && motors+="subjs "

    info_msg "Crawling B4 — motores: ${BOLD}${motors}${NC}"
    local start=$SECONDS

    # Ficheros intermedios compartidos entre sub-funciones
    local raw_urls; raw_urls=$(mktemp --suffix=.raw_urls)
    local domains_tmp; domains_tmp=$(mktemp --suffix=.domains)

    # 1) Crawl activo: katana o gospider
    if $has_active; then
        _crawl_active "$raw_urls" "$domains_tmp"
        local active_urls; active_urls=$(wc -l < "$raw_urls")
        log_only "[CRAWL_ACTIVE] ${active_urls} URLs recolectadas"
    fi

    # 2) URLs históricas: gau
    if $has_historical; then
        _crawl_gau "$domains_tmp"
    fi

    # 3) JS analysis: subjs (usa URLs del crawl activo)
    _crawl_subjs "$raw_urls" "$domains_tmp"

    # 4) Consolidar y filtrar scope
    sort -u "$domains_tmp" \
        | grep -E "(^|\.)${DOMAIN}$" \
        | grep -v '^\.' > "$out" 2>/dev/null || true

    normalize_and_filter "$out"
    rm -f "$raw_urls" "$domains_tmp"

    # Guardar también las URLs raw para subjs en futuras ejecuciones con --force
    local found; found=$(wc -l < "$out" 2>/dev/null || echo 0)

    if (( found == 0 )); then
        warn "crawl — sin hallazgos (¿target no accesible o requiere auth?)"
    else
        ok_msg "crawl" "${found} subdomains únicos extraídos  $(elapsed_fmt $(( SECONDS - start )))"
    fi
}

update_tools() {
    log_only "[UPDATE] Actualizando herramientas en background..."
    for tool in subfinder httpx alterx chaos; do
        [[ "${TOOL_OK[$tool]:-false}" == true ]] && "$tool" -up -silent >>"$LOG" 2>&1 &
    done
    wait
    log_only "[UPDATE] Completado"
}

# ============================================================
# Resumen final
# ============================================================
print_summary() {
    local final="$OUTPUT_DIR/subdomains.txt"
    local alive="$OUTPUT_DIR/subdomains_alive.txt"
    local ips="$OUTPUT_DIR/ips.txt"
    local total_elapsed=$(( SECONDS - START_TIME ))

    local cnt_total=0 cnt_resolved=0 cnt_alive=0 cnt_ips=0 cnt_passive=0 cnt_bf=0
    [[ -f "$final" ]]                                          && cnt_total=$(wc -l < "$final")
    [[ -f "$RAW_DIR/resolved.txt" ]]                  && cnt_resolved=$(wc -l < "$RAW_DIR/resolved.txt")
    [[ -f "$alive" ]]                                          && cnt_alive=$(wc -l < "$alive")
    [[ -f "$ips"   ]]                                          && cnt_ips=$(wc -l < "$ips")
    [[ -f "$PASSIVE_DIR/passive_merged.txt"       ]]   && cnt_passive=$(wc -l < "$PASSIVE_DIR/passive_merged.txt")
    [[ -f "$BRUTEFORCE_DIR/bruteforce_merged.txt" ]]   && cnt_bf=$(wc -l < "$BRUTEFORCE_DIR/bruteforce_merged.txt")

    # Únicos del modo bruteforce (no vistos en pasivo)
    local cnt_bf_unique=0
    if $MODE_PASSIVE && $MODE_BRUTEFORCE \
       && [[ -f "$PASSIVE_DIR/passive_merged.txt" && -f "$BRUTEFORCE_DIR/bruteforce_merged.txt" ]]; then
        cnt_bf_unique=$(comm -23 \
            <(sort -u "$BRUTEFORCE_DIR/bruteforce_merged.txt") \
            <(sort -u "$PASSIVE_DIR/passive_merged.txt") | wc -l)
    fi

    local sc; sc=$(_banner_color)

    echo ""
    echo -e "${BOLD}${sc}  ╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${sc}  ║${NC}${BOLD}  RESUMEN FINAL                                       ${sc}║${NC}"
    echo -e "${BOLD}${sc}  ╠══════════════════════════════════════════════════════╣${NC}"
    printf "${sc}  ║${NC}  ${BOLD}%-28s${NC}  ${GRN}${BOLD}%-20s${NC} ${sc}║${NC}\n" "Dominio:"        "$DOMAIN"
    echo -e "${sc}  ║${NC}  ${BOLD}Modo:${NC}                       $(_mode_label)"
    printf "${sc}  ║${NC}  %-28s  %-20s ${sc}║${NC}\n"                                "Duración total:" "$(elapsed_fmt $total_elapsed)"
    echo -e "${BOLD}${sc}  ╠══════════════════════════════════════════════════════╣${NC}"

    if $MODE_PASSIVE; then
        printf "${sc}  ║${NC}  ${BLU}%-28s${NC}  ${BOLD}%-20s${NC} ${sc}║${NC}\n"     "Pasivo (únicos):"  "$cnt_passive"
    fi
    if $MODE_BRUTEFORCE; then
        if $MODE_PASSIVE; then
            printf "${sc}  ║${NC}  ${RED}%-28s${NC}  ${BOLD}%-20s${NC} ${sc}║${NC}\n" "Fuerza bruta (total):" "$cnt_bf"
            printf "${sc}  ║${NC}  ${RED}%-28s${NC}  ${BOLD}+%-19s${NC} ${sc}║${NC}\n" "  └─ aportados nuevos:" "$cnt_bf_unique"
        else
            printf "${sc}  ║${NC}  ${RED}%-28s${NC}  ${BOLD}%-20s${NC} ${sc}║${NC}\n" "Fuerza bruta (únicos):" "$cnt_bf"
        fi
    fi

    echo -e "${BOLD}${sc}  ╠══════════════════════════════════════════════════════╣${NC}"
    printf "${sc}  ║${NC}  %-28s  ${GRN}${BOLD}%-20s${NC} ${sc}║${NC}\n" "Subdomains únicos:"   "$cnt_total"
    printf "${sc}  ║${NC}  %-28s  ${GRN}${BOLD}%-20s${NC} ${sc}║${NC}\n" "Resueltos (DNS):"     "$cnt_resolved"
    printf "${sc}  ║${NC}  %-28s  ${GRN}${BOLD}%-20s${NC} ${sc}║${NC}\n" "Vivos (HTTP/S):"      "$cnt_alive"
    printf "${sc}  ║${NC}  %-28s  ${GRN}${BOLD}%-20s${NC} ${sc}║${NC}\n" "IPs asociadas:"       "$cnt_ips"
    echo -e "${BOLD}${sc}  ╠══════════════════════════════════════════════════════╣${NC}"
    printf "${sc}  ║${NC}  ${BOLD}%-28s${NC}  ${GRN}%-20s${NC} ${sc}║${NC}\n" "► Resultado final:"   "subdomains.txt"
    if (( cnt_alive > 0 )); then
    printf "${sc}  ║${NC}  ${BOLD}%-28s${NC}  ${GRN}%-20s${NC} ${sc}║${NC}\n" "► Hosts vivos:"       "subdomains_alive.txt"
    fi
    echo -e "${BOLD}${sc}  ╠══════════════════════════════════════════════════════╣${NC}"
    printf "${sc}  ║${NC}  %-28s  ${DIM}%-20s${NC} ${sc}║${NC}\n" "Directorio:"        "$OUTPUT_DIR/"
    printf "${sc}  ║${NC}  %-28s  ${DIM}%-20s${NC} ${sc}║${NC}\n" "Datos intermedios:" "raw/"
    printf "${sc}  ║${NC}  %-28s  ${DIM}%-20s${NC} ${sc}║${NC}\n" "Log completo:"      "recon.log"
    echo -e "${BOLD}${sc}  ╚══════════════════════════════════════════════════════╝${NC}"
    echo ""

    # Top 5 fuentes pasivas
    if $MODE_PASSIVE; then
        echo -e "  ${BOLD}Top fuentes pasivas:${NC}"
        for f in "$PASSIVE_DIR"/*.txt; do
            [[ "$(basename "$f")" == "passive_merged.txt" ]] && continue
            [[ -f "$f" ]] && printf "%d %s\n" "$(wc -l < "$f")" "$(basename "$f" .txt)"
        done | sort -rn | head -5 | while IFS=' ' read -r count src; do
            (( count > 0 )) && printf "    ${GRN}${ICO_OK}${NC}  %-20s  ${BOLD}%d${NC}\n" "$src" "$count"
        done
        echo ""
    fi

    # Clasificación
    local classified_dir="$RAW_DIR/classified"
    if [[ -f "$classified_dir/all_classified.txt" ]]; then
        echo -e "  ${BOLD}Clasificación (top categorías):${NC}"
        for cat in admin auth internal vpn dev api git monitoring; do
            local cf="$classified_dir/${cat}.txt"
            [[ -f "$cf" ]] || continue
            local n; n=$(wc -l < "$cf")
            (( n > 0 )) || continue
            local color="$NC"
            case "$cat" in admin|auth|internal|vpn) color="$RED" ;; dev|git) color="$YEL" ;; esac
            printf "    ${color}${ICO_OK}${NC}  %-14s  ${BOLD}%d${NC}\n" "$cat:" "$n"
        done
        echo ""
    fi

    # Takeovers
    if $TAKEOVER && [[ -f "$OUTPUT_DIR/takeovers.txt" ]]; then
        local tk_count; tk_count=$(wc -l < "$OUTPUT_DIR/takeovers.txt")
        if (( tk_count > 0 )); then
            printf "  ${RED}${BOLD}${ICO_FAIL}  %-28s  %d candidatos${NC}\n" "Posibles takeovers:" "$tk_count"
            echo ""
        fi
    fi

    # Stats de fuerza bruta
    if $MODE_BRUTEFORCE; then
        echo -e "  ${BOLD}Fuerza bruta — detalle por módulo:${NC}"
        local bf_dns=0 bf_perms=0 bf_recursive=0 bf_amass=0
        [[ -f "$BRUTEFORCE_DIR/dns_bruteforce.txt" ]] && bf_dns=$(wc -l < "$BRUTEFORCE_DIR/dns_bruteforce.txt")
        [[ -f "$BRUTEFORCE_DIR/permutations.txt"   ]] && bf_perms=$(wc -l < "$BRUTEFORCE_DIR/permutations.txt")
        [[ -f "$BRUTEFORCE_DIR/recursive.txt"      ]] && bf_recursive=$(wc -l < "$BRUTEFORCE_DIR/recursive.txt")
        [[ -f "$BRUTEFORCE_DIR/amass_active.txt"   ]] && bf_amass=$(wc -l < "$BRUTEFORCE_DIR/amass_active.txt")
        local wc_count=0
        [[ -f "$RAW_DIR/wildcards.txt" ]] && wc_count=$(wc -l < "$RAW_DIR/wildcards.txt")
        local bf_crawl=0
        [[ -f "$BRUTEFORCE_DIR/crawl.txt" ]] && bf_crawl=$(wc -l < "$BRUTEFORCE_DIR/crawl.txt")
        printf "    ${RED}${ICO_OK}${NC}  %-22s  ${BOLD}%d${NC}\n" "dns_bruteforce (B1):"  "$bf_dns"
        printf "    ${RED}${ICO_OK}${NC}  %-22s  ${BOLD}%d${NC}\n" "permutations (B2):"    "$bf_perms"
        printf "    ${RED}${ICO_OK}${NC}  %-22s  ${BOLD}%d${NC}\n" "amass_active (B3):"    "$bf_amass"
        printf "    ${RED}${ICO_OK}${NC}  %-22s  ${BOLD}%d${NC}  ${DIM}[depth: ${CRAWL_DEPTH}]${NC}\n" \
            "crawl (B4):" "$bf_crawl"
        printf "    ${RED}${ICO_OK}${NC}  %-22s  ${BOLD}%d${NC}  ${DIM}[depth: ${RECURSIVE_DEPTH}]${NC}\n" \
            "recursive (B5):" "$bf_recursive"
        printf "    ${YEL}${ICO_WARN}${NC}  %-22s  ${BOLD}%d${NC} IP(s)\n" \
            "wildcards filtrados:" "$wc_count"
        echo ""
    fi
}

# ============================================================
# FASE 5 — Diff, Notify, Takeover auto-prompt
# ============================================================

# Guarda el subdomains.txt actual como baseline antes de re-ejecutar (modo --diff)
_save_prev_final() {
    $DIFF || return
    local final="$OUTPUT_DIR/subdomains.txt"
    if [[ -f "$final" ]]; then
        cp "$final" "${final}.prev"
        local n; n=$(wc -l < "${final}.prev")
        info_msg "Diff mode — baseline guardado: ${n} subdomains en ${final}.prev"
    else
        info_msg "Diff mode — no hay run previo; esta ejecución será la baseline"
    fi
}

# Compara subdomains.txt actual con la baseline y muestra los cambios
print_diff_summary() {
    $DIFF || return
    local final="$OUTPUT_DIR/subdomains.txt"
    local prev="${final}.prev"
    [[ -f "$final" && -f "$prev" ]] || return

    local new_file="$OUTPUT_DIR/diff_new.txt"
    local gone_file="$OUTPUT_DIR/diff_gone.txt"
    comm -23 <(sort -u "$final") <(sort -u "$prev") > "$new_file"
    comm -13 <(sort -u "$final") <(sort -u "$prev") > "$gone_file"

    local cnt_new; cnt_new=$(wc -l < "$new_file")
    local cnt_gone; cnt_gone=$(wc -l < "$gone_file")

    echo ""
    echo -e "${BOLD}${YEL}  ╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${YEL}  ║${NC}${BOLD}  DIFF vs. RUN ANTERIOR                              ${YEL}║${NC}"
    echo -e "${BOLD}${YEL}  ╠══════════════════════════════════════════════════════╣${NC}"
    printf "${YEL}  ║${NC}  ${GRN}${BOLD}+%-27s${NC}  ${BOLD}%-20s${NC} ${YEL}║${NC}\n" " Nuevos subdomains:"    "$cnt_new"
    printf "${YEL}  ║${NC}  ${RED}${BOLD}-%-27s${NC}  ${BOLD}%-20s${NC} ${YEL}║${NC}\n" " Desaparecidos:"        "$cnt_gone"
    echo -e "${BOLD}${YEL}  ╠══════════════════════════════════════════════════════╣${NC}"

    if (( cnt_new > 0 )); then
        echo -e "${YEL}  ║${NC}  ${GRN}${BOLD}Nuevos:${NC}"
        head -10 "$new_file" | while IFS= read -r line; do
            printf "${YEL}  ║${NC}    ${GRN}+${NC} %s\n" "$line"
        done
        (( cnt_new > 10 )) && \
            printf "${YEL}  ║${NC}    ${DIM}… y %d más → %s${NC}\n" "$(( cnt_new - 10 ))" "$new_file"
    fi

    if (( cnt_gone > 0 )); then
        echo -e "${YEL}  ║${NC}  ${RED}${BOLD}Desaparecidos:${NC}"
        head -5 "$gone_file" | while IFS= read -r line; do
            printf "${YEL}  ║${NC}    ${RED}-${NC} %s\n" "$line"
        done
        (( cnt_gone > 5 )) && \
            printf "${YEL}  ║${NC}    ${DIM}… y %d más → %s${NC}\n" "$(( cnt_gone - 5 ))" "$gone_file"
    fi

    echo -e "${BOLD}${YEL}  ╚══════════════════════════════════════════════════════╝${NC}"
    echo ""
    log_only "[DIFF] +${cnt_new} nuevos / -${cnt_gone} desaparecidos"
}

# Notificación de escritorio + bell al finalizar (siempre hace el bell)
notify_done() {
    local cnt_alive="${1:-0}"
    local title="Recon: ${DOMAIN}"
    local body="Completado — ${cnt_alive} hosts vivos"

    # Terminal bell (universal)
    printf '\a' 2>/dev/null || true

    $NOTIFY || return

    # macOS
    if command -v osascript &>/dev/null; then
        osascript -e \
            "display notification \"${body}\" with title \"${title}\"" \
            2>/dev/null || true
    # Linux (freedesktop)
    elif command -v notify-send &>/dev/null; then
        notify-send -i dialog-information "$title" "$body" 2>/dev/null || true
    # Windows WSL — PowerShell toast simplificado
    elif command -v powershell.exe &>/dev/null; then
        powershell.exe -NoProfile -Command \
            "Add-Type -AssemblyName System.Windows.Forms; \
             \$b = New-Object System.Windows.Forms.NotifyIcon; \
             \$b.Icon = [System.Drawing.SystemIcons]::Information; \
             \$b.Visible = \$true; \
             \$b.ShowBalloonTip(5000, '${title}', '${body}', \
               [System.Windows.Forms.ToolTipIcon]::Info); \
             Start-Sleep 6; \$b.Dispose()" \
            2>/dev/null || true
    fi
}

# Si hay hosts vivos y el usuario no pasó --takeover, preguntar (solo en TTY)
_maybe_prompt_takeover() {
    $TAKEOVER      && return   # ya está activado
    $NO_CONFIRM    && return   # modo no-interactivo
    [[ ! -t 0 ]]   && return   # sin TTY

    local alive="$OUTPUT_DIR/subdomains_alive.txt"
    [[ -s "$alive" ]] || return

    local n; n=$(wc -l < "$alive")
    echo ""
    echo -e "${YEL}  ${ICO_WARN}  ${BOLD}${n}${NC}${YEL} hosts vivos detectados.${NC}"
    printf "  ¿Ejecutar detección de ${BOLD}subdomain takeover${NC}? [s/N] "
    local ans
    if read -r -t 20 ans 2>/dev/null; then
        [[ "${ans,,}" == "s" || "${ans,,}" == "y" ]] && TAKEOVER=true
    fi
    echo ""
}

# ============================================================
# MAIN
# ============================================================
main() {
    START_TIME=$SECONDS
    parse_args "$@"
    interactive_menu         # solo si no se eligió modo en CLI

    mkdir -p "$OUTPUT_DIR"
    LOG="$OUTPUT_DIR/recon.log"
    PROGRESS_DIR="$OUTPUT_DIR/.progress"
    RAW_DIR="$OUTPUT_DIR/raw"
    PASSIVE_DIR="$RAW_DIR/passive"
    BRUTEFORCE_DIR="$RAW_DIR/bruteforce"
    mkdir -p "$PROGRESS_DIR" "$RAW_DIR" "$PASSIVE_DIR" "$BRUTEFORCE_DIR"

    # Ficheros vacíos para evitar errores en cat
    for f in subfinder assetfinder findomain amass_passive github chaos \
              crtsh wayback virustotal alienvault urlscan hackertarget rapiddns \
              securitytrails censys binaryedge bevigil fullhunt netlas \
              bufferover shodan_dns facebook_ct; do
        touch "$PASSIVE_DIR/${f}.txt"
    done
    for f in amass_active dns_bruteforce permutations crawl recursive; do
        touch "$BRUTEFORCE_DIR/${f}.txt"
    done

    log_only "════════════════════════════════════"
    log_only " recon_subdomains v2.6 — $DOMAIN"
    log_only " Modo: passive=$MODE_PASSIVE bruteforce=$MODE_BRUTEFORCE"
    log_only " $(date)"
    log_only "════════════════════════════════════"

    trap 'stop_spinner; echo ""; echo -e "\n${YEL}  ${ICO_WARN} Interrumpido — resultados parciales en ${OUTPUT_DIR}/${NC}"; exit 130' INT TERM
    trap 'stop_spinner' EXIT

    # Pre-inicializar KEY_OK para que _estimate_duration en banner sea correcta
    KEY_OK[github]=false;         [[ -n "${GITHUB_TOKEN:-}" ]]          && KEY_OK[github]=true         || true
    KEY_OK[virustotal]=false;     [[ -n "${VT_APIKEY:-}" ]]             && KEY_OK[virustotal]=true     || true
    KEY_OK[chaos]=false;          [[ -n "${PDCP_API_KEY:-}" ]]          && KEY_OK[chaos]=true          || true
    KEY_OK[securitytrails]=false; [[ -n "${SECURITYTRAILS_KEY:-}" ]]    && KEY_OK[securitytrails]=true || true
    KEY_OK[censys]=false
    [[ -n "${CENSYS_PAT:-}" ]]                           && KEY_OK[censys]=true || true
    [[ -n "${CENSYS_ID:-}" && -n "${CENSYS_SECRET:-}" ]] && KEY_OK[censys]=true || true
    KEY_OK[binaryedge]=false;     [[ -n "${BINARYEDGE_KEY:-}" ]]        && KEY_OK[binaryedge]=true     || true
    KEY_OK[bevigil]=false;        [[ -n "${BEVIGIL_KEY:-}" ]]           && KEY_OK[bevigil]=true        || true
    KEY_OK[fullhunt]=false;       [[ -n "${FULLHUNT_KEY:-}" ]]          && KEY_OK[fullhunt]=true       || true
    KEY_OK[netlas]=false;         [[ -n "${NETLAS_KEY:-}" ]]            && KEY_OK[netlas]=true         || true
    KEY_OK[shodan]=false;         [[ -n "${SHODAN_API_KEY:-}" ]]        && KEY_OK[shodan]=true         || true
    KEY_OK[facebook]=true

    banner
    check_dependencies

    # Guardar baseline antes de sobreescribir (modo --diff)
    _save_prev_final

    # Actualizar herramientas en background
    update_tools &
    local update_pid=$!

    # ── FASE PASIVA ──────────────────────────────────────────
    if $MODE_PASSIVE; then
        phase "FASE PASIVA — Fuentes OSINT  (paralelo)" "$BLU"

        local passive_sources=(
            subfinder assetfinder findomain amass_passive
            github chaos crtsh wayback
            virustotal alienvault urlscan hackertarget rapiddns
            securitytrails censys binaryedge bevigil fullhunt
            netlas bufferover shodan_dns facebook_ct
        )

        # Registrar fuentes esperadas para el monitor de debug
        printf '%s\n' "${passive_sources[@]}" > "$PROGRESS_DIR/.expected"

        # Capturar PIDs de solo las fuentes pasivas para no bloquear en update_tools
        local _passive_pids=()
        src_subfinder       & _passive_pids+=($!)
        src_assetfinder     & _passive_pids+=($!)
        src_findomain       & _passive_pids+=($!)
        src_amass_passive   & _passive_pids+=($!)
        src_github          & _passive_pids+=($!)
        src_chaos           & _passive_pids+=($!)
        src_crtsh           & _passive_pids+=($!)
        src_wayback         & _passive_pids+=($!)
        src_virustotal      & _passive_pids+=($!)
        src_alienvault      & _passive_pids+=($!)
        src_urlscan         & _passive_pids+=($!)
        src_hackertarget    & _passive_pids+=($!)
        src_rapiddns        & _passive_pids+=($!)
        src_securitytrails  & _passive_pids+=($!)
        src_censys          & _passive_pids+=($!)
        src_binaryedge      & _passive_pids+=($!)
        src_bevigil         & _passive_pids+=($!)
        src_fullhunt        & _passive_pids+=($!)
        src_netlas          & _passive_pids+=($!)
        src_bufferover      & _passive_pids+=($!)
        src_shodan_dns      & _passive_pids+=($!)
        src_facebook_ct     & _passive_pids+=($!)

        start_spinner "Consultando fuentes pasivas" ${#passive_sources[@]}
        wait "${_passive_pids[@]}"
        stop_spinner

        print_source_table "${passive_sources[@]}"
        phase_end
    fi

    # ── FASE FUERZA BRUTA ────────────────────────────────────
    if $MODE_BRUTEFORCE; then
        phase "FASE FUERZA BRUTA — B1: Preparación" "$RED"
        prepare_resolvers
        prepare_wordlist
        detect_wildcard
        phase_end

        phase "FASE FUERZA BRUTA — B1: DNS Bruteforce" "$RED"
        run_dns_bruteforce
        phase_end

        phase "FASE FUERZA BRUTA — B2: Permutaciones" "$RED"
        run_permutations
        phase_end

        phase "FASE FUERZA BRUTA — B3: Enumeración activa" "$RED"
        run_amass_active
        phase_end

        phase "FASE FUERZA BRUTA — B4: Crawling" "$RED"
        run_crawl
        phase_end

        phase "FASE FUERZA BRUTA — B5: Recursión" "$RED"
        run_recursive
        phase_end
    fi

    # ── FASE 4: Calidad y postproceso ────────────────────────
    phase "FASE 4 — Consolidación y resolución DNS" "$MAG"
    consolidate
    run_dns_resolve
    phase_end

    phase "FASE 4 — Sondeo HTTP y recolección" "$MAG"
    run_httpx
    run_ip_collection
    phase_end

    # Preguntar si ejecutar takeover (si hay vivos y no se pidió explícitamente)
    _maybe_prompt_takeover

    phase "FASE 4 — Clasificación y análisis" "$MAG"
    classify_subdomains
    run_takeover
    phase_end

    wait "$update_pid" 2>/dev/null || true

    trap - EXIT INT TERM
    print_summary
    print_diff_summary

    # Notificación al terminar
    local _cnt_alive=0
    [[ -f "$OUTPUT_DIR/subdomains_alive.txt" ]] && \
        _cnt_alive=$(wc -l < "$OUTPUT_DIR/subdomains_alive.txt")
    notify_done "$_cnt_alive"
}

main "$@"
