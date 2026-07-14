#!/bin/bash

# fix dryrun
# fix vuln to true or false instead of reading output

# ── Globals ────────────────────────────────────
v_level=0
ips=()
list=""
target=""
output_dir="."
check_tcp=false
check_udp=false
check_vuln=false
check_all=false
summary=()
cached_tcp_ports=""
cached_udp_ports=""

# ── Color codes ────────────────────────────────
WHITE='\033[1;37m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# ── Logging ────────────────────────────────────
log() {
  [[ "$v_level" -ge 1 ]] && echo -e "${BLUE}[verbose]${NC} $*"
}

# ── Root check ─────────────────────────────────
check_root() {
  if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}Error: This script must be run as root (UDP and vuln scans require it)${NC}" >&2
    exit 1
  fi
}

# ── Dependency check ───────────────────────────
check_deps() {
  if ! command -v nmap &>/dev/null; then
    echo -e "${RED}Error: nmap is not installed or not in PATH${NC}" >&2
    exit 1
  fi
}

# ── Usage ──────────────────────────────────────
usage() {
  echo -e "${YELLOW}
--=---+---=--
       \___
 ---=---+-I-=---
        |\\
  ---=----+----=---
        |
        ^

01000001 01010101 01010100 01001111  00101101  01010000 01001101${NC}"

  echo -e "\n${WHITE}Options:
 -h, --help\t\tDisplay this help message
 -v, --verbose\t\tEnable verbose mode (use -vv to also preview commands without executing)
 -i, --ip\t\tRemote host IP(s), comma-separated or CIDR (e.g. 10.0.0.1,10.0.0.2 or 10.0.0.0/24)
 -l, --list\t\tScan a list of IP addresses from file
 -t, --tcp\t\tPerform NMAP TCP scan and output file
 -u, --udp\t\tPerform NMAP UDP scan and output file
 -V, --vuln\t\tPerform NMAP Vuln script scan
 -a, --all\t\tPerform all scan types (TCP, UDP, Vuln)
 -o, --output\t\tDirectory to save output files (default: current directory)${NC}\n"
}

# ── Validation ─────────────────────────────────
validate() {
  if [[ ${#ips[@]} -eq 0 && -z "$list" ]]; then
    echo -e "${RED}Error: You must provide a target with -i or -l${NC}" >&2
    usage
    exit 1
  fi

  if [[ ${#ips[@]} -gt 0 && -n "$list" ]]; then
    echo -e "${RED}Error: Use either -i or -l, not both${NC}" >&2
    exit 1
  fi

  if [[ -n "$list" && ! -f "$list" ]]; then
    echo -e "${RED}Error: List file '$list' not found${NC}" >&2
    exit 1
  fi

  if [[ "$check_tcp" == false && "$check_udp" == false && "$check_vuln" == false && "$check_all" == false ]]; then
    echo -e "${YELLOW}Warning: No scan type specified (-t, -u, -V, -a). Nothing to do.${NC}"
    usage
    exit 0
  fi

  if [[ ! -d "$output_dir" ]]; then
    echo -e "${YELLOW}Output directory '$output_dir' not found, creating it...${NC}"
    mkdir -p "$output_dir" || { echo -e "${RED}Error: Could not create output directory${NC}" >&2; exit 1; }
  fi

  log "Validation passed"
  log "Output directory: $(realpath "$output_dir")"
  log "Scan types — TCP: $check_tcp | UDP: $check_udp | Vuln: $check_vuln"
}

# ── Set target ─────────────────────────────────
set_target() {
  if [[ -n "$list" ]]; then
    target="-iL $list"
    log "Using target list: $list"
  else
    target="${ips[*]}"
    log "Using target IPs: $target"
  fi
}

# ── Parse IPs ──────────────────────────────────
parse_ips() {
  local raw="$1"
  IFS=',' read -ra parsed <<< "$raw"
  for entry in "${parsed[@]}"; do
    entry="${entry// /}"
    ips+=("$entry")
    log "Added target: $entry"
  done
}

# ── Run nmap (vv-aware) ────────────────────────
run_nmap() {
  if [[ "$v_level" -ge 2 ]]; then
    echo -e "${BLUE}[verbose]${NC} nmap $*"
  else
    nmap "$@"
  fi
}

# ── Scan: TCP ──────────────────────────────────
tcp_scan() {
  echo -e "\n${GREEN}         	⢹⠁ ⡎⠑ ⣏⡱   ⢎⡑ ⡎⠑ ⣎⣱ ⡷⣸
	⠉⠉ ⠉⠉   ⠸  ⠣⠔ ⠇    ⠢⠜ ⠣⠔ ⠇⠸ ⠇⠹   ⠉⠉ ⠉⠉${NC}\n"

  local tcp_output=""

  if [[ "$v_level" -ge 2 ]]; then
    echo -e "${BLUE}[verbose]${NC} nmap $ip -p- --min-rate=1000 -Pn -oG -"
    echo -e "${BLUE}[verbose]${NC} nmap $ip -p <ports> -Pn -sV -sC -oN $output_dir/TCP-$ip"
    return
  fi

  echo -e "${WHITE}[1/2] Discovering open ports...${NC}"
  log "Starting full port discovery on $ip"

  tcp_output=$(nmap "$ip" -p- --min-rate=1000 -Pn -oG - \
    | grep -oP '\d+/open' \
    | cut -d'/' -f1 \
    | tr '\n' ',' \
    | sed 's/,$//')

  log "Raw tcp_output: $tcp_output"
  cached_tcp_ports="$tcp_output"

  if [[ -z "$tcp_output" ]]; then
    echo -e "${RED}No open ports found on $ip${NC}"
    summary+=("TCP | $ip | No open ports found")
  else
    echo -e "${WHITE}Ports found: ${GREEN}$tcp_output${NC}"
    echo -e "${WHITE}[2/2] Running scripts...${NC}"
    log "Launching script scan on ports: $tcp_output"
    run_nmap "$ip" -p "$tcp_output" -Pn -sV -sC -oN "$output_dir/TCP-$ip" &>/dev/null
    log "Output saved to $output_dir/TCP-$ip"
    echo -e "${GREEN}Saved: $output_dir/TCP-$ip${NC}"
    summary+=("TCP | $ip | Ports: $tcp_output | Saved: $output_dir/TCP-$ip")
  fi
}

# ── Scan: UDP ──────────────────────────────────
udp_scan() {
  echo -e "\n${GREEN}         	⡇⢸ ⡏⢱ ⣏⡱   ⢎⡑ ⡎⠑ ⣎⣱ ⡷⣸
	⠉⠉ ⠉⠉   ⠣⠜ ⠧⠜ ⠇    ⠢⠜ ⠣⠔ ⠇⠸ ⠇⠹   ⠉⠉ ⠉⠉${NC}\n"

  local udp_output=""

  if [[ "$v_level" -ge 2 ]]; then
    echo -e "${BLUE}[verbose]${NC} nmap $ip -F -sU -oG -"
    echo -e "${BLUE}[verbose]${NC} nmap $ip -p <ports> -sU -sV -sC -oN $output_dir/UDP-$ip"
    return
  fi

  echo -e "${WHITE}[1/2] Discovering open ports...${NC}"
  log "Starting UDP fast scan on $ip"

  udp_output=$(nmap "$ip" -F -sU -oG - \
    | grep -oP '\d+/open' \
    | cut -d'/' -f1 \
    | tr '\n' ',' \
    | sed 's/,$//')

  log "Raw udp_output: $udp_output"
  cached_udp_ports="$udp_output"

  if [[ -z "$udp_output" ]]; then
    echo -e "${RED}No open ports found on $ip${NC}"
    summary+=("UDP | $ip | No open ports found")
  else
    echo -e "${WHITE}Ports found: ${GREEN}$udp_output${NC}"
    echo -e "${WHITE}[2/2] Running scripts...${NC}"
    log "Launching script scan on ports: $udp_output"
    run_nmap "$ip" -p "$udp_output" -sU -sV -sC -oN "$output_dir/UDP-$ip" &>/dev/null
    log "Output saved to $output_dir/UDP-$ip"
    echo -e "${GREEN}Saved: $output_dir/UDP-$ip${NC}"
    summary+=("UDP | $ip | Ports: $udp_output | Saved: $output_dir/UDP-$ip")
  fi
}

# ── Scan: Vuln ─────────────────────────────────
vuln_scan() {
  echo -e "\n${GREEN}         	⡇⢸ ⡇⢸ ⡇  ⡷⣸   ⢎⡑ ⡎⠑ ⣎⣱ ⡷⣸
	⠉⠉ ⠉⠉   ⠸⠃ ⠣⠜ ⠧⠤ ⠇⠹   ⠢⠜ ⠣⠔ ⠇⠸ ⠇⠹   ⠉⠉ ⠉⠉${NC}\n"

  local out_file="$output_dir/VULN-$ip"
  log "Starting vuln scan on $ip"

  if [[ "$v_level" -ge 2 ]]; then
    echo -e "${BLUE}[verbose]${NC} nmap $ip -p- --min-rate=1000 -Pn -oG - (TCP discovery)"
    echo -e "${BLUE}[verbose]${NC} nmap $ip -p <ports> -Pn --script vuln >> $out_file"
    echo -e "${BLUE}[verbose]${NC} nmap $ip -F -sU -oG - (UDP discovery)"
    echo -e "${BLUE}[verbose]${NC} nmap $ip -p <ports> -sU --script vuln >> $out_file"
    return
  fi

  # TCP vuln
  local tcp_output=""
  local step=1
  local total=4

  if [[ -n "$cached_tcp_ports" ]]; then
    tcp_output="$cached_tcp_ports"
    total=$((total - 1))
    log "Reusing cached TCP ports: $tcp_output"
  else
    echo -e "${WHITE}[$step/$total] TCP port discovery...${NC}"
    log "Starting TCP port discovery on $ip"
    tcp_output=$(nmap "$ip" -p- --min-rate=1000 -Pn -oG - \
      | grep -oP '\d+/open' \
      | cut -d'/' -f1 \
      | tr '\n' ',' \
      | sed 's/,$//')
    log "TCP ports for vuln scan: $tcp_output"
    step=$((step + 1))
  fi

  if [[ -z "$tcp_output" ]]; then
    echo -e "${RED}TCP: No open ports on $ip, skipping${NC}"
    summary+=("VULN/TCP | $ip | No open ports found")
  else
    echo -e "${WHITE}[$step/$total] Running TCP vuln scripts...${NC}"
    log "Launching TCP vuln scripts on ports: $tcp_output"
    echo -e "TCP RESULTS\n" >> "$out_file"
    run_nmap "$ip" -p "$tcp_output" -Pn --script vuln >> "$out_file"
    log "TCP vuln results appended to $out_file"
    summary+=("VULN/TCP | $ip | Ports: $tcp_output | Saved: $out_file")
  fi
  step=$((step + 1))

  # UDP vuln
  local udp_output=""

  if [[ -n "$cached_udp_ports" ]]; then
    udp_output="$cached_udp_ports"
    total=$((total - 1))
    log "Reusing cached UDP ports: $udp_output"
  else
    echo -e "${WHITE}[$step/$total] UDP port discovery...${NC}"
    log "Starting UDP port discovery on $ip"
    udp_output=$(nmap "$ip" -F -sU -oG - \
      | grep -oP '\d+/open' \
      | cut -d'/' -f1 \
      | tr '\n' ',' \
      | sed 's/,$//')
    log "UDP ports for vuln scan: $udp_output"
    step=$((step + 1))
  fi

  if [[ -z "$udp_output" ]]; then
    echo -e "${RED}UDP: No open ports on $ip, skipping${NC}"
    summary+=("VULN/UDP | $ip | No open ports found")
  else
    echo -e "${WHITE}[$step/$total] Running UDP vuln scripts...${NC}"
    log "Launching UDP vuln scripts on ports: $udp_output"
    echo -e "UDP RESULTS\n" >> "$out_file"
    run_nmap "$ip" -p "$udp_output" -sU --script vuln >> "$out_file"
    log "UDP vuln results appended to $out_file"
    summary+=("VULN/UDP | $ip | Ports: $udp_output | Saved: $out_file")
  fi
}
# ── Go Through Selected Scans ────────────────────
cycle_scans() {
  for ip in "${ips[@]}"; do
    cached_tcp_ports=""
    cached_udp_ports=""
    echo -e "${YELLOW}Now scanning ${GREEN}$ip${NC}\n"

    [[ "$check_tcp"  == true ]] && tcp_scan "$ip"
    [[ "$check_udp"  == true ]] && udp_scan "$ip"
    [[ "$check_vuln" == true ]] && vuln_scan "$ip"
  done
}

# ── Summary ────────────────────────────────────
summary() {
  echo -e "\n${BLUE}══════════════════════════════════════${NC}"
  echo -e "${WHITE}  Scan Summary${NC}"
  echo -e "${BLUE}══════════════════════════════════════${NC}"
  for entry in "${summary[@]}"; do
    IFS='|' read -r scan ip rest <<< "$entry"
    echo -e " ${GREEN}[${scan// /}]${NC} ${WHITE}$ip${NC} —$rest"
  done
  echo -e "${BLUE}══════════════════════════════════════${NC}\n"
}

# ── Argument parsing ───────────────────────────
handle_options() {
  while [[ $# -gt 0 ]]; do
    case $1 in
      -h | --help)
        usage
        exit 0
        ;;
      -v | --verbose)
        v_level=1
        log "Verbose mode enabled"
        ;;
      -vv)
        v_level=2
        echo -e "${BLUE}[verbose]${NC} Verbose mode enabled — commands will be printed without executing"
        ;;
      -i | --ip)
        if [[ -z "$2" || "$2" == -* ]]; then
          echo -e "${RED}Error: --ip requires an argument${NC}" >&2
          exit 1
        fi
        parse_ips "$2"
        shift
        ;;
      -l | --list)
        if [[ -z "$2" || "$2" == -* ]]; then
          echo -e "${RED}Error: --list requires a file path${NC}" >&2
          exit 1
        fi
        list="$2"
        shift
        ;;
      -o | --output)
        if [[ -z "$2" || "$2" == -* ]]; then
          echo -e "${RED}Error: --output requires a directory path${NC}" >&2
          exit 1
        fi
        output_dir="$2"
        shift
        ;;
      -t | --tcp)  check_tcp=true  ;;
      -u | --udp)  check_udp=true  ;;
      -V | --vuln) check_vuln=true ;;
      -a | --all)  check_all=true  ;;
      *)
        echo -e "${RED}Error: Unknown option '$1'${NC}" >&2
        usage
        exit 1
        ;;
    esac
    shift
  done

  if [[ "$check_all" == true ]]; then
    check_tcp=true
    check_udp=true
    check_vuln=true
  fi
}

# ── Main ───────────────────────────────────────
main() {
  check_root
  check_deps
  handle_options "$@"
  validate
  set_target
  cycle_scans
  summary
  echo -e "\n${BLUE}[+]${GREEN} Done${NC}"
}

main "$@"
