#!/usr/bin/env bash
set -euo pipefail

DOMAIN=""
DOMAINS_FILE=""
PORTS="20,21,22,23,25,53,80,88,135,389,443,445,3389,5985,5986,8080,8081,8433"
OUTJSON=false
OUTDIR=""
JSON_FILENAME="connectivity-results.json"
NMAP_TIMEOUT_SECONDS=60
SCRIPT_NAME="./connectivity-test-zone.sh"

GREEN=$'\033[32m'
RESET=$'\033[0m'
INFO_PREFIX="[${GREEN}+${RESET}]"

REQUIRED_COMMANDS=(
	subfinder
	nmap
	python3
	jq
	sed
	grep
	sort
	wc
	tr
	date
	mktemp
	mkdir
	cp
	cat
	rm
)

usage() {
	cat <<EOF
Usage:
  ${SCRIPT_NAME} --domain example.com [options]
  ${SCRIPT_NAME} -d example.com [options]
  ${SCRIPT_NAME} --domains-file domains.txt [options]
  ${SCRIPT_NAME} -df domains.txt [options]

Options:
  -d,  --domain           DNS zone / root domain to enumerate
  -df, --domains-file     Text file containing DNS zones / root domains to enumerate
  -p,  --ports            Comma-separated ports to test
                          Default: ${PORTS}
  -oj, --outjson          Save JSON output to a file
  -od, --outdir           Output directory for JSON file
                          Only used when --outjson is present
                          Default with --outjson: current directory
  -h,  --help             Help

Examples:
  ${SCRIPT_NAME} --domain example.com
  ${SCRIPT_NAME} -d example.com
  ${SCRIPT_NAME} --domains-file domains.txt
  ${SCRIPT_NAME} -df domains.txt
  ${SCRIPT_NAME} --domain example.com --ports 22,80,443
  ${SCRIPT_NAME} -d example.com -p 22,80,443
  ${SCRIPT_NAME} --domain example.com --outjson
  ${SCRIPT_NAME} -d example.com -oj
  ${SCRIPT_NAME} --domain example.com --outjson --outdir ./results
  ${SCRIPT_NAME} -d example.com -oj -od ./results
EOF
}

check_dependencies() {
	local missing=()

	for cmd in "${REQUIRED_COMMANDS[@]}"; do
		if ! command -v "$cmd" >/dev/null 2>&1; then
			missing+=("$cmd")
		fi
	done

	if ((${#missing[@]} > 0)); then
		echo "[-] Missing required dependencies:" >&2

		for cmd in "${missing[@]}"; do
			echo "    - $cmd" >&2
		done

		echo >&2
		echo "Install the missing dependencies and run the script again." >&2
		exit 1
	fi
}

validate_input() {
	if [[ -n "$DOMAIN" && -n "$DOMAINS_FILE" ]]; then
		echo "[-] Use either --domain or --domains-file, not both." >&2
		usage
		exit 1
	fi

	if [[ -z "$DOMAIN" && -z "$DOMAINS_FILE" ]]; then
		echo "[-] Missing required domain or domains file." >&2
		usage
		exit 1
	fi

	if [[ -n "$DOMAINS_FILE" && ! -f "$DOMAINS_FILE" ]]; then
		echo "[-] Domains file does not exist: $DOMAINS_FILE" >&2
		exit 1
	fi

	if [[ -n "$DOMAINS_FILE" && ! -r "$DOMAINS_FILE" ]]; then
		echo "[-] Domains file is not readable: $DOMAINS_FILE" >&2
		exit 1
	fi
}

require_option_value() {
	local option="$1"
	local value="${2:-}"

	if [[ -z "$value" || "$value" == -* ]]; then
		echo "[-] Missing value for ${option}." >&2
		usage
		exit 1
	fi
}

parse_args() {
	while [[ $# -gt 0 ]]; do
		case "$1" in
		-d | --domain)
			require_option_value "$1" "${2:-}"
			DOMAIN="${2:-}"
			shift 2
			;;
		-df | --domains-file)
			require_option_value "$1" "${2:-}"
			DOMAINS_FILE="${2:-}"
			shift 2
			;;
		-p | --ports)
			require_option_value "$1" "${2:-}"
			PORTS="${2:-}"
			shift 2
			;;
		-oj | --outjson)
			OUTJSON=true
			shift
			;;
		-od | --outdir)
			require_option_value "$1" "${2:-}"
			OUTDIR="${2:-}"
			shift 2
			;;
		-h | --help)
			usage
			exit 0
			;;
		*)
			echo "[-] Unknown option: $1" >&2
			usage
			exit 1
			;;
		esac
	done
}

parse_args "$@"
validate_input
check_dependencies

WORKDIR="$(mktemp -d)"
cleanup() {
	rm -rf "$WORKDIR"
}
trap cleanup EXIT

DOMAINS="${WORKDIR}/domains.txt"
SUBFINDER_RAW_SUBS="${WORKDIR}/subfinder-subdomains.raw.txt"
SUBS="${WORKDIR}/subdomains.txt"
JSON_TEMP="${WORKDIR}/${JSON_FILENAME}"
NMAP_TMPDIR="${WORKDIR}/nmap"

mkdir -p "$NMAP_TMPDIR"
: >"$SUBFINDER_RAW_SUBS"
: >"$SUBS"

if [[ -n "$DOMAINS_FILE" ]]; then
	sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//; s/\.$//' "$DOMAINS_FILE" |
		tr '[:upper:]' '[:lower:]' |
		grep -E '[^[:space:]]' |
		sort -u >"$DOMAINS" || true
else
	printf '%s\n' "${DOMAIN%.}" |
		tr '[:upper:]' '[:lower:]' >"$DOMAINS"
fi

DOMAIN_COUNT="$(wc -l <"$DOMAINS" | tr -d ' ')"

if [[ "$DOMAIN_COUNT" -eq 0 ]]; then
	echo "[-] No domains found in domains file: $DOMAINS_FILE" >&2
	exit 1
fi

while IFS= read -r ROOT_DOMAIN; do
	printf '%s Enumerating subdomains for %s...\n' "$INFO_PREFIX" "$ROOT_DOMAIN" >&2

	SUBFINDER_DOMAIN_RAW_SUBS="${WORKDIR}/subfinder-${ROOT_DOMAIN}.raw.txt"

	subfinder -d "$ROOT_DOMAIN" -silent -o "$SUBFINDER_DOMAIN_RAW_SUBS" >/dev/null 2>&1 || {
		echo "[-] subfinder failed for $ROOT_DOMAIN." >&2
		exit 1
	}

	cat "$SUBFINDER_DOMAIN_RAW_SUBS" >>"$SUBFINDER_RAW_SUBS"

	DOMAIN_REGEX="${ROOT_DOMAIN//./\\.}"

	sed 's/\.$//' "$SUBFINDER_DOMAIN_RAW_SUBS" |
		tr '[:upper:]' '[:lower:]' |
		grep -E "(^|\.)${DOMAIN_REGEX}$" >>"$SUBS" || true
done <"$DOMAINS"

sort -u -o "$SUBS" "$SUBS"

COUNT="$(wc -l <"$SUBS" | tr -d ' ')"

if [[ "$COUNT" -eq 0 ]]; then
	echo "[-] No targets found." >&2
	exit 1
fi

printf '%s Found %s unique targets.\n' "$INFO_PREFIX" "$COUNT" >&2
printf '%s Testing connectivity...\n' "$INFO_PREFIX" >&2

if [[ "${EUID}" -eq 0 ]]; then
	NMAP_SCAN_TYPE="-sS"
else
	NMAP_SCAN_TYPE="-sT"
fi

RUN_DATETIME="$(date +"%m/%d/%Y %I:%M %p %Z" | sed -E 's#^0##; s#/0#/#; s# 0([0-9]):# \1:#')"

python3 - "$SUBS" "$PORTS" "$NMAP_SCAN_TYPE" "$JSON_TEMP" "$NMAP_TMPDIR" "$RUN_DATETIME" "$DOMAINS" "$NMAP_TIMEOUT_SECONDS" <<'PY'
import json
import socket
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Optional

target_file = Path(sys.argv[1])
ports = sys.argv[2]
nmap_scan_type = sys.argv[3]
json_temp = Path(sys.argv[4])
nmap_tmpdir = Path(sys.argv[5])
run_datetime = sys.argv[6]
domain_file = Path(sys.argv[7])
nmap_timeout_seconds = int(sys.argv[8])

domains = [
    line.strip().lower()
    for line in domain_file.read_text().splitlines()
    if line.strip()
]

targets = [
    line.strip().lower()
    for line in target_file.read_text().splitlines()
    if line.strip()
]

results = []
green_color = "\033[32m"
reset_color = "\033[0m"


def resolve_ip(hostname: str) -> Optional[str]:
    try:
        addresses = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return None

    for address in addresses:
        ipaddress = address[4][0]

        if ipaddress:
            return ipaddress

    return None


def source_ip() -> Optional[str]:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except OSError:
        return None


def scan_host(hostname: str) -> List[int]:
    with tempfile.NamedTemporaryFile(
        prefix="nmap-",
        suffix=".xml",
        dir=nmap_tmpdir,
        delete=True,
    ) as tmp:
        cmd = [
            "nmap",
            nmap_scan_type,
            "-Pn",
            "--open",
            "--host-timeout",
            f"{nmap_timeout_seconds}s",
            "-p",
            ports,
            hostname,
            "-oX",
            tmp.name,
        ]

        try:
            subprocess.run(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=nmap_timeout_seconds + 5,
                text=True,
            )
        except subprocess.TimeoutExpired:
            return []

        try:
            tree = ET.parse(tmp.name)
        except ET.ParseError:
            return []

    root = tree.getroot()
    open_ports = []

    for port in root.findall(".//ports/port"):
        state = port.find("state")

        if state is None:
            continue

        if state.attrib.get("state") != "open":
            continue

        port_id = port.attrib.get("portid")

        if port_id and port_id.isdigit():
            open_ports.append(int(port_id))

    return sorted(set(open_ports))

total = len(targets)

for index, target in enumerate(targets, start=1):
    print(
        f"[{green_color}+{reset_color}] "
        f"[{index}/{total}] Testing {target}",
        file=sys.stderr
    )

    ipaddress = resolve_ip(target)
    is_resolved = ipaddress is not None

    if not is_resolved:
        results.append({
            "target": target,
            "ipaddress": "",
            "resolved": False,
            "connected": False,
            "ports": []
        })
        continue

    open_ports = scan_host(target)

    results.append({
        "target": target,
        "ipaddress": ipaddress,
        "resolved": True,
        "connected": len(open_ports) > 0,
        "ports": open_ports
    })

results = sorted(results, key=lambda item: item["target"])

if len(domains) == 1:
    output = {
        "domain": domains[0],
        "source_ip": source_ip(),
        "run_datetime": run_datetime,
        "results": results,
    }
else:
    output = {
        "domains": domains,
        "source_ip": source_ip(),
        "run_datetime": run_datetime,
        "results": results,
    }

json_text = json.dumps(output, indent=2)
json_temp.write_text(json_text + "\n")
PY

jq -C . "$JSON_TEMP"

if [[ "$OUTJSON" == true ]]; then
	if [[ -n "$OUTDIR" ]]; then
		mkdir -p "$OUTDIR"
		JSON_OUT="${OUTDIR%/}/${JSON_FILENAME}"
	else
		JSON_OUT="./${JSON_FILENAME}"
	fi

	cp "$JSON_TEMP" "$JSON_OUT"
	printf '%s JSON saved to: %s\n' "$INFO_PREFIX" "$JSON_OUT" >&2
fi

printf '%s Done.\n' "$INFO_PREFIX" >&2
