#!/usr/bin/env bash
set -euo pipefail

DOMAIN=""
PORTS="20,21,22,23,25,53,80,88,135,389,443,445,3389,5985,5986,8080,8081,8433"
OUTJSON=false
OUTDIR=""
JSON_FILENAME="connectivity-results.json"

REQUIRED_COMMANDS=(
	subfinder
	amass
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
  $0 --domain example.com [options]
  $0 -d example.com [options]

Options:
  -d,  --domain           DNS zone / root domain to enumerate
  -p,  --ports            Comma-separated ports to test
                          Default: ${PORTS}
  -oj, --outjson          Save JSON output to a file
  -od, --outdir           Output directory for JSON file
                          Only used when --outjson is present
                          Default with --outjson: current directory
  -h,  --help             Help

Examples:
  $0 --domain example.com
  $0 -d example.com
  $0 --domain example.com --ports 22,80,443
  $0 -d example.com -p 22,80,443
  $0 --domain example.com --outjson
  $0 -d example.com -oj
  $0 --domain example.com --outjson --outdir ./results
  $0 -d example.com -oj -od ./results
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

validate_domain() {
	if [[ -z "$DOMAIN" ]]; then
		echo "[-] Missing required domain." >&2
		usage
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
check_dependencies
validate_domain

WORKDIR="$(mktemp -d)"
cleanup() {
	rm -rf "$WORKDIR"
}
trap cleanup EXIT

SUBFINDER_RAW_SUBS="${WORKDIR}/subfinder-subdomains.raw.txt"
AMASS_RAW_SUBS="${WORKDIR}/amass-subdomains.raw.txt"
RAW_SUBS="${WORKDIR}/subdomains-combined.raw.txt"
SUBS="${WORKDIR}/subdomains.txt"
JSON_TEMP="${WORKDIR}/${JSON_FILENAME}"
NMAP_TMPDIR="${WORKDIR}/nmap"

mkdir -p "$NMAP_TMPDIR"

echo "[+] Enumerating subdomains for ${DOMAIN}..." >&2

subfinder -d "$DOMAIN" -silent -o "$SUBFINDER_RAW_SUBS" >/dev/null 2>&1 || {
	echo "[-] subfinder failed." >&2
	exit 1
}

amass enum -passive -d "$DOMAIN" -o "$AMASS_RAW_SUBS" >/dev/null 2>&1 || {
	echo "[!] amass failed; continuing with subfinder results." >&2
	: >"$AMASS_RAW_SUBS"
}

cat "$SUBFINDER_RAW_SUBS" "$AMASS_RAW_SUBS" >"$RAW_SUBS"

DOMAIN_REGEX="${DOMAIN//./\\.}"

sed 's/\.$//' "$RAW_SUBS" |
	tr '[:upper:]' '[:lower:]' |
	grep -E "(^|\.)${DOMAIN_REGEX}$" |
	sort -u >"$SUBS" || true

COUNT="$(wc -l <"$SUBS" | tr -d ' ')"

if [[ "$COUNT" -eq 0 ]]; then
	echo "[-] No targets found." >&2
	exit 1
fi

echo "[+] Found ${COUNT} unique targets." >&2
echo "[+] Testing connectivity..." >&2

if [[ "${EUID}" -eq 0 ]]; then
	NMAP_SCAN_TYPE="-sS"
else
	NMAP_SCAN_TYPE="-sT"
fi

RUN_DATETIME="$(date +"%m/%d/%Y %I:%M %p %Z" | sed -E 's#^0##; s#/0#/#; s# 0([0-9]):# \1:#')"

python3 - "$SUBS" "$PORTS" "$NMAP_SCAN_TYPE" "$JSON_TEMP" "$NMAP_TMPDIR" "$RUN_DATETIME" "$DOMAIN" <<'PY'
import json
import socket
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional

target_file = Path(sys.argv[1])
ports = sys.argv[2]
nmap_scan_type = sys.argv[3]
json_temp = Path(sys.argv[4])
nmap_tmpdir = Path(sys.argv[5])
run_datetime = sys.argv[6]
domain = sys.argv[7]

targets = [
    line.strip().lower()
    for line in target_file.read_text().splitlines()
    if line.strip()
]

results = []
progress_color = "\033[36m"
reset_color = "\033[0m"

def resolves(hostname: str) -> bool:
    try:
        socket.getaddrinfo(hostname, None)
        return True
    except socket.gaierror:
        return False

def source_ip() -> Optional[str]:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except OSError:
        return None

def scan_host(hostname: str) -> list[int]:
    with tempfile.NamedTemporaryFile(
        prefix="nmap-",
        suffix=".xml",
        dir=nmap_tmpdir,
        delete=True
    ) as tmp:
        cmd = [
            "nmap",
            nmap_scan_type,
            "-Pn",
            "--open",
            "-p",
            ports,
            hostname,
            "-oX",
            tmp.name,
        ]

        subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            text=True,
        )

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
        f"{progress_color}[+] [{index}/{total}] Testing {target}{reset_color}",
        file=sys.stderr
    )

    is_resolved = resolves(target)

    if not is_resolved:
        results.append({
            "target": target,
            "resolved": False,
            "connected": False,
            "ports": []
        })
        continue

    open_ports = scan_host(target)

    results.append({
        "target": target,
        "resolved": True,
        "connected": len(open_ports) > 0,
        "ports": open_ports
    })

results = sorted(results, key=lambda item: item["target"])

output = {
    "domain": domain,
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
	echo "[+] JSON saved to: ${JSON_OUT}" >&2
fi

echo "[+] Done." >&2
