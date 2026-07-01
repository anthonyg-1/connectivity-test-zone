#!/usr/bin/env bash
set -euo pipefail

DOMAIN=""
DOMAINS_FILE=""
WORDLIST=""
RESOLVERS=""
VHOSTS=false
VHOST_WORDLIST=""
VHOST_SCHEME="https"
VHOST_URL=""
PORTS="20,21,22,23,25,53,80,88,111,135,139,389,443,445,464,593,636,1433,1521,2049,2379,2380,3268,3269,3306,3389,5432,5672,5900,5985,5986,6379,6443,8000,8080,8081,8433,8443,9000,9200,9389,10250,27017"
OUTJSON=false
OUTDIR=""
JSON_FILENAME="connectivity-results.json"
NMAP_TIMEOUT_SECONDS=60
SCRIPT_NAME="./connectivity-test-zone.sh"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

GREEN=$'\033[32m'
RED=$'\033[31m'
RESET=$'\033[0m'
INFO_PREFIX="[${GREEN}+${RESET}]"
WARN_PREFIX="[${RED}!${RESET}]"

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
  -wl, --wordlist         Optional DNS brute-force wordlist.
                          Runs active dnsx enumeration in addition to subfinder.
  -r,  --resolvers        Optional resolver list for dnsx.
                          Comma-separated resolvers or a resolvers file.
  -vh, --vhosts           Run vhost enumeration.
                          Defaults to ${SCRIPT_DIR}/vhost-wordlist.txt.
  -vwl,--vhost-wordlist   Optional vhost wordlist.
                          Implies --vhosts.
  -vs, --vhost-scheme     URL scheme for vhost checks.
                          Default: ${VHOST_SCHEME}
  -vu, --vhost-url        Optional base URL for vhost checks.
                          Useful when the root domain does not resolve.
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
  ${SCRIPT_NAME} --domain example.com --wordlist ad-dns.txt
  ${SCRIPT_NAME} -d example.com -wl ad-dns.txt
  ${SCRIPT_NAME} -df domains.txt -wl ad-dns.txt -r 10.0.0.10,10.0.0.11
  ${SCRIPT_NAME} --domain example.com --vhosts
  ${SCRIPT_NAME} -d example.com -vh -vwl vhost-wordlist.txt
  ${SCRIPT_NAME} -d example.com -vh -vu https://192.0.2.10
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
	local required_commands=("${REQUIRED_COMMANDS[@]}")

	if [[ -n "$WORDLIST" ]]; then
		required_commands+=(dnsx)
	fi

	if [[ "$VHOSTS" == true ]]; then
		required_commands+=(gobuster)
	fi

	for cmd in "${required_commands[@]}"; do
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

	if [[ -n "$WORDLIST" && ! -f "$WORDLIST" ]]; then
		echo "[-] Wordlist does not exist: $WORDLIST" >&2
		exit 1
	fi

	if [[ -n "$WORDLIST" && ! -r "$WORDLIST" ]]; then
		echo "[-] Wordlist is not readable: $WORDLIST" >&2
		exit 1
	fi

	if [[ -n "$RESOLVERS" && -z "$WORDLIST" ]]; then
		echo "[-] --resolvers can only be used with --wordlist." >&2
		exit 1
	fi

	if [[ "$VHOSTS" == true && -z "$VHOST_WORDLIST" ]]; then
		VHOST_WORDLIST="${SCRIPT_DIR}/vhost-wordlist.txt"
	fi

	if [[ "$VHOSTS" == true && ! -f "$VHOST_WORDLIST" ]]; then
		echo "[-] Vhost wordlist does not exist: $VHOST_WORDLIST" >&2
		exit 1
	fi

	if [[ "$VHOSTS" == true && ! -r "$VHOST_WORDLIST" ]]; then
		echo "[-] Vhost wordlist is not readable: $VHOST_WORDLIST" >&2
		exit 1
	fi

	if [[ "$VHOST_SCHEME" != "http" && "$VHOST_SCHEME" != "https" ]]; then
		echo "[-] --vhost-scheme must be either http or https." >&2
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
		-wl | --wordlist)
			require_option_value "$1" "${2:-}"
			WORDLIST="${2:-}"
			shift 2
			;;
		-r | --resolvers)
			require_option_value "$1" "${2:-}"
			RESOLVERS="${2:-}"
			shift 2
			;;
		-vh | --vhosts)
			VHOSTS=true
			shift
			;;
		-vwl | --vhost-wordlist)
			require_option_value "$1" "${2:-}"
			VHOSTS=true
			VHOST_WORDLIST="${2:-}"
			shift 2
			;;
		-vs | --vhost-scheme)
			require_option_value "$1" "${2:-}"
			VHOST_SCHEME="${2:-}"
			shift 2
			;;
		-vu | --vhost-url)
			require_option_value "$1" "${2:-}"
			VHOSTS=true
			VHOST_URL="${2:-}"
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

target_count() {
	local target_file="$1"

	wc -l <"$target_file" | tr -d ' '
}

filter_domain_hosts() {
	local raw_file="$1"
	local root_domain="$2"
	local filtered_file="$3"
	local domain_regex

	domain_regex="${root_domain//./\\.}"

	sed 's/\.$//' "$raw_file" |
		tr '[:upper:]' '[:lower:]' |
		grep -E "(^|\.)${domain_regex}$" >"$filtered_file" || true
}

run_subfinder_enum() {
	local root_domain="$1"
	local domain_subs="$2"
	local raw_file="${WORKDIR}/subfinder-${root_domain}.raw.txt"
	local filtered_file="${WORKDIR}/subfinder-${root_domain}.filtered.txt"
	local found_count

	printf '%s Running passive enumeration for %s...\n' "$INFO_PREFIX" "$root_domain" >&2
	: >"$filtered_file"

	subfinder -d "$root_domain" -silent -o "$raw_file" </dev/null >/dev/null 2>&1 || {
		echo "[-] subfinder failed for $root_domain." >&2
		exit 1
	}

	cat "$raw_file" >>"$SUBFINDER_RAW_SUBS"
	filter_domain_hosts "$raw_file" "$root_domain" "$filtered_file"

	found_count="$(target_count "$filtered_file")"
	printf '%s Passive enumeration found %s target(s) for %s.\n' "$INFO_PREFIX" "$found_count" "$root_domain" >&2
	cat "$filtered_file" >>"$domain_subs"
}

run_dnsx_enum() {
	local root_domain="$1"
	local domain_subs="$2"
	local candidates_file="${WORKDIR}/dnsx-${root_domain}.candidates.txt"
	local raw_file="${WORKDIR}/dnsx-${root_domain}.raw.txt"
	local filtered_file="${WORKDIR}/dnsx-${root_domain}.filtered.txt"
	local found_count
	local dnsx_args

	if [[ -z "$WORDLIST" ]]; then
		return 0
	fi

	printf '%s Running active DNS enumeration for %s...\n' "$INFO_PREFIX" "$root_domain" >&2
	: >"$filtered_file"

	python3 - "$WORDLIST" "$root_domain" "$candidates_file" <<'PY'
import sys
from pathlib import Path

wordlist = Path(sys.argv[1])
root_domain = sys.argv[2].strip().lower().rstrip(".")
candidate_file = Path(sys.argv[3])
suffix = f".{root_domain}"
candidates = set()

for line in wordlist.read_text().splitlines():
    word = line.strip().lower().rstrip(".")

    if not word or word.startswith("#"):
        continue

    if word == root_domain or word.endswith(suffix):
        candidate = word
    else:
        candidate = f"{word}.{root_domain}"

    candidates.add(candidate)

candidate_file.write_text("\n".join(sorted(candidates)) + "\n")
PY

	dnsx_args=(-l "$candidates_file" -silent -o "$raw_file")

	if [[ -n "$RESOLVERS" ]]; then
		dnsx_args+=(-r "$RESOLVERS")
	fi

	dnsx "${dnsx_args[@]}" </dev/null >/dev/null 2>&1 || {
		echo "[-] dnsx failed for $root_domain." >&2
		exit 1
	}

	filter_domain_hosts "$raw_file" "$root_domain" "$filtered_file"

	found_count="$(target_count "$filtered_file")"
	printf '%s Active DNS enumeration found %s target(s) for %s.\n' "$INFO_PREFIX" "$found_count" "$root_domain" >&2
	cat "$filtered_file" >>"$domain_subs"
}

run_gobuster_vhost_enum() {
	local root_domain="$1"
	local domain_subs="$2"
	local raw_file="${WORKDIR}/gobuster-${root_domain}.raw.txt"
	local filtered_file="${WORKDIR}/gobuster-${root_domain}.filtered.txt"
	local error_file="${WORKDIR}/gobuster-${root_domain}.err.txt"
	local gobuster_url
	local gobuster_error
	local found_count

	if [[ "$VHOSTS" != true ]]; then
		return 0
	fi

	printf '%s Running vhost enumeration for %s...\n' "$INFO_PREFIX" "$root_domain" >&2
	: >"$filtered_file"

	gobuster_url="${VHOST_URL:-${VHOST_SCHEME}://${root_domain}}"

	if ! gobuster vhost \
		--url "$gobuster_url" \
		--wordlist "$VHOST_WORDLIST" \
		--append-domain \
		--domain "$root_domain" \
		--quiet \
		--no-progress \
		--no-error \
		--no-color \
		--output "$raw_file" </dev/null >/dev/null 2>"$error_file"; then
		if grep -q -e 'no such host' -e 'timeout occurred during the request' "$error_file"; then
			return 0
		fi

		gobuster_error="$(sed -n '1p' "$error_file")"
		printf '%s Vhost enumeration failed for %s; continuing. %s\n' "$WARN_PREFIX" "$root_domain" "$gobuster_error" >&2
		return 0
	fi

	python3 - "$raw_file" "$root_domain" "$filtered_file" <<'PY'
import re
import sys
from pathlib import Path

raw_file = Path(sys.argv[1])
root_domain = sys.argv[2].strip().lower().rstrip(".")
output_file = Path(sys.argv[3])
suffix = f".{re.escape(root_domain)}"
host_pattern = re.compile(
    rf"\b[a-z0-9](?:[a-z0-9-]{{0,61}}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{{0,61}}[a-z0-9])?)*{suffix}\b",
    re.IGNORECASE,
)
hosts = set()

for line in raw_file.read_text(errors="ignore").splitlines():
    for match in host_pattern.finditer(line.lower().rstrip(".")):
        host = match.group(0).rstrip(".")

        if host == root_domain or host.endswith(f".{root_domain}"):
            hosts.add(host)

output_file.write_text("\n".join(sorted(hosts)) + ("\n" if hosts else ""))
PY

	found_count="$(target_count "$filtered_file")"
	printf '%s Vhost enumeration found %s target(s) for %s.\n' "$INFO_PREFIX" "$found_count" "$root_domain" >&2
	cat "$filtered_file" >>"$domain_subs"
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

printf '%s Loaded %s DNS zone(s).\n' "$INFO_PREFIX" "$DOMAIN_COUNT" >&2

while IFS= read -r ROOT_DOMAIN; do
	DOMAIN_SUBS="${WORKDIR}/subdomains-${ROOT_DOMAIN}.txt"
	: >"$DOMAIN_SUBS"
	run_subfinder_enum "$ROOT_DOMAIN" "$DOMAIN_SUBS"
	run_dnsx_enum "$ROOT_DOMAIN" "$DOMAIN_SUBS"
	run_gobuster_vhost_enum "$ROOT_DOMAIN" "$DOMAIN_SUBS"

	sort -u -o "$DOMAIN_SUBS" "$DOMAIN_SUBS"
	DOMAIN_TARGET_COUNT="$(target_count "$DOMAIN_SUBS")"

	if [[ "$DOMAIN_TARGET_COUNT" -eq 0 ]]; then
		printf '%s No targets found for %s; continuing.\n' "$INFO_PREFIX" "$ROOT_DOMAIN" >&2
		continue
	fi

	printf '%s Found %s unique targets for %s.\n' "$INFO_PREFIX" "$DOMAIN_TARGET_COUNT" "$ROOT_DOMAIN" >&2
	cat "$DOMAIN_SUBS" >>"$SUBS"
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
import hashlib
import socket
import ssl
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

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


def format_certificate_name(name_parts: tuple) -> str:
    attributes = []

    for relative_distinguished_name in name_parts:
        for key, value in relative_distinguished_name:
            attributes.append(f"{key}={value}")

    return ", ".join(attributes)


def certificate_expiration_details(not_after: str) -> Dict[str, object]:
    if not not_after:
        return {"expiration": "", "expired": False}

    try:
        expires_at = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
    except ValueError:
        return {"expiration": not_after, "expired": False}

    expires_at = expires_at.replace(tzinfo=timezone.utc)

    return {
        "expiration": expires_at.strftime("%B %-d, %Y at %-I:%M:%S %p UTC"),
        "expired": expires_at < datetime.now(timezone.utc),
    }


def decode_certificate(der_cert: bytes) -> Dict:
    pem_cert = ssl.DER_cert_to_PEM_cert(der_cert)

    with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=True) as tmp:
        tmp.write(pem_cert)
        tmp.flush()
        return ssl._ssl._test_decode_cert(tmp.name)


def read_tls_certificate(hostname: str, port: int) -> Optional[Dict[str, str]]:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((hostname, port), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                der_cert = tls_sock.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError, TimeoutError):
        return None

    if not der_cert:
        return None

    try:
        decoded_cert = decode_certificate(der_cert)
    except ssl.SSLError:
        decoded_cert = {}

    expiration_details = certificate_expiration_details(decoded_cert.get("notAfter", ""))

    return {
        "issuer": format_certificate_name(decoded_cert.get("issuer", ())),
        "subject": format_certificate_name(decoded_cert.get("subject", ())),
        "thumbprint": hashlib.sha256(der_cert).hexdigest().upper(),
        "expiration": expiration_details["expiration"],
        "expired": expiration_details["expired"],
    }


def scan_tls_certificates(hostname: str, open_ports: List[int]) -> List[Dict[str, str]]:
    certificates = []
    seen_thumbprints = set()

    for port in open_ports:
        certificate = read_tls_certificate(hostname, port)

        if certificate is None:
            continue

        thumbprint = certificate["thumbprint"]

        if thumbprint in seen_thumbprints:
            continue

        seen_thumbprints.add(thumbprint)
        certificates.append(certificate)

    return certificates


total = len(targets)

for index, target in enumerate(targets, start=1):
    print(
        f"[{green_color}+{reset_color}] [{index}/{total}] Testing {target}",
        file=sys.stderr,
    )

    ipaddress = resolve_ip(target)
    is_resolved = ipaddress is not None

    if not is_resolved:
        results.append(
            {
                "target": target,
                "ipaddress": "",
                "resolved": False,
                "connected": False,
                "ports": [],
                "tls_certificates": [],
            }
        )
        continue

    open_ports = scan_host(target)
    tls_certificates = scan_tls_certificates(target, open_ports)

    results.append(
        {
            "target": target,
            "ipaddress": ipaddress,
            "resolved": True,
            "connected": len(open_ports) > 0,
            "ports": open_ports,
            "tls_certificates": tls_certificates,
        }
    )

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
