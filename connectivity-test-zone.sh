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
WAF=false
IPINFO=false
WHOIS=false
SERVICE_VERSION=false
NSE=false
NSE_SCRIPTS="default,safe"
HTTP_EVIDENCE=false
HTTP_TIMEOUT=10
NUCLEI=false
NUCLEI_SEVERITIES="info,low,medium,high,critical"
NUCLEI_TEMPLATES=""
ZAP=false
ZAP_IMAGE="ghcr.io/zaproxy/zaproxy:stable"
ZAP_SPIDER_MINUTES=1
ZAP_TIMEOUT_MINUTES=5
ZAP_MAX_ENDPOINTS=10
RATE_DELAY=0
PORTS="20,21,22,23,25,53,80,88,111,135,139,389,443,445,464,593,636,1433,1521,2049,2379,2380,3268,3269,3306,3389,5432,5672,5900,5985,5986,6379,6443,8000,8080,8081,8433,8443,9000,9200,9389,10250,27017"
OUTJSON=false
OUTDIR=""
JSON_FILENAME="connectivity-results.json"
NMAP_TIMEOUT_SECONDS=60
WAFW00F_TIMEOUT_SECONDS=30
SCRIPT_NAME="./connectivity-test-zone.sh"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

GREEN=$'\033[32m'
RED=$'\033[31m'
YELLOW=$'\033[33m'
RESET=$'\033[0m'
INFO_PREFIX="[${GREEN}+${RESET}]"
WARN_PREFIX="[${RED}!${RESET}]"
YELLOW_WARN_PREFIX="[${YELLOW}!${RESET}]"

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
  -wf, --waf              Run WAF detection with wafw00f for open HTTP/HTTPS
                          endpoints.
  -ii, --ipinfo           Add ipinfo.io Lite geolocation and ASN data for each
                          resolved target IP.
                          Requires IPINFO_API_KEY in the environment.
  -wi, --whois            Add registration data for each supplied DNS zone.
                          Uses RDAP first, then local whois as a fallback.
  -sv, --service-version  Run nmap service/version detection with
                          -sV --version-light.
  --nse                   Run nmap NSE scripts. Defaults to default,safe.
  --nse-scripts           NSE script set to use with --nse.
                          Default: ${NSE_SCRIPTS}
  -he, --http-evidence    Collect basic HTTP response evidence and advisory
                          security header assessments.
  --http-timeout          HTTP request timeout in seconds.
                          Default: ${HTTP_TIMEOUT}
  -nu, --nuclei           Run nuclei against discovered HTTP/HTTPS endpoints.
  --nuclei-severities     Nuclei severities to include.
                          Default: ${NUCLEI_SEVERITIES}
  --nuclei-templates      Optional nuclei template path.
  -zap, --zap             Run OWASP ZAP baseline scan through Docker against
                          discovered HTTP/HTTPS endpoints.
  --zap-image             Docker image for ZAP baseline scans.
                          Default: ${ZAP_IMAGE}
  --zap-spider-minutes    Minutes for ZAP baseline spidering per endpoint.
                          Default: ${ZAP_SPIDER_MINUTES}
  --zap-timeout-minutes   Max minutes to wait for each ZAP baseline scan.
                          Default: ${ZAP_TIMEOUT_MINUTES}
  --zap-max-endpoints     Maximum HTTP/HTTPS endpoints to scan with ZAP.
                          Default: ${ZAP_MAX_ENDPOINTS}
  --rate-delay            Delay in seconds between optional evidence requests.
                          Default: ${RATE_DELAY}
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
  ${SCRIPT_NAME} -d example.com --waf
  ${SCRIPT_NAME} -d example.com -wf
  ${SCRIPT_NAME} -d example.com --ipinfo
  ${SCRIPT_NAME} -d example.com -ii
  ${SCRIPT_NAME} --domain example.com --whois
  ${SCRIPT_NAME} -d example.com -wi
  ${SCRIPT_NAME} -d example.com -oj -sv -he
  ${SCRIPT_NAME} -d example.com -oj -sv --nse --nse-scripts "default,safe"
  ${SCRIPT_NAME} -d example.com -oj -sv -he -nu
  ${SCRIPT_NAME} -d example.com -oj -sv -he -nu -zap
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

	if [[ "$WAF" == true ]]; then
		required_commands+=(wafw00f)
	fi

	if [[ "$WHOIS" == true ]]; then
		required_commands+=(whois)
	fi

	if [[ "$NUCLEI" == true ]]; then
		required_commands+=(nuclei)
	fi

	if [[ "$ZAP" == true ]]; then
		required_commands+=(docker)
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

	if ! [[ "$HTTP_TIMEOUT" =~ ^[0-9]+$ ]] || [[ "$HTTP_TIMEOUT" -lt 1 ]]; then
		echo "[-] --http-timeout must be a positive integer." >&2
		exit 1
	fi

	if ! [[ "$RATE_DELAY" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
		echo "[-] --rate-delay must be a non-negative number." >&2
		exit 1
	fi

	if [[ "$NSE" == true && -z "$NSE_SCRIPTS" ]]; then
		echo "[-] --nse-scripts cannot be empty when --nse is used." >&2
		exit 1
	fi

	if [[ "$NUCLEI" == true && -z "$NUCLEI_SEVERITIES" ]]; then
		echo "[-] --nuclei-severities cannot be empty when --nuclei is used." >&2
		exit 1
	fi

	if ! [[ "$ZAP_SPIDER_MINUTES" =~ ^[0-9]+$ ]] || [[ "$ZAP_SPIDER_MINUTES" -lt 1 ]]; then
		echo "[-] --zap-spider-minutes must be a positive integer." >&2
		exit 1
	fi

	if ! [[ "$ZAP_TIMEOUT_MINUTES" =~ ^[0-9]+$ ]] || [[ "$ZAP_TIMEOUT_MINUTES" -lt 1 ]]; then
		echo "[-] --zap-timeout-minutes must be a positive integer." >&2
		exit 1
	fi

	if ! [[ "$ZAP_MAX_ENDPOINTS" =~ ^[0-9]+$ ]] || [[ "$ZAP_MAX_ENDPOINTS" -lt 1 ]]; then
		echo "[-] --zap-max-endpoints must be a positive integer." >&2
		exit 1
	fi

	if [[ "$ZAP" == true && -z "$ZAP_IMAGE" ]]; then
		echo "[-] --zap-image cannot be empty when --zap is used." >&2
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
		-wf | --waf)
			WAF=true
			shift
			;;
		-ii | --ipinfo)
			IPINFO=true
			shift
			;;
		-wi | --whois)
			WHOIS=true
			shift
			;;
		-sv | --service-version)
			SERVICE_VERSION=true
			shift
			;;
		--nse)
			NSE=true
			shift
			;;
		--nse-scripts)
			require_option_value "$1" "${2:-}"
			NSE=true
			NSE_SCRIPTS="${2:-}"
			shift 2
			;;
		-he | --http-evidence)
			HTTP_EVIDENCE=true
			shift
			;;
		--http-timeout)
			require_option_value "$1" "${2:-}"
			HTTP_TIMEOUT="${2:-}"
			shift 2
			;;
		-nu | --nuclei)
			NUCLEI=true
			shift
			;;
		--nuclei-severities)
			require_option_value "$1" "${2:-}"
			NUCLEI=true
			NUCLEI_SEVERITIES="${2:-}"
			shift 2
			;;
		--nuclei-templates)
			require_option_value "$1" "${2:-}"
			NUCLEI=true
			NUCLEI_TEMPLATES="${2:-}"
			shift 2
			;;
		-zap | --zap)
			ZAP=true
			shift
			;;
		--zap-image)
			require_option_value "$1" "${2:-}"
			ZAP=true
			ZAP_IMAGE="${2:-}"
			shift 2
			;;
		--zap-spider-minutes)
			require_option_value "$1" "${2:-}"
			ZAP=true
			ZAP_SPIDER_MINUTES="${2:-}"
			shift 2
			;;
		--zap-timeout-minutes)
			require_option_value "$1" "${2:-}"
			ZAP=true
			ZAP_TIMEOUT_MINUTES="${2:-}"
			shift 2
			;;
		--zap-max-endpoints)
			require_option_value "$1" "${2:-}"
			ZAP=true
			ZAP_MAX_ENDPOINTS="${2:-}"
			shift 2
			;;
		--rate-delay)
			require_option_value "$1" "${2:-}"
			RATE_DELAY="${2:-}"
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

if [[ "$IPINFO" == true && -z "${IPINFO_API_KEY:-}" ]]; then
	printf '%s --ipinfo requested but IPINFO_API_KEY is not set; ipinfo JSON will be omitted.\n' "$YELLOW_WARN_PREFIX" >&2
	IPINFO=false
fi

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
	printf '%s\n' "$ROOT_DOMAIN" >"$DOMAIN_SUBS"
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

python3 - "$SUBS" "$PORTS" "$NMAP_SCAN_TYPE" "$JSON_TEMP" "$NMAP_TMPDIR" "$RUN_DATETIME" "$DOMAINS" "$NMAP_TIMEOUT_SECONDS" "$WAF" "$WAFW00F_TIMEOUT_SECONDS" "$IPINFO" "$WHOIS" "$SERVICE_VERSION" "$NSE" "$NSE_SCRIPTS" "$HTTP_EVIDENCE" "$HTTP_TIMEOUT" "$NUCLEI" "$NUCLEI_SEVERITIES" "$NUCLEI_TEMPLATES" "$ZAP" "$ZAP_IMAGE" "$ZAP_SPIDER_MINUTES" "$ZAP_TIMEOUT_MINUTES" "$ZAP_MAX_ENDPOINTS" "$RATE_DELAY" <<'PY'
import json
import hashlib
import html
import os
import re
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

target_file = Path(sys.argv[1])
ports = sys.argv[2]
nmap_scan_type = sys.argv[3]
json_temp = Path(sys.argv[4])
nmap_tmpdir = Path(sys.argv[5])
run_datetime = sys.argv[6]
domain_file = Path(sys.argv[7])
nmap_timeout_seconds = int(sys.argv[8])
waf_enabled = sys.argv[9] == "true"
wafw00f_timeout_seconds = int(sys.argv[10])
ipinfo_enabled = sys.argv[11] == "true"
whois_enabled = sys.argv[12] == "true"
service_version_enabled = sys.argv[13] == "true"
nse_enabled = sys.argv[14] == "true"
nse_scripts = sys.argv[15]
http_evidence_enabled = sys.argv[16] == "true"
http_timeout_seconds = int(sys.argv[17])
nuclei_enabled = sys.argv[18] == "true"
nuclei_severities = sys.argv[19]
nuclei_templates = sys.argv[20].strip()
zap_enabled = sys.argv[21] == "true"
zap_image = sys.argv[22].strip()
zap_spider_minutes = int(sys.argv[23])
zap_timeout_minutes = int(sys.argv[24])
zap_max_endpoints = int(sys.argv[25])
rate_delay_seconds = float(sys.argv[26])
effective_nmap_timeout_seconds = nmap_timeout_seconds

if nse_enabled:
    effective_nmap_timeout_seconds = max(nmap_timeout_seconds, 180)
elif service_version_enabled:
    effective_nmap_timeout_seconds = max(nmap_timeout_seconds, 90)

ipinfo_api_key = os.environ.get("IPINFO_API_KEY", "").strip()
ipinfo_cache: Dict[str, Optional[Dict[str, object]]] = {}
rdap_bootstrap_cache: Optional[Dict[str, object]] = None
rdap_cache: Dict[str, Dict[str, Optional[str]]] = {}
prioritization_hints: List[Dict[str, object]] = []

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
http_ports_by_scheme = {
    80: "http",
    8000: "http",
    8008: "http",
    8080: "http",
    8081: "http",
    8888: "http",
    9000: "http",
    9080: "http",
    443: "https",
    8433: "https",
    8443: "https",
    9443: "https",
    10443: "https",
}
HTTP_BODY_LIMIT_BYTES = 512 * 1024
SERVICE_EXPOSURE_HINTS = {
    22: ("ssh", "External SSH service is reachable.", "medium"),
    445: ("smb", "External SMB service is reachable.", "high"),
    3389: ("rdp", "External RDP service is reachable.", "high"),
    5985: ("winrm", "External WinRM service is reachable.", "high"),
    5986: ("winrm", "External WinRM over TLS service is reachable.", "high"),
    1433: ("database", "External Microsoft SQL Server service is reachable.", "high"),
    1521: ("database", "External Oracle database service is reachable.", "high"),
    2379: ("etcd", "External etcd service is reachable.", "high"),
    2380: ("etcd", "External etcd peer service is reachable.", "high"),
    3306: ("database", "External MySQL service is reachable.", "high"),
    5432: ("database", "External PostgreSQL service is reachable.", "high"),
    5672: ("messaging", "External AMQP/RabbitMQ service is reachable.", "medium"),
    6379: ("redis", "External Redis service is reachable.", "high"),
    6443: ("kubernetes", "External Kubernetes API service is reachable.", "high"),
    9200: ("search", "External Elasticsearch service is reachable.", "high"),
    10250: ("kubernetes", "External kubelet service is reachable.", "high"),
    27017: ("database", "External MongoDB service is reachable.", "high"),
}
HEADER_LOOKUP = {
    "strict_transport_security": "Strict-Transport-Security",
    "content_security_policy": "Content-Security-Policy",
    "x_frame_options": "X-Frame-Options",
    "x_content_type_options": "X-Content-Type-Options",
    "referrer_policy": "Referrer-Policy",
    "permissions_policy": "Permissions-Policy",
    "cross_origin_opener_policy": "Cross-Origin-Opener-Policy",
    "cross_origin_embedder_policy": "Cross-Origin-Embedder-Policy",
    "cross_origin_resource_policy": "Cross-Origin-Resource-Policy",
    "access_control_allow_origin": "Access-Control-Allow-Origin",
    "access_control_allow_credentials": "Access-Control-Allow-Credentials",
    "cache_control": "Cache-Control",
    "server": "Server",
    "x_powered_by": "X-Powered-By",
}
SECURITY_HEADER_SCORE_KEYS = [
    "strict_transport_security",
    "content_security_policy",
    "x_frame_options",
    "x_content_type_options",
    "referrer_policy",
    "permissions_policy",
    "cross_origin_opener_policy",
    "cross_origin_embedder_policy",
    "cross_origin_resource_policy",
    "cache_control",
    "server",
    "x_powered_by",
]


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


def rate_delay() -> None:
    if rate_delay_seconds > 0:
        time.sleep(rate_delay_seconds)


def append_hint(
    *,
    target: str,
    port: Optional[int],
    severity_hint: str,
    category: str,
    reason: str,
    validation: str,
    evidence: Optional[Dict[str, object]] = None,
) -> None:
    hint: Dict[str, object] = {
        "target": target,
        "severity_hint": severity_hint,
        "category": category,
        "reason": reason,
        "validation": validation,
    }

    if port is not None:
        hint["port"] = port

    if evidence:
        hint["evidence"] = evidence

    prioritization_hints.append(hint)


def lookup_ipinfo(ipaddress: str) -> Optional[Dict[str, object]]:
    if not ipinfo_enabled or not ipinfo_api_key:
        return None

    if ipaddress in ipinfo_cache:
        return ipinfo_cache[ipaddress]

    request = urllib.request.Request(
        f"https://api.ipinfo.io/lite/{ipaddress}",
        headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {ipinfo_api_key}",
            "User-Agent": "connectivity-test-zone",
        },
    )

    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (json.JSONDecodeError, OSError, TimeoutError, urllib.error.URLError):
        ipinfo_cache[ipaddress] = None
        return None

    if not isinstance(payload, dict):
        ipinfo_cache[ipaddress] = None
        return None

    ipinfo_cache[ipaddress] = payload
    return payload


def empty_registration() -> Dict[str, Optional[str]]:
    return {
        "registrar_whois_server": None,
        "registrar_url": None,
        "updated_date": None,
        "creation_date": None,
        "expiration_date": None,
        "registrar": None,
        "registrant_name": None,
        "registrant_organization": None,
        "registrant_street": None,
        "registrant_city": None,
        "registrant_state_province": None,
        "registrant_postal_code": None,
        "registrant_country": None,
        "registrant_phone": None,
    }


def merge_registration(
    registration: Dict[str, Optional[str]],
    fallback: Dict[str, Optional[str]],
    *,
    overwrite: bool = False,
) -> Dict[str, Optional[str]]:
    for key, value in fallback.items():
        if not overwrite and registration.get(key):
            continue

        if not value:
            continue

        registration[key] = value

    return registration


def first_whois_value(
    fields: Dict[str, List[str]],
    names: List[str],
) -> Optional[str]:
    for name in names:
        values = fields.get(name.lower(), [])

        for value in values:
            if value:
                return value

    return None


def parse_whois_registration(raw_output: str) -> Dict[str, Optional[str]]:
    fields: Dict[str, List[str]] = {}

    for line in raw_output.splitlines():
        if ":" not in line:
            continue

        key, value = line.split(":", 1)
        normalized_key = " ".join(key.strip().lower().split())
        normalized_value = value.strip()

        if not normalized_key or not normalized_value:
            continue

        fields.setdefault(normalized_key, []).append(normalized_value)

    registration = empty_registration()
    registration["registrar_whois_server"] = first_whois_value(
        fields,
        ["registrar whois server", "whois server"],
    )
    registration["registrar_url"] = first_whois_value(
        fields,
        ["registrar url", "url of the icann whois inaccuracy complaint form"],
    )
    registration["updated_date"] = first_whois_value(
        fields,
        ["updated date", "last updated on"],
    )
    registration["creation_date"] = first_whois_value(
        fields,
        ["creation date", "created on", "created"],
    )
    registration["expiration_date"] = first_whois_value(
        fields,
        [
            "registrar registration expiration date",
            "registry expiry date",
            "expiration date",
            "expires on",
            "expiry date",
        ],
    )
    registration["registrar"] = first_whois_value(fields, ["registrar"])
    registration["registrant_name"] = first_whois_value(fields, ["registrant name"])
    registration["registrant_organization"] = first_whois_value(
        fields,
        ["registrant organization", "registrant org"],
    )
    registration["registrant_street"] = first_whois_value(
        fields,
        ["registrant street", "registrant address"],
    )
    registration["registrant_city"] = first_whois_value(fields, ["registrant city"])
    registration["registrant_state_province"] = first_whois_value(
        fields,
        ["registrant state/province", "registrant state province", "registrant state"],
    )
    registration["registrant_postal_code"] = first_whois_value(
        fields,
        ["registrant postal code", "registrant zip code"],
    )
    registration["registrant_country"] = first_whois_value(
        fields,
        ["registrant country"],
    )
    registration["registrant_phone"] = first_whois_value(
        fields,
        ["registrant phone", "registrant phone number"],
    )

    return registration


def query_whois(domain: str, server: Optional[str] = None) -> str:
    cmd = ["whois"]
    normalized_server = normalize_whois_server(server)

    if normalized_server:
        cmd.extend(["-h", normalized_server])

    cmd.append(domain)

    try:
        completed = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=15,
            text=True,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""

    return completed.stdout


def registration_from_whois(
    domain: str,
    server: Optional[str] = None,
) -> Dict[str, Optional[str]]:
    raw_output = query_whois(domain, server)

    if not raw_output:
        return empty_registration()

    return parse_whois_registration(raw_output)


def normalize_whois_server(server: Optional[str]) -> Optional[str]:
    if not server:
        return None

    normalized = server.strip()

    if not normalized:
        return None

    if "://" in normalized:
        parsed = urllib.parse.urlparse(normalized)
        normalized = parsed.netloc or parsed.path

    normalized = normalized.split("/", 1)[0].strip()

    if not normalized:
        return None

    return normalized


def read_json_url(url: str, timeout: int = 8) -> Optional[Dict[str, object]]:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/rdap+json, application/json",
            "User-Agent": "connectivity-test-zone",
        },
    )

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (json.JSONDecodeError, OSError, TimeoutError, urllib.error.URLError):
        return None

    if isinstance(payload, dict):
        return payload

    return None


def rdap_bootstrap() -> Optional[Dict[str, object]]:
    global rdap_bootstrap_cache

    if rdap_bootstrap_cache is None:
        rdap_bootstrap_cache = read_json_url("https://data.iana.org/rdap/dns.json")

    return rdap_bootstrap_cache


def rdap_base_url(domain: str) -> Optional[str]:
    bootstrap = rdap_bootstrap()

    if not bootstrap:
        return None

    labels = domain.rstrip(".").lower().split(".")
    services = bootstrap.get("services", [])

    if not isinstance(services, list):
        return None

    for index in range(len(labels)):
        candidate = ".".join(labels[index:])

        for service in services:
            if not isinstance(service, list) or len(service) < 2:
                continue

            tlds, urls = service[0], service[1]

            if not isinstance(tlds, list) or not isinstance(urls, list):
                continue

            if candidate not in {str(tld).lower() for tld in tlds}:
                continue

            for url in urls:
                if isinstance(url, str) and url.startswith(("http://", "https://")):
                    return url.rstrip("/")

    return None


def rdap_domain_lookup(domain: str) -> Optional[Dict[str, object]]:
    base_url = rdap_base_url(domain)

    if not base_url:
        return None

    encoded_domain = urllib.parse.quote(domain.rstrip("."), safe="")
    return read_json_url(f"{base_url}/domain/{encoded_domain}")


def event_date(payload: Dict[str, object], action_names: List[str]) -> Optional[str]:
    action_lookup = {action.lower() for action in action_names}
    events = payload.get("events", [])

    if not isinstance(events, list):
        return None

    for event in events:
        if not isinstance(event, dict):
            continue

        action = event.get("eventAction")
        date = event.get("eventDate")

        if (
            isinstance(action, str)
            and action.lower() in action_lookup
            and isinstance(date, str)
            and date
        ):
            return date

    return None


def entity_roles(entity: Dict[str, object]) -> List[str]:
    roles = entity.get("roles", [])

    if not isinstance(roles, list):
        return []

    return [str(role).lower() for role in roles]


def vcard_values(entity: Dict[str, object], name: str) -> List[object]:
    vcard = entity.get("vcardArray")

    if not isinstance(vcard, list) or len(vcard) < 2 or not isinstance(vcard[1], list):
        return []

    values = []

    for item in vcard[1]:
        if not isinstance(item, list) or len(item) < 4:
            continue

        if item[0] == name:
            values.append(item[3])

    return values


def first_vcard_text(entity: Dict[str, object], name: str) -> Optional[str]:
    for value in vcard_values(entity, name):
        if isinstance(value, str) and value.strip():
            return value.strip()

        if isinstance(value, list):
            text = ", ".join(str(item).strip() for item in value if str(item).strip())

            if text:
                return text

    return None


def entity_name(entity: Dict[str, object]) -> Optional[str]:
    return first_vcard_text(entity, "fn") or first_vcard_text(entity, "name")


def first_vcard_address(entity: Dict[str, object]) -> Dict[str, Optional[str]]:
    empty_address = {
        "street": None,
        "city": None,
        "state_province": None,
        "postal_code": None,
        "country": None,
    }

    for value in vcard_values(entity, "adr"):
        if not isinstance(value, list) or len(value) < 7:
            continue

        street_value = value[2]

        if isinstance(street_value, list):
            street = ", ".join(
                str(item).strip() for item in street_value if str(item).strip()
            )
        elif isinstance(street_value, str):
            street = street_value.strip()
        else:
            street = None

        return {
            "street": street or None,
            "city": str(value[3]).strip() or None,
            "state_province": str(value[4]).strip() or None,
            "postal_code": str(value[5]).strip() or None,
            "country": str(value[6]).strip() or None,
        }

    return empty_address


def first_entity(payload: Dict[str, object], role: str) -> Optional[Dict[str, object]]:
    entities = payload.get("entities", [])

    if not isinstance(entities, list):
        return None

    role = role.lower()

    for entity in entities:
        if isinstance(entity, dict) and role in entity_roles(entity):
            return entity

    return None


def link_href(entity: Dict[str, object], rel: str) -> Optional[str]:
    links = entity.get("links", [])

    if not isinstance(links, list):
        return None

    for link in links:
        if not isinstance(link, dict):
            continue

        link_rel = link.get("rel")
        href = link.get("href")

        if link_rel == rel and isinstance(href, str) and href.strip():
            return href.strip()

    return None


def registration_from_rdap(domain: str) -> Dict[str, Optional[str]]:
    if not whois_enabled:
        return empty_registration()

    if domain in rdap_cache:
        return rdap_cache[domain]

    registration = empty_registration()
    payload = rdap_domain_lookup(domain)

    if payload is not None:
        port43 = payload.get("port43")

        if isinstance(port43, str) and port43.strip():
            registration["registrar_whois_server"] = port43.strip()

        registration["updated_date"] = event_date(
            payload, ["last changed", "last update of RDAP database"]
        )
        registration["creation_date"] = event_date(payload, ["registration"])
        registration["expiration_date"] = event_date(payload, ["expiration"])

        registrar_entity = first_entity(payload, "registrar")
        registrant_entity = first_entity(payload, "registrant")

        if registrar_entity:
            registration["registrar"] = entity_name(registrar_entity)
            registration["registrar_url"] = first_vcard_text(
                registrar_entity, "url"
            ) or link_href(registrar_entity, "about")

        if registrant_entity:
            address = first_vcard_address(registrant_entity)
            registration["registrant_name"] = entity_name(registrant_entity)
            registration["registrant_organization"] = first_vcard_text(
                registrant_entity, "org"
            )
            registration["registrant_street"] = address["street"]
            registration["registrant_city"] = address["city"]
            registration["registrant_state_province"] = address["state_province"]
            registration["registrant_postal_code"] = address["postal_code"]
            registration["registrant_country"] = address["country"]
            registration["registrant_phone"] = first_vcard_text(
                registrant_entity, "tel"
            )

    registry_whois = registration_from_whois(domain)
    merge_registration(registration, registry_whois)

    registrar_whois_server = registration.get("registrar_whois_server")

    if registrar_whois_server:
        registrar_whois = registration_from_whois(domain, registrar_whois_server)
        merge_registration(registration, registrar_whois, overwrite=True)

    rdap_cache[domain] = registration
    return registration


def script_entries(port: ET.Element, port_id: int) -> List[Dict[str, object]]:
    entries = []

    for script in port.findall("script"):
        script_id = script.attrib.get("id", "").strip()
        output = script.attrib.get("output", "").strip()

        if not script_id:
            continue

        entries.append(
            {
                "port": port_id,
                "script_id": script_id,
                "output": output,
            }
        )

    return entries


def host_script_entries(root: ET.Element) -> List[Dict[str, object]]:
    entries = []

    for script in root.findall(".//host/hostscript/script"):
        script_id = script.attrib.get("id", "").strip()
        output = script.attrib.get("output", "").strip()

        if not script_id:
            continue

        entries.append(
            {
                "script_id": script_id,
                "output": output,
            }
        )

    return entries


def service_from_port(
    port: ET.Element, state: ET.Element, port_id: int
) -> Dict[str, object]:
    service = port.find("service")
    service_attrs = service.attrib if service is not None else {}

    return {
        "port": port_id,
        "protocol": port.attrib.get("protocol", "tcp"),
        "state": state.attrib.get("state", ""),
        "name": service_attrs.get("name"),
        "product": service_attrs.get("product"),
        "version": service_attrs.get("version"),
        "extrainfo": service_attrs.get("extrainfo"),
        "tunnel": service_attrs.get("tunnel"),
        "confidence": service_attrs.get("conf"),
    }


def scan_host(
    hostname: str,
) -> Tuple[
    List[int], List[Dict[str, object]], List[Dict[str, object]], List[Dict[str, object]]
]:
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
            f"{effective_nmap_timeout_seconds}s",
            "-p",
            ports,
            "-oX",
            tmp.name,
        ]

        if service_version_enabled:
            cmd.extend(["-sV", "--version-light"])

        if nse_enabled:
            cmd.extend(["--script", nse_scripts])

        cmd.append(hostname)

        try:
            subprocess.run(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=effective_nmap_timeout_seconds + 10,
                text=True,
            )
        except subprocess.TimeoutExpired:
            return [], [], [], []

        try:
            tree = ET.parse(tmp.name)
        except ET.ParseError:
            return [], [], [], []

    root = tree.getroot()
    open_ports = []
    services = []
    nse = []

    for port in root.findall(".//ports/port"):
        state = port.find("state")

        if state is None:
            continue

        if state.attrib.get("state") != "open":
            continue

        port_id = port.attrib.get("portid")

        if port_id and port_id.isdigit():
            parsed_port_id = int(port_id)
            open_ports.append(parsed_port_id)
            port_scripts = script_entries(port, parsed_port_id)
            service = service_from_port(port, state, parsed_port_id)

            if port_scripts:
                service["nse"] = port_scripts
                nse.extend(port_scripts)

            services.append(service)

    open_ports = sorted(set(open_ports))
    services = sorted(services, key=lambda item: int(item["port"]))

    return open_ports, services, nse, host_script_entries(root)


def format_certificate_name(name_parts: tuple) -> str:
    attributes = []

    for relative_distinguished_name in name_parts:
        for key, value in relative_distinguished_name:
            attributes.append(f"{key}={value}")

    return ", ".join(attributes)


def certificate_expiration_details(not_after: str) -> Dict[str, object]:
    if not not_after:
        return {
            "expiration": "",
            "expired": False,
            "expires_soon": False,
            "days_until_expiration": None,
        }

    try:
        expires_at = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
    except ValueError:
        return {
            "expiration": not_after,
            "expired": False,
            "expires_soon": False,
            "days_until_expiration": None,
        }

    expires_at = expires_at.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    days_until_expiration = (expires_at - now).days
    expired = expires_at < now

    return {
        "expiration": expires_at.strftime("%B %-d, %Y at %-I:%M:%S %p UTC"),
        "expired": expired,
        "expires_soon": not expired and days_until_expiration <= 30,
        "days_until_expiration": days_until_expiration,
    }


def decode_certificate(der_cert: bytes) -> Dict:
    pem_cert = ssl.DER_cert_to_PEM_cert(der_cert)

    with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=True) as tmp:
        tmp.write(pem_cert)
        tmp.flush()
        return ssl._ssl._test_decode_cert(tmp.name)


def certificate_subject_alternative_names(decoded_cert: Dict) -> List[str]:
    return [
        value
        for name_type, value in decoded_cert.get("subjectAltName", ())
        if name_type == "DNS"
    ]


def read_tls_certificate(hostname: str, port: int) -> Optional[Dict[str, object]]:
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

    expiration_details = certificate_expiration_details(
        decoded_cert.get("notAfter", "")
    )

    return {
        "ports": [port],
        "issuer": format_certificate_name(decoded_cert.get("issuer", ())),
        "subject": format_certificate_name(decoded_cert.get("subject", ())),
        "subject_alternative_names": certificate_subject_alternative_names(
            decoded_cert
        ),
        "thumbprint": hashlib.sha256(der_cert).hexdigest().upper(),
        "expiration": expiration_details["expiration"],
        "expired": expiration_details["expired"],
        "expires_soon": expiration_details["expires_soon"],
        "days_until_expiration": expiration_details["days_until_expiration"],
    }


def scan_tls_certificates(
    hostname: str, open_ports: List[int]
) -> List[Dict[str, object]]:
    certificates = []
    certificates_by_thumbprint = {}

    for port in open_ports:
        certificate = read_tls_certificate(hostname, port)

        if certificate is None:
            continue

        thumbprint = certificate["thumbprint"]

        if thumbprint in certificates_by_thumbprint:
            certificates_by_thumbprint[thumbprint]["ports"].append(port)
            continue

        certificates_by_thumbprint[thumbprint] = certificate
        certificates.append(certificate)

    return certificates


def default_waf_result() -> Dict[str, object]:
    return {
        "checked": False,
        "detected": False,
        "products": [],
        "endpoints": [],
    }


def waf_display_url(hostname: str, scheme: str) -> str:
    return f"{scheme}://{hostname}"


def waf_request_url(hostname: str, port: int, scheme: str) -> str:
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        return f"{scheme}://{hostname}"

    return f"{scheme}://{hostname}:{port}"


def normalize_waf_product(product: object) -> str:
    if not isinstance(product, str):
        return ""

    normalized = product.strip()

    if not normalized or normalized.lower() in {"none", "unknown", "generic"}:
        return ""

    return normalized


def format_waf_product(product: str, manufacturer: str) -> str:
    if not manufacturer:
        return product

    if (
        product.lower() == manufacturer.lower()
        or manufacturer.lower() in product.lower()
    ):
        return product

    return f"{product} ({manufacturer})"


def collect_waf_products(value: object) -> List[str]:
    products = []

    if isinstance(value, str):
        product = normalize_waf_product(value)

        if product:
            products.append(product)
    elif isinstance(value, list):
        for item in value:
            products.extend(collect_waf_products(item))
    elif isinstance(value, dict):
        manufacturer = normalize_waf_product(value.get("manufacturer"))
        direct_products = []

        for key in ("firewall", "waf", "name", "product"):
            direct_products.extend(collect_waf_products(value.get(key)))

        if direct_products:
            products.extend(
                format_waf_product(product, manufacturer) for product in direct_products
            )
        elif manufacturer:
            products.append(manufacturer)

        for key, item in value.items():
            if key in {"firewall", "waf", "name", "product", "manufacturer"}:
                continue

            if isinstance(item, (dict, list)):
                products.extend(collect_waf_products(item))

    return products


def waf_detection_from_payload(payload: object) -> Dict[str, object]:
    detected = False
    products = []

    entries = payload if isinstance(payload, list) else [payload]

    for entry in entries:
        if not isinstance(entry, dict):
            continue

        detected_value = next(
            (
                entry[key]
                for key in ("detected", "identified", "is_waf")
                if isinstance(entry.get(key), bool)
            ),
            None,
        )

        entry_detected = detected_value is True

        if entry_detected:
            detected = True
            products.extend(collect_waf_products(entry))

        for key, value in entry.items():
            if key in {"firewall", "waf", "name", "product", "manufacturer"}:
                continue

            if isinstance(value, (dict, list)):
                nested_detection = waf_detection_from_payload(value)
                detected = detected or bool(nested_detection["detected"])
                products.extend(nested_detection["products"])

    unique_products = sorted(set(products))

    return {
        "detected": detected,
        "products": unique_products,
    }


def parse_wafw00f_json(output: str) -> object:
    stripped_output = output.strip()

    if not stripped_output:
        raise json.JSONDecodeError("empty wafw00f output", output, 0)

    try:
        return json.loads(stripped_output)
    except json.JSONDecodeError:
        pass

    starts = [
        index
        for index in (stripped_output.find("["), stripped_output.find("{"))
        if index >= 0
    ]

    if not starts:
        raise json.JSONDecodeError("wafw00f output contains no JSON", output, 0)

    return json.loads(stripped_output[min(starts) :])


def read_server_header(url: str) -> str:
    request = urllib.request.Request(
        url,
        method="HEAD",
        headers={"User-Agent": "connectivity-test-zone"},
    )
    context = ssl._create_unverified_context()

    try:
        with urllib.request.urlopen(
            request,
            timeout=5,
            context=context,
        ) as response:
            return normalize_waf_product(response.headers.get("Server", ""))
    except urllib.error.HTTPError as exc:
        return normalize_waf_product(exc.headers.get("Server", ""))
    except (OSError, TimeoutError, ValueError):
        return ""


def scan_waf_endpoint(hostname: str, port: int, scheme: str) -> Dict[str, object]:
    url = waf_display_url(hostname, scheme)
    request_url = waf_request_url(hostname, port, scheme)
    endpoint_result = {
        "url": url,
        "port": port,
        "checked": False,
        "detected": False,
        "products": [],
    }

    try:
        completed = subprocess.run(
            ["wafw00f", "-f", "json", "-o", "-", request_url],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=wafw00f_timeout_seconds,
            text=True,
        )
    except subprocess.TimeoutExpired:
        return endpoint_result
    except OSError:
        return endpoint_result

    if completed.returncode not in {0, 1} and not completed.stdout.strip():
        return endpoint_result

    try:
        payload = parse_wafw00f_json(completed.stdout)
    except json.JSONDecodeError:
        return endpoint_result

    detection = waf_detection_from_payload(payload)
    products = detection["products"]

    if detection["detected"] and not products:
        server_header = read_server_header(request_url)

        if server_header:
            products = [server_header]
        else:
            products = ["unknown"]

    endpoint_result["checked"] = True
    endpoint_result["detected"] = detection["detected"]
    endpoint_result["products"] = products

    return endpoint_result


def scan_waf(hostname: str, open_ports: List[int]) -> Dict[str, object]:
    if not waf_enabled:
        return default_waf_result()

    endpoints = []

    for port in open_ports:
        scheme = http_ports_by_scheme.get(port)

        if scheme is None:
            continue

        endpoints.append(scan_waf_endpoint(hostname, port, scheme))

    checked_endpoints = [endpoint for endpoint in endpoints if endpoint["checked"]]
    products = sorted(
        {product for endpoint in checked_endpoints for product in endpoint["products"]}
    )

    return {
        "checked": len(checked_endpoints) > 0,
        "detected": any(endpoint["detected"] for endpoint in checked_endpoints),
        "products": products,
        "endpoints": endpoints,
    }


def default_http_result() -> Dict[str, object]:
    return {
        "checked": False,
        "endpoints": [],
    }


def endpoint_url(hostname: str, port: int, scheme: str) -> str:
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        return f"{scheme}://{hostname}"

    return f"{scheme}://{hostname}:{port}"


def scheme_from_service(
    port: int, service: Optional[Dict[str, object]]
) -> Optional[str]:
    mapped_scheme = http_ports_by_scheme.get(port)

    if service is None:
        return mapped_scheme

    name = str(service.get("name") or "").lower()
    tunnel = str(service.get("tunnel") or "").lower()

    if tunnel == "ssl" and ("http" in name or port in {443, 8443, 9443, 10443}):
        return "https"

    if name in {"https", "ssl/http"}:
        return "https"

    if "http" in name:
        return mapped_scheme or "http"

    return mapped_scheme


def http_endpoint_candidates(
    hostname: str,
    open_ports: List[int],
    services: List[Dict[str, object]],
) -> List[Dict[str, object]]:
    services_by_port = {int(service["port"]): service for service in services}
    candidates = []

    for port in open_ports:
        scheme = scheme_from_service(port, services_by_port.get(port))

        if scheme is None:
            continue

        candidates.append(
            {
                "url": endpoint_url(hostname, port, scheme),
                "port": port,
                "scheme": scheme,
            }
        )

    return candidates


def selected_header_values(headers) -> Dict[str, Optional[str]]:
    return {
        "strict-transport-security": headers.get("Strict-Transport-Security"),
        "content-security-policy": headers.get("Content-Security-Policy"),
        "x-frame-options": headers.get("X-Frame-Options"),
        "x-content-type-options": headers.get("X-Content-Type-Options"),
        "referrer-policy": headers.get("Referrer-Policy"),
        "permissions-policy": headers.get("Permissions-Policy"),
        "cross-origin-opener-policy": headers.get("Cross-Origin-Opener-Policy"),
        "cross-origin-embedder-policy": headers.get("Cross-Origin-Embedder-Policy"),
        "cross-origin-resource-policy": headers.get("Cross-Origin-Resource-Policy"),
        "access-control-allow-origin": headers.get("Access-Control-Allow-Origin"),
        "access-control-allow-credentials": headers.get(
            "Access-Control-Allow-Credentials"
        ),
        "cache-control": headers.get("Cache-Control"),
        "x-powered-by": headers.get("X-Powered-By"),
    }


def extract_title(body: bytes, headers) -> Optional[str]:
    charset = (
        headers.get_content_charset()
        if hasattr(headers, "get_content_charset")
        else None
    )
    charset = charset or "utf-8"

    try:
        text = body.decode(charset, errors="ignore")
    except LookupError:
        text = body.decode("utf-8", errors="ignore")

    match = re.search(r"<title[^>]*>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)

    if not match:
        return None

    title = html.unescape(match.group(1))
    title = " ".join(title.split())

    return title or None


def header_result(
    present: bool,
    value: Optional[str],
    assessment: str,
    recommendation: Optional[str],
) -> Dict[str, object]:
    return {
        "present": present,
        "value": value,
        "assessment": assessment,
        "recommendation": recommendation,
    }


def hsts_max_age(value: Optional[str]) -> Optional[int]:
    if not value:
        return None

    match = re.search(r"(?:^|;)\s*max-age\s*=\s*(\d+)", value, re.IGNORECASE)

    if not match:
        return None

    return int(match.group(1))


def has_detailed_version(value: Optional[str]) -> bool:
    if not value:
        return False

    return bool(re.search(r"(?:/|\s)\d+(?:\.\d+){1,}", value))


def csp_has_frame_ancestors(value: Optional[str]) -> bool:
    return bool(value and re.search(r"(?:^|;)\s*frame-ancestors\b", value, re.I))


def csp_uses_unsafe_directives(value: Optional[str]) -> bool:
    return bool(value and re.search(r"'unsafe-(?:inline|eval)'", value, re.I))


def header_finding(
    *,
    url: str,
    port: int,
    header: str,
    value: Optional[str],
    assessment: str,
    recommendation: Optional[str],
) -> Optional[Dict[str, object]]:
    if assessment in {"good", "not_applicable", "not_present", "present"}:
        return None

    severity = "low"
    title_suffix = "requires review"

    if assessment == "missing":
        title_suffix = "is missing"
    elif assessment == "weak":
        title_suffix = "appears weak"
    elif assessment == "misconfigured":
        title_suffix = "appears misconfigured"
    elif assessment == "potentially_misconfigured":
        title_suffix = "may be misconfigured"
        severity = "medium"
    elif assessment == "informational_exposure":
        title_suffix = "exposes implementation details"
        severity = "info"

    evidence: Dict[str, object] = {"header": header}

    if value is not None:
        evidence["value"] = value

    return {
        "category": "HTTP Security Headers",
        "severity_hint": severity,
        "title": f"{header} header {title_suffix}",
        "target": url,
        "port": port,
        "evidence": evidence,
        "recommendation": recommendation,
    }


def assess_security_headers(
    headers: Dict[str, Optional[str]],
    scheme: str,
    url: str,
    port: int,
) -> Tuple[Dict[str, Dict[str, object]], Dict[str, object], List[Dict[str, object]]]:
    values = {key: headers.get(name.lower()) for key, name in HEADER_LOOKUP.items()}
    csp_value = values["content_security_policy"]
    csp_has_frame_ancestors_directive = csp_has_frame_ancestors(csp_value)
    acao = values["access_control_allow_origin"]
    acac = values["access_control_allow_credentials"]
    results: Dict[str, Dict[str, object]] = {}

    hsts_value = values["strict_transport_security"]
    hsts_age = hsts_max_age(hsts_value)

    if scheme != "https":
        results["strict_transport_security"] = header_result(
            bool(hsts_value),
            hsts_value,
            "not_applicable",
            None,
        )
    elif not hsts_value:
        results["strict_transport_security"] = header_result(
            False,
            None,
            "missing",
            "Consider enabling Strict-Transport-Security for HTTPS endpoints.",
        )
    elif hsts_age is None or hsts_age < 31536000:
        results["strict_transport_security"] = header_result(
            True,
            hsts_value,
            "weak",
            "Consider an HSTS max-age of at least one year after validation.",
        )
    else:
        results["strict_transport_security"] = header_result(
            True,
            hsts_value,
            "good",
            None,
        )

    if not csp_value:
        results["content_security_policy"] = header_result(
            False,
            None,
            "missing",
            "Consider implementing a Content-Security-Policy.",
        )
    elif csp_uses_unsafe_directives(csp_value):
        results["content_security_policy"] = header_result(
            True,
            csp_value,
            "weak",
            "Review whether unsafe CSP directives can be removed.",
        )
    else:
        results["content_security_policy"] = header_result(
            True,
            csp_value,
            "good",
            None,
        )

    xfo_value = values["x_frame_options"]
    normalized_xfo = (xfo_value or "").strip().upper()

    if not xfo_value and csp_has_frame_ancestors_directive:
        results["x_frame_options"] = header_result(
            False,
            None,
            "not_applicable",
            None,
        )
    elif not xfo_value:
        results["x_frame_options"] = header_result(
            False,
            None,
            "missing",
            "Consider DENY, SAMEORIGIN, or CSP frame-ancestors for clickjacking protection.",
        )
    elif normalized_xfo in {"DENY", "SAMEORIGIN"}:
        results["x_frame_options"] = header_result(True, xfo_value, "good", None)
    elif normalized_xfo.startswith("ALLOW-FROM"):
        results["x_frame_options"] = header_result(
            True,
            xfo_value,
            "weak",
            "ALLOW-FROM is obsolete in modern browsers; prefer CSP frame-ancestors.",
        )
    else:
        results["x_frame_options"] = header_result(
            True,
            xfo_value,
            "misconfigured",
            "Use DENY or SAMEORIGIN, or define CSP frame-ancestors.",
        )

    xcto_value = values["x_content_type_options"]

    if not xcto_value:
        results["x_content_type_options"] = header_result(
            False,
            None,
            "missing",
            "Consider setting X-Content-Type-Options to nosniff.",
        )
    elif xcto_value.strip().lower() == "nosniff":
        results["x_content_type_options"] = header_result(
            True,
            xcto_value,
            "good",
            None,
        )
    else:
        results["x_content_type_options"] = header_result(
            True,
            xcto_value,
            "misconfigured",
            "Set X-Content-Type-Options to nosniff.",
        )

    referrer_value = values["referrer_policy"]

    if not referrer_value:
        results["referrer_policy"] = header_result(
            False,
            None,
            "missing",
            "Consider defining a Referrer-Policy appropriate for the application.",
        )
    elif "unsafe-url" in referrer_value.lower():
        results["referrer_policy"] = header_result(
            True,
            referrer_value,
            "weak",
            "Avoid unsafe-url unless the application explicitly requires it.",
        )
    else:
        results["referrer_policy"] = header_result(True, referrer_value, "good", None)

    permissions_value = values["permissions_policy"]

    if not permissions_value:
        results["permissions_policy"] = header_result(
            False,
            None,
            "missing",
            "Consider a Permissions-Policy that disables unneeded browser features.",
        )
    else:
        results["permissions_policy"] = header_result(
            True,
            permissions_value,
            "good",
            None,
        )

    coop_value = values["cross_origin_opener_policy"]

    if not coop_value:
        results["cross_origin_opener_policy"] = header_result(
            False,
            None,
            "missing",
            "Consider Cross-Origin-Opener-Policy for stronger document isolation.",
        )
    elif coop_value.strip().lower() == "same-origin":
        results["cross_origin_opener_policy"] = header_result(
            True,
            coop_value,
            "good",
            None,
        )
    else:
        results["cross_origin_opener_policy"] = header_result(
            True,
            coop_value,
            "weak",
            "Review whether same-origin is appropriate for this endpoint.",
        )

    coep_value = values["cross_origin_embedder_policy"]

    if not coep_value:
        results["cross_origin_embedder_policy"] = header_result(
            False,
            None,
            "missing",
            "Consider Cross-Origin-Embedder-Policy where isolation is required.",
        )
    elif coep_value.strip().lower() in {"require-corp", "credentialless"}:
        results["cross_origin_embedder_policy"] = header_result(
            True,
            coep_value,
            "good",
            None,
        )
    else:
        results["cross_origin_embedder_policy"] = header_result(
            True,
            coep_value,
            "weak",
            "Review the Cross-Origin-Embedder-Policy value.",
        )

    corp_value = values["cross_origin_resource_policy"]

    if not corp_value:
        results["cross_origin_resource_policy"] = header_result(
            False,
            None,
            "missing",
            "Consider Cross-Origin-Resource-Policy for resources that should be isolated.",
        )
    elif corp_value.strip().lower() in {"same-origin", "same-site"}:
        results["cross_origin_resource_policy"] = header_result(
            True,
            corp_value,
            "good",
            None,
        )
    else:
        results["cross_origin_resource_policy"] = header_result(
            True,
            corp_value,
            "weak",
            "Review whether this Cross-Origin-Resource-Policy value is intended.",
        )

    acac_true = (acac or "").strip().lower() == "true"

    if not acao:
        results["access_control_allow_origin"] = header_result(
            False,
            None,
            "not_present",
            None,
        )
    elif acao.strip() == "*" and acac_true:
        results["access_control_allow_origin"] = header_result(
            True,
            acao,
            "potentially_misconfigured",
            "Avoid wildcard Access-Control-Allow-Origin with credentialed requests.",
        )
    elif acao.strip() == "*":
        results["access_control_allow_origin"] = header_result(
            True,
            acao,
            "weak",
            "Review whether wildcard CORS is intended for this endpoint.",
        )
    else:
        results["access_control_allow_origin"] = header_result(True, acao, "good", None)

    if not acac:
        results["access_control_allow_credentials"] = header_result(
            False,
            None,
            "not_present",
            None,
        )
    elif acac_true and acao and acao.strip() == "*":
        results["access_control_allow_credentials"] = header_result(
            True,
            acac,
            "potentially_misconfigured",
            "Avoid credentialed CORS responses with wildcard origins.",
        )
    elif acac_true:
        results["access_control_allow_credentials"] = header_result(
            True,
            acac,
            "present",
            "Confirm credentialed CORS is required for this endpoint.",
        )
    else:
        results["access_control_allow_credentials"] = header_result(
            True,
            acac,
            "weak",
            "Use true only when credentialed CORS is explicitly required.",
        )

    cache_value = values["cache_control"]

    if not cache_value:
        results["cache_control"] = header_result(
            False,
            None,
            "missing",
            "Consider Cache-Control directives for sensitive or authenticated responses.",
        )
    elif re.search(r"\b(no-store|private|no-cache)\b", cache_value, re.I):
        results["cache_control"] = header_result(True, cache_value, "good", None)
    elif re.search(r"\bpublic\b|\bmax-age\s*=\s*[1-9]", cache_value, re.I):
        results["cache_control"] = header_result(
            True,
            cache_value,
            "weak",
            "Review cacheability in the context of the response content.",
        )
    else:
        results["cache_control"] = header_result(True, cache_value, "present", None)

    server_value = values["server"]

    if not server_value:
        results["server"] = header_result(False, None, "good", None)
    elif has_detailed_version(server_value):
        results["server"] = header_result(
            True,
            server_value,
            "informational_exposure",
            "Consider suppressing detailed server version information.",
        )
    else:
        results["server"] = header_result(True, server_value, "present", None)

    x_powered_by_value = values["x_powered_by"]

    if not x_powered_by_value:
        results["x_powered_by"] = header_result(False, None, "good", None)
    else:
        results["x_powered_by"] = header_result(
            True,
            x_powered_by_value,
            "informational_exposure",
            "Consider suppressing X-Powered-By unless it is operationally required.",
        )

    score = sum(
        1
        for key in SECURITY_HEADER_SCORE_KEYS
        if results[key]["assessment"] in {"good", "not_applicable", "present"}
    )
    max_score = len(SECURITY_HEADER_SCORE_KEYS)
    missing_headers = [
        HEADER_LOOKUP[key]
        for key in SECURITY_HEADER_SCORE_KEYS
        if results[key]["assessment"] == "missing"
    ]

    if score >= 10:
        rating = "Good"
    elif score >= 7:
        rating = "Fair"
    elif score >= 4:
        rating = "Needs Review"
    else:
        rating = "Needs Attention"

    summary = {
        "score": score,
        "max_score": max_score,
        "rating": rating,
        "missing_headers": missing_headers,
    }
    findings = []

    for key, result in results.items():
        finding = header_finding(
            url=url,
            port=port,
            header=HEADER_LOOKUP[key],
            value=result["value"],
            assessment=str(result["assessment"]),
            recommendation=result["recommendation"],
        )

        if finding is not None:
            findings.append(finding)

    return results, summary, findings


def assess_php_cve_exposure(headers: Dict[str, Optional[str]]) -> List[Dict[str, object]]:
    """Banner-only triage; neither exploit verification nor a patch inventory."""
    findings = []
    fixed = {(8, 2): 35, (8, 3): 36, (8, 4): 27, (8, 5): 12}
    for header in ("x-powered-by", "server"):
        value = headers.get(header) or ""
        for match in re.finditer(r"\bPHP/(\d+)\.(\d+)\.(\d+)(?![\d.])", value, re.I):
            major, minor, patch = map(int, match.groups())
            branch = (major, minor)
            if branch not in fixed and not ((5, 4) <= branch <= (8, 1)):
                continue
            if branch in fixed and patch >= fixed[branch]:
                continue
            version = match.group(0).split("/", 1)[1]
            for cve in ("CVE-2026-109618", "CVE-2026-109619"):
                if any(item["cve"] == cve and item["version"] == version for item in findings):
                    continue
                findings.append({
                    "cve": cve,
                    "version": version,
                    "assessment": "potentially_affected",
                    "detection_method": "http_version_banner",
                    "header": header,
                    "value": value,
                    "fixed_version": f"8.{minor}.{fixed[branch]}" if branch in fixed else None,
                    "validation": (
                        "Verify the installed PHP package and vendor security advisory. "
                        "Banners may be stale or spoofed and vendor backports may fix older "
                        "versions. This check does not confirm exploitability."
                    ),
                    "recommendation": "Install a vendor-patched PHP package or upgrade to a fixed supported release.",
                })
    return findings


def fetch_http_endpoint(candidate: Dict[str, object]) -> Dict[str, object]:
    url = str(candidate["url"])
    port = int(candidate["port"])
    scheme = str(candidate["scheme"])
    endpoint_result: Dict[str, object] = {
        "url": url,
        "port": port,
        "reachable": False,
        "status_code": None,
        "final_url": None,
        "title": None,
        "server": None,
        "headers": {},
        "security_headers": {},
        "security_header_summary": {
            "score": 0,
            "max_score": len(SECURITY_HEADER_SCORE_KEYS),
            "rating": "Not Checked",
            "missing_headers": [],
        },
        "security_header_findings": [],
        "php_cve_findings": [],
        "error": None,
    }
    request = urllib.request.Request(
        url,
        method="GET",
        headers={"User-Agent": "connectivity-test-zone"},
    )
    context = ssl._create_unverified_context()

    try:
        with urllib.request.urlopen(
            request,
            timeout=http_timeout_seconds,
            context=context,
        ) as response:
            body = response.read(HTTP_BODY_LIMIT_BYTES)
            status_code = response.getcode()
            final_url = response.geturl()
            response_headers = response.headers
    except urllib.error.HTTPError as exc:
        body = exc.read(HTTP_BODY_LIMIT_BYTES)
        status_code = exc.code
        final_url = exc.geturl()
        response_headers = exc.headers
    except (
        OSError,
        TimeoutError,
        ValueError,
        ssl.SSLError,
        urllib.error.URLError,
    ) as exc:
        endpoint_result["error"] = str(exc)
        return endpoint_result

    selected_headers = selected_header_values(response_headers)
    server_header = response_headers.get("Server")
    php_cve_findings = assess_php_cve_exposure({**selected_headers, "server": server_header})
    security_headers, summary, findings = assess_security_headers(
        {**selected_headers, "server": server_header},
        scheme,
        url,
        port,
    )

    endpoint_result.update(
        {
            "reachable": True,
            "status_code": status_code,
            "final_url": final_url,
            "title": extract_title(body, response_headers),
            "server": server_header,
            "headers": selected_headers,
            "security_headers": security_headers,
            "security_header_summary": summary,
            "security_header_findings": findings,
            "php_cve_findings": php_cve_findings,
            "error": None,
        }
    )

    for finding in php_cve_findings:
        append_hint(
            target=url,
            port=port,
            severity_hint="high",
            category="PHP CVE Exposure",
            reason=f"PHP {finding['version']} banner indicates potential {finding['cve']} exposure; requires validation.",
            validation=str(finding["validation"]),
            evidence=finding,
        )

    for finding in findings:
        append_hint(
            target=url,
            port=port,
            severity_hint=str(finding["severity_hint"]),
            category="HTTP Security Headers",
            reason=f"{finding['title']} on {url}; requires validation.",
            validation=(
                "Treat as a hardening opportunity and confirm application "
                "context before reporting."
            ),
            evidence=finding.get("evidence")
            if isinstance(finding.get("evidence"), dict)
            else None,
        )

    return endpoint_result


def collect_http_evidence(candidates: List[Dict[str, object]]) -> Dict[str, object]:
    if not http_evidence_enabled:
        return default_http_result()

    endpoints = []

    for candidate in candidates:
        rate_delay()
        endpoints.append(fetch_http_endpoint(candidate))

    return {
        "checked": True,
        "endpoints": endpoints,
    }


def normalize_nuclei_finding(finding: Dict[str, object]) -> Dict[str, object]:
    info = finding.get("info") if isinstance(finding.get("info"), dict) else {}
    template_id = finding.get("template-id") or finding.get("template_id")
    matched_at = (
        finding.get("matched-at")
        or finding.get("matched_at")
        or finding.get("matched")
        or finding.get("url")
    )

    return {
        "template_id": template_id,
        "name": info.get("name") or finding.get("name"),
        "severity": info.get("severity") or finding.get("severity"),
        "matched_at": matched_at,
        "host": finding.get("host"),
        "port": str(finding.get("port")) if finding.get("port") is not None else None,
        "type": finding.get("type"),
        "raw": finding,
    }


def add_nuclei_hints(findings: List[Dict[str, object]]) -> None:
    for finding in findings:
        severity = str(finding.get("severity") or "").lower()

        if severity not in {"medium", "high", "critical"}:
            continue

        port_value = finding.get("port")
        port = (
            int(port_value)
            if isinstance(port_value, str) and port_value.isdigit()
            else None
        )
        title = finding.get("name") or finding.get("template_id") or "Nuclei finding"
        target = str(finding.get("matched_at") or finding.get("host") or "")

        append_hint(
            target=target,
            port=port,
            severity_hint=severity,
            category="nuclei",
            reason=(
                f"Nuclei reported {severity} finding '{title}'. "
                "Treat this as a hypothesis requiring validation."
            ),
            validation=(
                "Manually confirm exploitability, application context, and "
                "whether the finding is a false positive."
            ),
            evidence={
                "template_id": finding.get("template_id"),
                "matched_at": finding.get("matched_at"),
            },
        )


def run_nuclei(urls: List[str]) -> Dict[str, object]:
    result = {
        "checked": nuclei_enabled,
        "severities": nuclei_severities,
        "findings": [],
        "errors": [],
    }

    if not nuclei_enabled:
        return result

    urls = sorted(set(urls))

    if not urls:
        message = "No HTTP/HTTPS endpoints discovered; nuclei was not run."
        print(f"[!] --nuclei requested but {message}", file=sys.stderr)
        result["errors"].append(message)
        return result

    with tempfile.NamedTemporaryFile(
        mode="w",
        prefix="nuclei-targets-",
        suffix=".txt",
        dir=nmap_tmpdir,
        delete=False,
    ) as targets_file:
        targets_file.write("\n".join(urls) + "\n")
        targets_path = targets_file.name

    output_path = nmap_tmpdir / "nuclei-results.jsonl"
    cmd = [
        "nuclei",
        "-list",
        targets_path,
        "-jsonl",
        "-severity",
        nuclei_severities,
        "-silent",
        "-o",
        str(output_path),
    ]

    if nuclei_templates:
        cmd.extend(["-t", nuclei_templates])

    print(
        f"[{green_color}+{reset_color}] Running nuclei against {len(urls)} endpoint(s)",
        file=sys.stderr,
    )

    try:
        completed = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=max(120, len(urls) * 45),
            text=True,
        )
    except subprocess.TimeoutExpired:
        result["errors"].append("nuclei timed out; partial JSONL output was preserved.")
        completed = None
    except OSError as exc:
        result["errors"].append(f"nuclei failed to start: {exc}")
        completed = None

    if completed is not None and completed.returncode != 0:
        stderr = completed.stderr.strip()
        error = f"nuclei exited with status {completed.returncode}"

        if stderr:
            error = f"{error}: {stderr[:1000]}"

        result["errors"].append(error)

    jsonl_lines = []

    if output_path.exists():
        jsonl_lines.extend(output_path.read_text(errors="ignore").splitlines())

    if completed is not None and completed.stdout.strip():
        jsonl_lines.extend(completed.stdout.splitlines())

    seen_findings = set()

    for line in jsonl_lines:
        stripped = line.strip()

        if not stripped:
            continue

        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError:
            result["errors"].append("Unable to parse one nuclei JSONL line.")
            continue

        if isinstance(parsed, dict):
            finding = normalize_nuclei_finding(parsed)
            finding_key = (
                finding.get("template_id"),
                finding.get("matched_at"),
                finding.get("host"),
                finding.get("port"),
                finding.get("type"),
            )

            if finding_key in seen_findings:
                continue

            seen_findings.add(finding_key)
            result["findings"].append(finding)

    add_nuclei_hints(result["findings"])
    return result


def normalize_zap_alert(alert: Dict[str, object], target: str) -> Dict[str, object]:
    instances = alert.get("instances")

    if not isinstance(instances, list):
        instances = []

    return {
        "target": target,
        "plugin_id": str(alert.get("pluginid") or alert.get("pluginId") or ""),
        "alert": alert.get("alert") or alert.get("name"),
        "name": alert.get("name") or alert.get("alert"),
        "risk": alert.get("risk") or alert.get("riskdesc"),
        "confidence": alert.get("confidence"),
        "risk_desc": alert.get("riskdesc"),
        "description": alert.get("desc"),
        "solution": alert.get("solution"),
        "reference": alert.get("reference"),
        "cwe_id": str(alert.get("cweid") or ""),
        "wasc_id": str(alert.get("wascid") or ""),
        "instances_count": len(instances),
        "instances": instances[:10],
        "raw": alert,
    }


def zap_alerts_from_report(
    report: Dict[str, object], target: str
) -> List[Dict[str, object]]:
    alerts = []
    sites = report.get("site", [])

    if isinstance(sites, dict):
        sites = [sites]

    if not isinstance(sites, list):
        return alerts

    for site in sites:
        if not isinstance(site, dict):
            continue

        site_alerts = site.get("alerts", [])

        if not isinstance(site_alerts, list):
            continue

        for alert in site_alerts:
            if isinstance(alert, dict):
                alerts.append(normalize_zap_alert(alert, target))

    return alerts


def zap_severity_hint(risk: object) -> str:
    normalized = str(risk or "").strip().lower()

    if "high" in normalized:
        return "high"

    if "medium" in normalized:
        return "medium"

    if "low" in normalized:
        return "low"

    return "info"


def add_zap_hints(alerts: List[Dict[str, object]]) -> None:
    for alert in alerts:
        severity = zap_severity_hint(alert.get("risk"))

        if severity == "info":
            continue

        title = alert.get("alert") or alert.get("name") or "ZAP passive alert"
        target = str(alert.get("target") or "")

        append_hint(
            target=target,
            port=None,
            severity_hint=severity,
            category="zap",
            reason=(
                f"OWASP ZAP baseline reported '{title}'. "
                "Treat this as passive-scan evidence requiring validation."
            ),
            validation=(
                "Manually confirm the affected URLs, application context, "
                "and whether the passive alert is a false positive."
            ),
            evidence={
                "plugin_id": alert.get("plugin_id"),
                "risk": alert.get("risk"),
                "confidence": alert.get("confidence"),
            },
        )


def run_zap_baseline_for_url(url: str, index: int) -> Dict[str, object]:
    result: Dict[str, object] = {
        "target": url,
        "mode": "baseline-passive",
        "alerts": [],
        "errors": [],
        "exit_code": None,
    }

    with tempfile.TemporaryDirectory(prefix="zap-", dir="/tmp") as zap_dir:
        zap_path = Path(zap_dir)
        report_name = f"zap-{index}.json"
        report_path = zap_path / report_name
        cmd = [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{zap_path}:/zap/wrk/:rw",
            "-t",
            zap_image,
            "zap-baseline.py",
            "-t",
            url,
            "-J",
            report_name,
            "-I",
            "-m",
            str(zap_spider_minutes),
            "-T",
            str(zap_timeout_minutes),
        ]

        try:
            completed = subprocess.run(
                cmd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=(zap_timeout_minutes * 60) + 120,
                text=True,
            )
        except subprocess.TimeoutExpired:
            result["errors"].append("OWASP ZAP baseline scan timed out.")
            return result
        except OSError as exc:
            result["errors"].append(f"OWASP ZAP failed to start through Docker: {exc}")
            return result

        result["exit_code"] = completed.returncode

        if completed.returncode not in {0, 1, 2}:
            message = f"OWASP ZAP exited with status {completed.returncode}"

            if completed.stderr.strip():
                message = f"{message}: {completed.stderr.strip()[:1000]}"

            result["errors"].append(message)

        if not report_path.exists():
            if completed.stdout.strip():
                result["stdout_excerpt"] = completed.stdout.strip()[:4000]

            if completed.stderr.strip():
                result["stderr_excerpt"] = completed.stderr.strip()[:4000]

            result["errors"].append("OWASP ZAP did not produce a JSON report.")
            return result

        try:
            report = json.loads(report_path.read_text(errors="ignore"))
        except json.JSONDecodeError:
            result["errors"].append("Unable to parse OWASP ZAP JSON report.")
            return result

        if isinstance(report, dict):
            result["alerts"] = zap_alerts_from_report(report, url)
            result["raw_summary"] = {
                "generated": report.get("@generated") or report.get("generated"),
                "version": report.get("@version") or report.get("version"),
            }

    return result


def run_zap_baseline(urls: List[str]) -> Dict[str, object]:
    result: Dict[str, object] = {
        "checked": zap_enabled,
        "mode": "baseline-passive",
        "image": zap_image if zap_enabled else None,
        "spider_minutes": zap_spider_minutes,
        "timeout_minutes": zap_timeout_minutes,
        "max_endpoints": zap_max_endpoints,
        "findings": [],
        "errors": [],
    }

    if not zap_enabled:
        return result

    urls = sorted(set(urls))

    if not urls:
        message = "No HTTP/HTTPS endpoints discovered; OWASP ZAP was not run."
        print(f"[!] --zap requested but {message}", file=sys.stderr)
        result["errors"].append(message)
        return result

    if len(urls) > zap_max_endpoints:
        result["errors"].append(
            f"OWASP ZAP limited to first {zap_max_endpoints} endpoint(s)."
        )
        urls = urls[:zap_max_endpoints]

    print(
        f"[{green_color}+{reset_color}] Running OWASP ZAP baseline against {len(urls)} endpoint(s)",
        file=sys.stderr,
    )

    for index, url in enumerate(urls, start=1):
        rate_delay()
        zap_result = run_zap_baseline_for_url(url, index)
        alerts = zap_result.get("alerts", [])

        if isinstance(alerts, list):
            add_zap_hints(alerts)

        result["findings"].append(zap_result)

    return result


def add_exposure_hints(target: str, open_ports: List[int]) -> None:
    for port in open_ports:
        hint = SERVICE_EXPOSURE_HINTS.get(port)

        if hint is None:
            continue

        category, reason, severity = hint
        append_hint(
            target=target,
            port=port,
            severity_hint=severity,
            category=category,
            reason=reason,
            validation=(
                "Manually confirm expected exposure, authentication, network "
                "controls, and business justification."
            ),
        )


def add_service_version_hints(target: str, services: List[Dict[str, object]]) -> None:
    if not service_version_enabled:
        return

    for service in services:
        product = service.get("product")
        version = service.get("version")

        if not product or not version:
            continue

        append_hint(
            target=target,
            port=int(service["port"]),
            severity_hint="info",
            category="service-version",
            reason=(
                f"Service version evidence observed for {product} {version}; "
                "patch status requires validation."
            ),
            validation=(
                "Confirm the detected version, vendor support status, and "
                "compensating controls before assigning risk."
            ),
            evidence={
                "service": service.get("name"),
                "product": product,
                "version": version,
            },
        )


def add_tls_hints(target: str, certificates: List[Dict[str, object]]) -> None:
    for certificate in certificates:
        cert_ports = certificate.get("ports", [])
        first_port = cert_ports[0] if cert_ports else None

        if certificate.get("expired") is True:
            append_hint(
                target=target,
                port=first_port,
                severity_hint="medium",
                category="tls",
                reason="A TLS certificate appears expired.",
                validation="Confirm certificate status and service ownership.",
                evidence={
                    "expiration": certificate.get("expiration"),
                    "thumbprint": certificate.get("thumbprint"),
                    "ports": cert_ports,
                },
            )
        elif certificate.get("expires_soon") is True:
            append_hint(
                target=target,
                port=first_port,
                severity_hint="low",
                category="tls",
                reason="A TLS certificate appears to expire within 30 days.",
                validation="Confirm renewal status and operational impact.",
                evidence={
                    "expiration": certificate.get("expiration"),
                    "days_until_expiration": certificate.get("days_until_expiration"),
                    "thumbprint": certificate.get("thumbprint"),
                    "ports": cert_ports,
                },
            )


total = len(targets)
http_endpoint_urls: List[str] = []

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
                "services": [],
                "tls_certificates": [],
                "waf": default_waf_result(),
                "http": default_http_result(),
                "nse": [],
                "host_nse": [],
            }
        )
        continue

    open_ports, services, nse, host_nse = scan_host(target)
    tls_certificates = scan_tls_certificates(target, open_ports)
    waf = scan_waf(target, open_ports)
    http_candidates = http_endpoint_candidates(target, open_ports, services)
    http_endpoint_urls.extend(str(candidate["url"]) for candidate in http_candidates)
    http = collect_http_evidence(http_candidates)
    add_exposure_hints(target, open_ports)
    add_service_version_hints(target, services)
    add_tls_hints(target, tls_certificates)
    target_result = {
        "target": target,
        "ipaddress": ipaddress,
        "resolved": True,
        "connected": len(open_ports) > 0,
        "ports": open_ports,
        "services": services,
        "tls_certificates": tls_certificates,
        "waf": waf,
        "http": http,
        "nse": nse,
        "host_nse": host_nse,
    }
    ipinfo = lookup_ipinfo(ipaddress)

    if ipinfo is not None:
        target_result["ipinfo"] = ipinfo

    results.append(target_result)
    rate_delay()

results = sorted(results, key=lambda item: item["target"])
nuclei = run_nuclei(http_endpoint_urls)
zap = run_zap_baseline(http_endpoint_urls)
tool_metadata = {
    "schema_version": "2.0",
    "features_enabled": {
        "service_version": service_version_enabled,
        "nse": nse_enabled,
        "http_evidence": http_evidence_enabled,
        "nuclei": nuclei_enabled,
        "zap": zap_enabled,
    },
    "options": {
        "nse_scripts": nse_scripts if nse_enabled else None,
        "http_timeout": http_timeout_seconds,
        "nuclei_severities": nuclei_severities if nuclei_enabled else None,
        "nuclei_templates": nuclei_templates or None,
        "zap_image": zap_image if zap_enabled else None,
        "zap_spider_minutes": zap_spider_minutes if zap_enabled else None,
        "zap_timeout_minutes": zap_timeout_minutes if zap_enabled else None,
        "zap_max_endpoints": zap_max_endpoints if zap_enabled else None,
        "rate_delay": rate_delay_seconds,
    },
    "notes": [
        "Nuclei findings are hypotheses requiring analyst validation.",
        "OWASP ZAP baseline findings are passive-scan evidence requiring validation.",
        "Prioritization hints are advisory and do not replace analyst judgment.",
    ],
}
prioritization_hints = sorted(
    prioritization_hints,
    key=lambda item: (
        str(item.get("severity_hint", "")),
        str(item.get("category", "")),
        str(item.get("target", "")),
        int(item.get("port", 0)) if isinstance(item.get("port"), int) else 0,
    ),
)

if len(domains) == 1:
    output = {
        "domain": domains[0],
        "source_ip": source_ip(),
        "run_datetime": run_datetime,
        "results": results,
        "nuclei": nuclei,
        "zap": zap,
        "prioritization_hints": prioritization_hints,
        "tool_metadata": tool_metadata,
    }

    if whois_enabled:
        output["registration"] = registration_from_rdap(domains[0])
else:
    output = {
        "domains": domains,
        "source_ip": source_ip(),
        "run_datetime": run_datetime,
        "results": results,
        "nuclei": nuclei,
        "zap": zap,
        "prioritization_hints": prioritization_hints,
        "tool_metadata": tool_metadata,
    }

    if whois_enabled:
        output["registrations"] = {
            domain: registration_from_rdap(domain) for domain in domains
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
