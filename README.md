# connectivity-test-zone

`connectivity-test-zone` enumerates DNS subdomains for one or more target domains,
resolves each hostname, tests selected TCP ports, and emits JSON connectivity
results.

## Responsible use

Use this tool only for authorized security testing, asset inventory, and network
administration. See [DISCLAIMER.md](DISCLAIMER.md) for details.

## What it does

- Runs `subfinder` for the supplied domain or each domain in a supplied text file.
- Optionally brute-forces DNS names with `dnsx` and a supplied wordlist, then
  merges those results with `subfinder` output.
- Optionally enumerates HTTP virtual hosts, then merges those results with the
  other discovered names.
- Resolves each hostname before scanning.
- Skips `nmap` for unresolved names.
- Tests selected TCP ports with `nmap`.
- Suppresses noisy output from enumeration tools and `nmap` while printing
  progress messages.
- Writes colorized JSON to the console through `jq -C`.
- Optionally saves plain valid JSON with no ANSI color codes.
- Includes the local outbound source IP address and run date/time in the
  top-level JSON object.

## JSON schema

```json
{
  "domain": "example.com",
  "source_ip": "192.0.2.10",
  "run_datetime": "6/26/2026 2:41 PM EDT",
  "results": [
    {
      "target": "api.example.com",
      "ipaddress": "192.0.2.20",
      "resolved": true,
      "connected": true,
      "ports": [80, 443]
    }
  ]
}
```

## Dependencies

- `dnsx` when using `--wordlist`
- `gobuster` when using `--vhosts` or `--vhost-wordlist`
- `nmap`
- `subfinder`
- `python3`
- `jq`
- `sed`
- `grep`
- `sort`
- `wc`
- `tr`
- `date`
- `mktemp`
- `mkdir`
- `cp`
- `cat`
- `rm`

## macOS installation

Install common dependencies with Homebrew:

```bash
brew install gobuster jq nmap shellcheck shfmt
```

Install `subfinder` with Go:

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

Install `dnsx` with Go:

```bash
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
```

Ensure your Go binary path is on `PATH`. A common setup is:

```bash
export PATH="$PATH:$HOME/go/bin"
```

## Linux installation

On Debian/Ubuntu, install common packages with:

```bash
sudo apt update
sudo apt install -y gobuster jq nmap python3 sed grep coreutils findutils
```

Install `subfinder` with Go:

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

Install `dnsx` with Go:

```bash
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
```

Ensure your Go binary path is on `PATH`. A common setup is:

```bash
export PATH="$PATH:$HOME/go/bin"
```

## Usage

```console
./connectivity-test-zone.sh -h
```

This will display help for the tool. Here are all the switches it supports.

```text
Usage:
  ./connectivity-test-zone.sh --domain example.com [options]
  ./connectivity-test-zone.sh -d example.com [options]
  ./connectivity-test-zone.sh --domains-file domains.txt [options]
  ./connectivity-test-zone.sh -df domains.txt [options]

Options:
  -d,  --domain           DNS zone / root domain to enumerate
  -df, --domains-file     Text file containing DNS zones / root domains to enumerate
  -wl, --wordlist         Optional DNS brute-force wordlist.
                          Runs active dnsx enumeration in addition to subfinder.
  -r,  --resolvers        Optional resolver list for dnsx.
                          Comma-separated resolvers or a resolvers file.
  -vh, --vhosts           Run vhost enumeration.
                          Defaults to ./vhost-wordlist.txt beside the script.
  -vwl,--vhost-wordlist   Optional vhost wordlist.
                          Implies --vhosts.
  -vs, --vhost-scheme     URL scheme for vhost checks.
                          Default: https
  -vu, --vhost-url        Optional base URL for vhost checks.
                          Useful when the root domain does not resolve.
  -p,  --ports            Comma-separated ports to test
  -oj, --outjson          Save JSON output to a file
  -od, --outdir           Output directory for JSON file
                          Only used when --outjson is present
                          Default with --outjson: current directory
  -h,  --help             Help
```

Common runs:

```console
./connectivity-test-zone.sh --domain example.com
./connectivity-test-zone.sh -d example.com
./connectivity-test-zone.sh --domains-file domains.txt
./connectivity-test-zone.sh -df domains.txt
./connectivity-test-zone.sh --domain example.com --wordlist ad-dns.txt
./connectivity-test-zone.sh -d example.com -wl ad-dns.txt
./connectivity-test-zone.sh -df domains.txt -wl wordlist.txt -oj
./connectivity-test-zone.sh -df domains.txt -wl ad-dns.txt -r 10.0.0.10,10.0.0.11
./connectivity-test-zone.sh --domain example.com --vhosts
./connectivity-test-zone.sh -d example.com -vh -vwl vhost-wordlist.txt
./connectivity-test-zone.sh -d example.com --vhosts --vhost-url https://192.0.2.10
./connectivity-test-zone.sh --domain example.com --ports 22,80,443
./connectivity-test-zone.sh -d example.com -p 22,80,443
./connectivity-test-zone.sh --domain example.com --outjson
./connectivity-test-zone.sh -d example.com -oj
./connectivity-test-zone.sh --domain example.com --outjson --outdir ./results
./connectivity-test-zone.sh -d example.com -oj -od ./results
```

Default ports:

```text
20,21,22,23,25,53,80,88,111,135,139,389,443,445,464,593,636,1433,1521,2049,2379,2380,3268,3269,3306,3389,5432,5672,5900,5985,5986,6379,6443,8000,8080,8081,8433,8443,9000,9200,9389,10250,27017
```

Use `--ports` or `-p` to override the default list.

Use `--domains-file` or `-df` to read root domains from a text file, one domain
per line. Empty lines are ignored. If the file does not exist, the script exits
with an error before scanning.

Use `--wordlist` or `-wl` to run active DNS brute-force enumeration with `dnsx`
in addition to the passive `subfinder` enumeration. The wordlist should contain
subdomain labels such as `dc01`, `ldap`, or `vpn`, one per line. Resolved names
from `dnsx` are merged with `subfinder` results and deduplicated before the
connectivity scan.

Use `--resolvers` or `-r` with `--wordlist` to send the active `dnsx` queries to
specific DNS resolvers. This can be a comma-separated resolver list or a resolver
file accepted by `dnsx`.

Use `--vhosts` or `-vh` to run vhost enumeration for each root domain.
By default this uses the bundled `vhost-wordlist.txt`. Use `--vhost-wordlist` or
`-vwl` to provide a custom list. Vhost results are filtered to names inside the
current root domain and merged with other discovered targets before the
connectivity scan.

Use `--vhost-scheme` or `-vs` to choose the base URL scheme used for vhost
checks. The default is `https`; valid values are `http` and `https`.

Use `--vhost-url` or `-vu` when the root domain itself does not resolve but you
know the web server URL or IP address to probe. The vhost check appends and tests
hostnames under each root domain.

## Permissions

The script uses `nmap -sS` when run as root and `nmap -sT` otherwise.

## Output

Console JSON is colorized through `jq -C`. Saved JSON is plain valid JSON.

Single-domain runs include a top-level `domain` string. File-based runs with
more than one domain include a top-level `domains` array.

If `--outjson` is present, the script saves `connectivity-results.json`.
If `--outdir` is also provided, the JSON file is saved in that directory.
If `--outjson` is present without `--outdir`, the JSON file is saved in the
current directory.

If `--outjson` is not present, the script does not create persistent output
files or directories.

## Temporary files

Temporary files are created in a `mktemp -d` workdir and removed automatically
on exit. Persistent JSON is only written when `--outjson` is used.

The script does not leave persistent `.nmap`, `.gnmap`, or `.xml` files behind.

## Development checks

```bash
bash -n connectivity-test-zone.sh
shellcheck connectivity-test-zone.sh
shfmt -d connectivity-test-zone.sh
```

The script also contains embedded Python heredocs. Extract them before running
Python linting and syntax checks:

```bash
awk '
  /<<'\''PY'\''/ { count++; flag=1; next }
  /^PY$/ { flag=0; next }
  flag {
    print > ("/tmp/connectivity-test-zone-embedded-" count ".py")
  }
' connectivity-test-zone.sh
ruff check /tmp/connectivity-test-zone-embedded-*.py
ruff format --check /tmp/connectivity-test-zone-embedded-*.py
python3 -m py_compile /tmp/connectivity-test-zone-embedded-*.py
```
