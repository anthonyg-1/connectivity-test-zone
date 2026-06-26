# connectivity-test-zone

`connectivity-test-zone` enumerates DNS subdomains for a target domain, resolves each hostname, tests selected TCP ports, and emits JSON connectivity results.

## What it does

- Runs `subfinder` and `amass enum -passive` for the supplied domain.
- Deduplicates discovered DNS names.
- Resolves each hostname before scanning.
- Skips `nmap` for unresolved names.
- Tests selected TCP ports with `nmap`.
- Suppresses noisy output from `subfinder`, `amass`, and `nmap` while printing progress messages.
- Writes colorized JSON to the console through `jq -C`.
- Optionally saves plain valid JSON with no ANSI color codes.
- Includes the local outbound source IP address and run date/time in the top-level JSON object.

## JSON schema

```json
{
  "domain": "example.com",
  "source_ip": "192.0.2.10",
  "run_datetime": "6/26/2026 2:41 PM EDT",
  "results": [
    {
      "target": "api.example.com",
      "resolved": true,
      "connected": true,
      "ports": [80, 443]
    }
  ]
}
```

## Dependencies

- `subfinder`
- `amass`
- `nmap`
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
brew install jq nmap amass shellcheck shfmt
```

Install `subfinder` with Go:

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

Ensure your Go binary path is on `PATH`. A common setup is:

```bash
export PATH="$PATH:$HOME/go/bin"
```

## Linux installation

On Debian/Ubuntu, install common packages with:

```bash
sudo apt update
sudo apt install -y jq nmap python3 sed grep coreutils findutils
```

Install `amass` with your package manager if available, or use the upstream release instructions from the OWASP Amass project.

Install `subfinder` with Go:

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

Ensure your Go binary path is on `PATH`. A common setup is:

```bash
export PATH="$PATH:$HOME/go/bin"
```

## Usage

```bash
./connectivity-test-zone.sh --domain example.com
./connectivity-test-zone.sh -d example.com
./connectivity-test-zone.sh --domain example.com --ports 22,80,443
./connectivity-test-zone.sh -d example.com -p 22,80,443
./connectivity-test-zone.sh --domain example.com --outjson
./connectivity-test-zone.sh -d example.com -oj
./connectivity-test-zone.sh --domain example.com --outjson --outdir ./results
./connectivity-test-zone.sh -d example.com -oj -od ./results
```

Default ports:

```text
20,21,22,23,25,53,80,88,135,389,443,445,3389,5985,5986,8080,8081,8433
```

Use `--ports` or `-p` to override the default list.

## Permissions

The script uses `nmap -sS` when run as root and `nmap -sT` otherwise.

## Output

Console JSON is colorized through `jq -C`. Saved JSON is plain valid JSON.

If `--outjson` is present, the script saves `connectivity-results.json`. If `--outdir` is also provided, the JSON file is saved in that directory. If `--outjson` is present without `--outdir`, the JSON file is saved in the current directory.

If `--outjson` is not present, the script does not create persistent output files or directories.

## Temporary files

Temporary files are created in a `mktemp -d` workdir and removed automatically on exit. Persistent JSON is only written when `--outjson` is used.

The script does not leave persistent `.nmap`, `.gnmap`, or `.xml` files behind.

## Development checks

```bash
bash -n connectivity-test-zone.sh
shellcheck connectivity-test-zone.sh
shfmt -d connectivity-test-zone.sh
```
