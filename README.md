# connectivity-test-zone

`connectivity-test-zone` enumerates DNS subdomains for one or more target domains,
resolves each hostname, tests selected TCP ports, collects TLS certificate
metadata from discovered services, and emits JSON-first results for authorized
asset inventory and security assessment evidence collection.

## Responsible use

Use this tool only for authorized security testing, asset inventory, and network
administration. See [DISCLAIMER.md](DISCLAIMER.md) for details.

## What it does

- Runs `subfinder` for the supplied domain or each domain in a supplied text file.
- Includes each supplied domain itself in the connectivity scan, even when no
  subdomains are discovered.
- Optionally brute-forces DNS names with `dnsx` and a supplied wordlist, then
  merges those results with `subfinder` output.
- Optionally enumerates HTTP virtual hosts, then merges those results with the
  other discovered names.
- Resolves each hostname before scanning.
- Skips `nmap` for unresolved names.
- Tests selected TCP ports with `nmap`.
- Optionally runs nmap service/version detection with `-sV --version-light`.
- Optionally runs safe/default NSE scripts and stores structured script output.
- Attempts a TLS handshake on each open port and records discovered certificate
  metadata.
- Optionally collects HTTP response evidence, including selected headers, page
  title, redirects, and advisory security header assessments.
- Optionally runs `wafw00f` against open HTTP/HTTPS endpoints and records WAF
  detection results.
- Optionally runs `nuclei` against discovered HTTP/HTTPS endpoints and stores
  JSONL findings as hypotheses requiring validation.
- Optionally runs OWASP ZAP baseline scans through Docker and stores passive
  scanner alerts as hypotheses requiring validation.
- Adds advisory `prioritization_hints` for downstream report generation.
- Optionally queries ipinfo.io Lite for geolocation, ASN, and ISP/organization
  metadata for each resolved target IP.
- Optionally queries RDAP registration data for each supplied DNS zone using the
  IANA RDAP bootstrap.
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
  "registration": {
    "registrar_whois_server": "whois.namecheap.com",
    "registrar_url": "http://www.namecheap.com",
    "updated_date": "2026-07-01T08:35:27Z",
    "creation_date": "2026-07-01T08:35:27Z",
    "expiration_date": "2027-07-01T08:35:27Z",
    "registrar": "NAMECHEAP INC",
    "registrant_name": "Redacted for Privacy",
    "registrant_organization": "Withheld for Privacy ehf",
    "registrant_street": "Kalkofnsvegur 2",
    "registrant_city": "Reykjavik",
    "registrant_state_province": "Capital Region",
    "registrant_postal_code": "101",
    "registrant_country": "IS",
    "registrant_phone": "+354.4212434"
  },
  "results": [
    {
      "target": "api.example.com",
      "ipaddress": "192.0.2.20",
      "resolved": true,
      "connected": true,
      "ports": [80, 443],
      "services": [
        {
          "port": 443,
          "protocol": "tcp",
          "state": "open",
          "name": "https",
          "product": "nginx",
          "version": "1.24.0",
          "extrainfo": null,
          "tunnel": "ssl",
          "confidence": "10"
        }
      ],
      "tls_certificates": [
        {
          "ports": [443],
          "issuer": "commonName=Example Issuer",
          "subject": "commonName=api.example.com",
          "thumbprint": "C1F4A64C8D2D3B7A2F4B1F2D5F63A1B9E1D0B938254F0B7C8A9D123456789ABC",
          "expiration": "December 15, 2026 at 11:59:59 PM UTC",
          "expired": false,
          "expires_soon": false,
          "days_until_expiration": 167
        }
      ],
      "http": {
        "checked": true,
        "endpoints": [
          {
            "url": "https://api.example.com",
            "port": 443,
            "reachable": true,
            "status_code": 200,
            "final_url": "https://api.example.com/login",
            "title": "Login",
            "server": "nginx",
            "headers": {
              "strict-transport-security": "max-age=31536000",
              "content-security-policy": null,
              "x-frame-options": "DENY",
              "x-content-type-options": "nosniff",
              "referrer-policy": "same-origin",
              "permissions-policy": null,
              "cross-origin-opener-policy": null,
              "cross-origin-embedder-policy": null,
              "cross-origin-resource-policy": null,
              "access-control-allow-origin": null,
              "access-control-allow-credentials": null,
              "cache-control": "no-store",
              "x-powered-by": null
            },
            "security_headers": {
              "content_security_policy": {
                "present": false,
                "value": null,
                "assessment": "missing",
                "recommendation": "Consider implementing a Content-Security-Policy."
              }
            },
            "security_header_summary": {
              "score": 8,
              "max_score": 12,
              "rating": "Good",
              "missing_headers": ["Content-Security-Policy", "Permissions-Policy"]
            },
            "security_header_findings": [
              {
                "category": "HTTP Security Headers",
                "severity_hint": "low",
                "title": "Content-Security-Policy header is missing",
                "target": "https://api.example.com",
                "port": 443,
                "evidence": {
                  "header": "Content-Security-Policy"
                },
                "recommendation": "Consider implementing a Content-Security-Policy."
              }
            ],
            "error": null
          }
        ]
      },
      "waf": {
        "checked": true,
        "detected": true,
        "products": ["Example WAF"],
        "endpoints": [
          {
            "url": "https://api.example.com",
            "port": 443,
            "checked": true,
            "detected": true,
            "products": ["Example WAF"]
          }
        ]
      },
      "nse": [
        {
          "port": 443,
          "script_id": "http-title",
          "output": "Example App"
        }
      ],
      "host_nse": [],
      "ipinfo": {
        "ip": "192.0.2.20",
        "asn": "AS64496",
        "as_name": "Example ISP, Inc.",
        "as_domain": "example.net",
        "country_code": "US",
        "country": "United States",
        "continent_code": "NA",
        "continent": "North America"
      }
    }
  ],
  "nuclei": {
    "checked": true,
    "severities": "info,low,medium,high,critical",
    "findings": [
      {
        "template_id": "example-template",
        "name": "Example Finding",
        "severity": "info",
        "matched_at": "https://api.example.com",
        "host": "api.example.com",
        "port": "443",
        "type": "http",
        "raw": {}
      }
    ],
    "errors": []
  },
  "zap": {
    "checked": true,
    "mode": "baseline-passive",
    "image": "ghcr.io/zaproxy/zaproxy:stable",
    "spider_minutes": 1,
    "timeout_minutes": 5,
    "max_endpoints": 10,
    "findings": [
      {
        "target": "https://api.example.com",
        "mode": "baseline-passive",
        "alerts": [
          {
            "target": "https://api.example.com",
            "plugin_id": "10020",
            "alert": "X-Frame-Options Header Not Set",
            "risk": "Medium",
            "confidence": "Medium",
            "instances_count": 1,
            "raw": {}
          }
        ],
        "errors": [],
        "exit_code": 0
      }
    ],
    "errors": []
  },
  "prioritization_hints": [
    {
      "target": "https://api.example.com",
      "port": 443,
      "severity_hint": "low",
      "category": "HTTP Security Headers",
      "reason": "Content-Security-Policy header is missing; requires validation.",
      "validation": "Confirm application context before reporting."
    }
  ],
  "tool_metadata": {
    "schema_version": "2.0",
    "features_enabled": {
      "service_version": true,
      "nse": true,
      "http_evidence": true,
      "nuclei": true,
      "zap": true
    }
  }
}
```

## Dependencies

- `dnsx` when using `--wordlist`
- `gobuster` when using `--vhosts` or `--vhost-wordlist`
- `wafw00f` when using `--waf`
- `whois` when using `--whois`
- `nuclei` when using `--nuclei`
- `docker` when using `--zap`
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
brew install gobuster jq nmap pipx shellcheck shfmt
```

Install `subfinder` with Go:

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

Install `dnsx` with Go:

```bash
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
```

Install `nuclei` with Go if you plan to use `--nuclei`:

```bash
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

Install Docker Desktop and pull the ZAP stable image if you plan to use
`--zap`:

```bash
brew install --cask docker
docker pull ghcr.io/zaproxy/zaproxy:stable
```

Ensure your Go binary path is on `PATH`. A common setup is:

```bash
export PATH="$PATH:$HOME/go/bin"
```

Install `wafw00f` if you plan to use `--waf`:

```bash
pipx install wafw00f
```

## Linux installation

On Debian/Ubuntu, install common packages with:

```bash
sudo apt update
sudo apt install -y gobuster jq nmap pipx python3 sed grep coreutils findutils
```

Install `subfinder` with Go:

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

Install `dnsx` with Go:

```bash
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
```

Install `nuclei` with Go if you plan to use `--nuclei`:

```bash
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

Install Docker and pull the ZAP stable image if you plan to use `--zap`:

```bash
sudo apt install -y docker.io
sudo systemctl enable --now docker
docker pull ghcr.io/zaproxy/zaproxy:stable
```

Ensure your Go binary path is on `PATH`. A common setup is:

```bash
export PATH="$PATH:$HOME/go/bin"
```

Install `wafw00f` if you plan to use `--waf`:

```bash
pipx install wafw00f
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
                          Default: default,safe
  -he, --http-evidence    Collect basic HTTP response evidence and advisory
                          security header assessments.
  --http-timeout          HTTP request timeout in seconds.
                          Default: 10
  -nu, --nuclei           Run nuclei against discovered HTTP/HTTPS endpoints.
  --nuclei-severities     Nuclei severities to include.
                          Default: info,low,medium,high,critical
  --nuclei-templates      Optional nuclei template path.
  -zap, --zap             Run OWASP ZAP baseline scan through Docker against
                          discovered HTTP/HTTPS endpoints.
  --zap-image             Docker image for ZAP baseline scans.
                          Default: ghcr.io/zaproxy/zaproxy:stable
  --zap-spider-minutes    Minutes for ZAP baseline spidering per endpoint.
                          Default: 1
  --zap-timeout-minutes   Max minutes to wait for each ZAP baseline scan.
                          Default: 5
  --zap-max-endpoints     Maximum HTTP/HTTPS endpoints to scan with ZAP.
                          Default: 10
  --rate-delay            Delay in seconds between optional evidence requests.
                          Default: 0
  -p,  --ports            Comma-separated ports to test
                          Default: 20,21,22,23,25,53,80,88,111,135,139,389,443,445,464,593,636,1433,1521,2049,2379,2380,3268,3269,3306,3389,5432,5672,5900,5985,5986,6379,6443,8000,8080,8081,8433,8443,9000,9200,9389,10250,27017
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
./connectivity-test-zone.sh --domain example.com --waf
./connectivity-test-zone.sh -d example.com -wf
./connectivity-test-zone.sh --domain example.com --ipinfo
./connectivity-test-zone.sh -d example.com -ii
./connectivity-test-zone.sh --domain example.com --whois
./connectivity-test-zone.sh -d example.com -wi
./connectivity-test-zone.sh -d example.com -oj -sv -he
./connectivity-test-zone.sh -d example.com -oj -sv --nse --nse-scripts "default,safe"
./connectivity-test-zone.sh -d example.com -oj -sv -he -nu
./connectivity-test-zone.sh -d example.com -oj -sv -he -nu -zap
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
TLS certificate collection is automatic for any open port in the selected port
list that accepts a TLS handshake.

Use `--domains-file` or `-df` to read root domains from a text file, one domain
per line. Empty lines are ignored. If the file does not exist, the script exits
with an error before scanning. Each listed domain is included as a scan target
alongside any discovered subdomains.

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

Use `--waf` or `-wf` to run `wafw00f` against open HTTP/HTTPS endpoints found by
the port scan. This is opt-in because it adds an additional request-driven check
per web endpoint and can noticeably increase runtime on large target sets.

Use `--ipinfo` or `-ii` to query ipinfo.io Lite for each resolved target IP and
add an `ipinfo` object to that target's JSON result. This is opt-in because it
sends discovered target IPs to ipinfo.io and requires an API key.

Set the API key in the `IPINFO_API_KEY` environment variable before running:

```bash
export IPINFO_API_KEY="<your ipinfo.io API key>"
```

For regular use, prefer loading the variable from secure storage instead of
leaving the key in shell history or dotfiles. On Linux desktops, store and read
it with Secret Service tools such as `secret-tool`. On macOS, store it in
Keychain and read it with the `security` command.

If `--ipinfo` is present but `IPINFO_API_KEY` is not set, the script prints a
yellow warning near startup and omits `ipinfo` from the JSON output.

Use `--whois` or `-wi` to add registration data for each supplied DNS zone. The
script downloads `https://data.iana.org/rdap/dns.json`, selects the authoritative
RDAP endpoint for the domain suffix, and requests the domain registration object
from that endpoint. If RDAP omits requested fields, the script falls back to the
local `whois` command, first with the default registry lookup and then with the
referred registrar WHOIS server when one is available. RDAP and WHOIS responses
may still omit registrant contact fields or replace them with privacy/redaction
values, depending on registry and registrar policy.
Registrar WHOIS referrals that are returned as URLs, such as
`https://whois.trustname.com/`, are normalized to hostnames before querying port
43.

## Pentest evidence collection

All pentest-oriented evidence features are opt-in and intended for authorized
testing only. They collect structured observations for analyst review and
downstream report generation. They do not perform automatic exploitation,
credential attacks, payload delivery, persistence, evasion, or
post-exploitation.

Use `--service-version` or `-sv` to add nmap service/version evidence with
`-sV --version-light`. The selected port list is preserved, unresolved hosts are
still skipped, and each result gets a `services` array keyed by open port.

Use `--nse` to run nmap NSE scripts. The default script set is `default,safe`.
Use `--nse-scripts "default,safe"` to override the set explicitly. Do not use
intrusive, brute, dos, or vuln script categories unless the scope owner has
explicitly authorized that activity.

Use `--http-evidence` or `-he` to perform a conservative GET request against
discovered HTTP/HTTPS endpoints. The script records reachability, status code,
final URL, page title, selected headers, and request errors. `--http-timeout 10`
controls the per-request timeout. HTTP status codes such as 401, 403, and 404
are treated as reachable responses, not script failures.

HTTP evidence automatically includes an advisory security header assessment.
The score is a convenience signal for reporting workflow triage only; it is not
an industry standard, certification, or proof of vulnerability. Missing or weak
headers are reported as hardening opportunities requiring analyst review.

Use `--nuclei` or `-nu` to run `nuclei` against discovered HTTP/HTTPS endpoints.
The default severities are `info,low,medium,high,critical`; override them with
`--nuclei-severities`. Use `--nuclei-templates ./templates` to point at a
specific template path. Nuclei findings are hypotheses and may be false
positives; validate them manually before reporting.

Use `--zap` or `-zap` to run OWASP ZAP baseline scans through Docker against
discovered HTTP/HTTPS endpoints. This uses the ZAP Docker packaged baseline
scan, which spiders briefly and waits for passive scanning. It does not perform
active attacks. ZAP findings are passive scanner observations and may be false
positives; validate them manually before reporting.

Useful ZAP controls:

```console
./connectivity-test-zone.sh -d example.com -oj -sv -he -zap
./connectivity-test-zone.sh -d example.com -oj -sv -he -zap \
  --zap-max-endpoints 3
./connectivity-test-zone.sh -d example.com -oj -sv -he -zap \
  --zap-spider-minutes 2
```

Use `--rate-delay 1` to add a delay between optional request-oriented checks.
This can reduce burstiness on large target sets.

Sample evidence commands:

```console
./connectivity-test-zone.sh -d example.com -oj -sv -he
./connectivity-test-zone.sh -d example.com -oj -sv --nse --nse-scripts "default,safe"
./connectivity-test-zone.sh -d example.com -oj -sv -he -nu
./connectivity-test-zone.sh -d example.com -oj -sv -he -nu -zap
```

Sample HTTP evidence excerpt:

```json
{
  "http": {
    "checked": true,
    "endpoints": [
      {
        "url": "https://api.example.com",
        "port": 443,
        "reachable": true,
        "status_code": 200,
        "final_url": "https://api.example.com/login",
        "title": "Login",
        "server": "nginx",
        "headers": {
          "strict-transport-security": "max-age=31536000",
          "content-security-policy": null,
          "x-frame-options": "DENY",
          "x-content-type-options": "nosniff",
          "referrer-policy": "same-origin",
          "x-powered-by": null
        },
        "security_header_summary": {
          "score": 8,
          "max_score": 12,
          "rating": "Good",
          "missing_headers": ["Content-Security-Policy", "Permissions-Policy"]
        }
      }
    ]
  }
}
```

## Permissions

The script uses `nmap -sS` when run as root and `nmap -sT` otherwise.

## Output

Each result includes `services`. Without `--service-version`, this contains the
basic service names nmap infers from the selected ports when available. With
`--service-version`, entries may also include `product`, `version`,
`extrainfo`, `tunnel`, and nmap confidence values. NSE port script output is
stored in the target-level `nse` array and, when associated with a service, on
that service entry as `nse`. Host-level NSE scripts are stored in `host_nse`.

Each result includes `tls_certificates`. The script attempts a direct TLS
handshake against every open port found by `nmap`, accepts untrusted/self-signed
certificates for inventory purposes, and deduplicates identical certificates by
thumbprint. Each certificate object contains `ports`, `issuer`, `subject`,
`subject_alternative_names`, `thumbprint`, `expiration`, `expired`,
`expires_soon`, and `days_until_expiration`.

`ports` lists every open port where that certificate was observed.
`subject_alternative_names` lists the DNS names from the certificate's Subject
Alternative Name extension.

`thumbprint` is the SHA-256 digest of the DER-encoded certificate, rendered as
uppercase hexadecimal. `expiration` is rendered in UTC as a readable string such
as `December 15, 2026 at 11:59:59 PM UTC`. `expired` is `true` when the
certificate expiration timestamp is earlier than the scan time.

If a target does not resolve, has no open ports, or none of its open ports accept
a TLS handshake, `tls_certificates` is an empty array.

Each result includes `http`. When `--http-evidence` is not used, `http.checked`
is `false` and `http.endpoints` is empty. When enabled, endpoint entries contain
request evidence, selected response headers, `security_headers`,
`security_header_summary`, and `security_header_findings`. These findings are
advisory hardening observations and should not be treated as confirmed
vulnerabilities solely because a header is absent.

Each result includes `waf`. When `--waf` is not used, `waf.checked` is `false`
and `waf.endpoints` is empty. When `--waf` is used, the script checks open ports
that commonly serve HTTP or HTTPS, records each checked endpoint URL, and sets
`waf.detected` to `true` if `wafw00f` detects a WAF. If `wafw00f` detects a WAF
and reports both a WAF name and manufacturer, products are rendered as
`Name (Manufacturer)`, such as `Cloudfront (Amazon)`. If `wafw00f` detects a WAF
but does not identify a product, the script uses the endpoint's HTTP `Server`
response header as a product fallback when that header is available, otherwise
it records `unknown`. Endpoint entries with `checked: false` are inconclusive
rather than a negative WAF result. Endpoint `url` values include the scheme and
hostname; the `port` field carries the port number.

When `--ipinfo` is used with `IPINFO_API_KEY` set, resolved targets may include
an `ipinfo` object with the response returned by the ipinfo.io Lite API, such as
`ip`, `asn`, `as_name`, `as_domain`, `country_code`, `country`,
`continent_code`, and `continent`. If the key is missing, the field is omitted.

When `--whois` is used, single-domain runs include a top-level `registration`
object. File-based runs with more than one domain include a top-level
`registrations` object keyed by domain. RDAP values are used first, registry
WHOIS values fill missing fields, and referred registrar WHOIS values replace
earlier values when available. The registration object contains
`registrar_whois_server`, `registrar_url`, `updated_date`, `creation_date`,
`expiration_date`, `registrar`, `registrant_name`, `registrant_organization`,
`registrant_street`, `registrant_city`, `registrant_state_province`,
`registrant_postal_code`, `registrant_country`, and `registrant_phone`. Missing
or redacted values are represented as `null`.

Top-level `nuclei` contains `checked`, `severities`, normalized `findings`, and
`errors`. The full raw nuclei JSON object is preserved under each finding's
`raw` field.

Top-level `zap` contains `checked`, baseline scan settings, per-endpoint
`findings`, and `errors`. Each endpoint finding includes normalized passive
alerts and preserves each raw ZAP alert under `raw`.

Top-level `prioritization_hints` contains report-friendly observations such as
externally reachable administrative services, HTTP security header hardening
opportunities, TLS certificate expiration concerns, nuclei/ZAP findings that
require validation, and service version evidence that may need patch validation.

Top-level `tool_metadata` contains `schema_version`, enabled features, selected
option values, and safety notes for downstream report agents.

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
