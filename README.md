# recon

Automated recon pipeline for bug bounty hunters. Orchestrates your entire recon workflow from subdomain enumeration to vulnerability scanning in a single command.

```
recon -d target.com
```

---

## Installation

```bash
go install github.com/cipherKT/recon@latest
```

Requires Go 1.21 or higher.

---

## Requirements

The following tools must be installed and available in `$PATH`. recon will check for all of them at startup and tell you exactly which ones are missing.

| Tool | Install |
|------|---------|
| subfinder | `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| assetfinder | `go install github.com/tomnomnom/assetfinder@latest` |
| amass | `go install -v github.com/owasp-amass/amass/v4/...@master` |
| shuffledns | `go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest` |
| alterx | `go install -v github.com/projectdiscovery/alterx/cmd/alterx@latest` |
| dnsx | `go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest` |
| httpx | `go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| katana | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| hakrawler | `go install github.com/hakluke/hakrawler@latest` |
| naabu | `go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest` |
| nuclei | `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| subzy | `go install -v github.com/lukasikic/subzy@latest` |

---

## Usage

```bash
recon -d target.com
```

### Flags

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--domain` | `-d` | Target domain (required) | — |
| `--output` | `-o` | Output directory | `./results` |
| `--github-token` | `-g` | GitHub token for github-subdomains | `$GITHUB_TOKEN` env var |
| `--threads` | `-t` | Number of concurrent threads | `50` |

### Examples

```bash
# Basic run
recon -d target.com

# Custom output directory
recon -d target.com -o /home/user/bugbounty/results

# With GitHub token for better subdomain coverage
recon -d target.com -g ghp_yourtoken

# Using GITHUB_TOKEN env var instead
export GITHUB_TOKEN=ghp_yourtoken
recon -d target.com
```

---

## Pipeline

recon runs the following phases in order:

```
Phase 1 — Passive subdomain enumeration
          subfinder, assetfinder, amass, crt.sh, github-subdomains
          → all_subs.txt

Phase 2 — Active subdomain enumeration
          shuffledns (resolve) → alterx (permutations) → dnsx (resolve)
          → all.txt

          ↓ subzy starts in background here

Phase 3 — HTTP probing
          httpx with status code, title, tech detect, IP, web server, content length
          → httpx_alive.txt + httpx_urls.txt

Phase 4 — Crawling + Port scanning (parallel)
          katana + hakrawler → crawl_results.txt + js_files.txt
          naabu top 1000 ports → ports.txt

Phase 5 — Vulnerability scanning
          nuclei (medium, high, critical severity)
          → nuclei_results.txt

          ← subzy finishes here → takeover.txt

Phase 6 — Summary
          → summary.md
```

---

## Output

All results are saved to a timestamped directory:
```
results/
└── target.com_DD-MM-YYYY_HH-MM/
    ├── subfinder_subs.txt
    ├── assetfinder_subs.txt
    ├── amass_passive_subs.txt
    ├── crtsh_subs.txt
    ├── github_subs.txt        (only if token provided)
    ├── all_subs.txt           (merged passive results)
    ├── resolvers.txt          (latest from trickest/resolvers)
    ├── active_subs.txt        (shuffledns output)
    ├── alterx_subs.txt        (permutations)
    ├── all.txt                (final resolved subdomains)
    ├── httpx_alive.txt        (full httpx output)
    ├── httpx_urls.txt         (clean URL list)
    ├── katana_urls.txt
    ├── hakrawler_urls.txt
    ├── crawl_results.txt      (merged crawl output)
    ├── js_files.txt           (extracted JS files)
    ├── ports.txt              (naabu port scan)
    ├── nuclei_results.txt
    ├── takeover.txt           (subzy output)
    └── summary.md             (dynamic next steps)
```

---

## summary.md

At the end of every run recon generates a `summary.md` with:
- Count of subdomains, live hosts, ports, crawled URLs, JS files
- Nuclei and takeover findings with file links
- Dynamic next steps based on what was found — archive enumeration, JS analysis, parameter discovery, dir fuzzing targets

---

## Supported Platforms

- Linux
- macOS

---

## License

MIT
