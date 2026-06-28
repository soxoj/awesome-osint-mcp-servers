<div align="center">

# Awesome OSINT MCP Servers

[![Awesome](https://awesome.re/badge.svg)](https://awesome.re)

A curated list of MCP servers for OSINT (Open Source Intelligence).

An [MCP](https://modelcontextprotocol.io/) server connects tools and services to LLM systems like Claude, Cursor, Windsurf, etc.\
MCP servers simplify execution of OSINT tools by combining them with the ease of LLM querying\
and the ability to create flexible reports.

</div>

---

Legend: 📦 Open Source &nbsp;&middot;&nbsp; 🆓 Free / Has Free Tier &nbsp;&middot;&nbsp; 💰 Paid / Requires Paid API

## Contents

- [SOCMINT](#socmint)
- [Network Scanning](#network-scanning)
- [Web Scraping](#web-scraping)
- [Company Intelligence](#company-intelligence)
- [Threat Intelligence](#threat-intelligence)
- [Research Intelligence](#research-intelligence)
- [Meta / Discovery](#meta--discovery)
- [Blockchain Intelligence](#blockchain-intelligence)
- [Market & Trading](#market--trading)

## SOCMINT

- 💰 [Expose Team](https://expose.team?utm_source=github.com&utm_campaign=soxoj_awesome_osint_mcp_servers) — AI-powered OSINT at lightspeed. Credit-based plans from $8/month.
- 📦🆓 [Maigret](https://github.com/BurtTheCoder/mcp-maigret) — Collect user account information from various public sources by username.
- 📦💰 [Xquik](https://github.com/Xquik-dev/x-twitter-scraper) — X (Twitter) data extraction and automation with 40+ REST API endpoints, real-time account monitoring, and trending topics. MCP server with API key auth.

## Network Scanning

- 📦🆓💰 [Shodan](https://github.com/BurtTheCoder/mcp-shodan) — Query the Shodan API and CVEDB for IP reconnaissance, DNS operations, vulnerability tracking, and device discovery. Free tier available with limited queries, requires Shodan API key.
- 📦🆓💰 [ZoomEye](https://github.com/zoomeye-ai/mcp_zoomeye) — Obtain network asset information by querying ZoomEye using dorks and other search parameters. 7-day free trial available, requires ZoomEye API key.
- 📦🆓 [DNSTwist](https://github.com/BurtTheCoder/mcp-dnstwist) — DNS fuzzing tool that helps detect typosquatting, phishing, and corporate espionage.
- 📦🆓 [OSINT Toolkit](https://www.pulsemcp.com/servers/himanshusanecha-osint-toolkit) — Unified interface for network reconnaissance with parallel execution of WHOIS, Nmap, DNS lookups, and typosquatting detection.
- 📦🆓💰 [ContrastAPI](https://github.com/UPinar/contrastapi) — Security intelligence server with 49 tools: domain recon (DNS, WHOIS, SSL, subdomains, WAF, Wayback) plus orchestrated `audit_domain`, IP reputation plus orchestrated `threat_report` (Shodan + AbuseIPDB + ASN), CVE/EPSS/KEV lookup plus `calculate_risk_score` (CVSS+EPSS+KEV+PoC fusion) and `bulk_cve_lookup` (50/call), `cve_leading` (MITRE/GHSA pre-NVD), IOC enrichment plus `bulk_ioc_lookup` (50/call), threat intel, MITRE ATLAS (167 AI/ML attack techniques + bulk drill) and D3FEND defenses (149 techniques + coverage report), web intelligence (robots.txt, redirect chain, email validation, brand assets, SEO audit), `check_dependencies` (requirements.txt / package.json audit), and code security scanning. Anonymous tier + Pro tier with API key.
- 🆓💰 [DomScan](https://domscan.net) — Domain intelligence with DNS, WHOIS/RDAP, SSL/TLS, subdomain enumeration, certificate search, typosquatting and brand monitoring, plus domain valuation and availability. One API and MCP server; free tools with paid API tiers.

## Web Scraping

- 🆓💰 [AnySite](https://docs.anysite.io/mcp-server/overview) — Structured data access to 115+ endpoints across 40+ platforms (LinkedIn, Instagram, X, Reddit, YouTube, GitHub, Amazon, etc.) via five meta-tools. 7-day free trial with 1,000 credits.
- 📦🆓💰 [Bright Data](https://github.com/brightdata/brightdata-mcp) — Real-time web search, scraping, and structured data extraction from 60+ sources (Amazon, LinkedIn, TikTok, Google Maps, etc.) with CAPTCHA and anti-bot bypass. Free tier: 5,000 requests/month.

## Company Intelligence

- 📦🆓💰 [CompanyScope](https://github.com/Stewyboy1990/companyscope-mcp) — Company intelligence aggregating data from 8 public sources (Wikipedia, SEC EDGAR, OpenCorporates, RDAP, GitHub, and more) for corporate reconnaissance. Free tier 25 calls/day, pay-per-use tier on Apify.
- 📦🆓 [StockScope](https://github.com/Stewyboy1990/companyscope-mcp) — SEC EDGAR financial intelligence for stock research. Revenue, net income, margins, filings, and company comparisons for any US public company. Free, no API key needed.
- 📦💰 [US Business Data](https://github.com/avabuildsdata/mcp-us-business-data) — Search Secretary of State business registrations across 17 US states, building permits in 400+ cities, and Yellow Pages business leads. Returns entity details, filing status, and registered agents.
- 🆓💰 [OpenRegistry](https://github.com/sophymarine/openregistry) — Real-time access to 27 national corporate registries worldwide (UK Companies House, France Sirene, Germany Handelsregister, South Korea OPENDART, Australia ABR, Canada Corporations, etc.) via a unified JSON schema. Returns company profiles, officers, shareholders, beneficial ownership, filings, and raw documents. Free tier: 20 rpm without signup, 30 rpm with email. Paid up to $29/mo. OAuth 2.1, no API keys.
- 📦💰 [Checko MCP](https://github.com/Nymaxxx/checko-mcp) — Unofficial wrapper for the Russian Checko.ru API: verify counterparties (companies, sole proprietors, individuals) via EGRUL/EGRIP, arbitration cases, government contracts (44-FZ/223-FZ), Rosstat financials, inspections, Fedresurs and EFRSB bankruptcy records. 12 tools and 6 ready-made workflow prompts. Requires paid `CHECKO_API_KEY`.

## Threat Intelligence

- 📦🆓 [VirusTotal](https://github.com/BurtTheCoder/mcp-virustotal) — Analyze URLs, files (by hash), IPs, and domains with detailed relationship mapping. Free API tier available, requires `VIRUSTOTAL_API_KEY`.
- 📦🆓 [Voidly](https://www.npmjs.com/package/@voidly/mcp-server) — Global internet censorship intelligence: 116 tools across 119+ countries. Query OONI / IODA / CensoredPlanet evidence, look up 5,356 citable incidents, check if a domain or service is blocked in a country, fetch ISP-level risk scores, run ML-driven shutdown forecasts, and verify censorship claims. Free, no API key needed for read endpoints. `npx @voidly/mcp-server`.
- 📦🆓 [OpenOSINT](https://github.com/OpenOSINT/OpenOSINT) — AI-powered OSINT agent with interactive REPL, MCP server, and CLI.

## Research Intelligence

- 📦🆓💰 [BGPT MCP](https://github.com/connerlambden/bgpt-mcp) — Scientific paper search with structured full-text evidence: methods, sample sizes, results, limitations, quality scores, and falsification prompts. Useful for claim verification and literature OSINT. Remote MCP + REST. Free tier: 50 results. [docs](https://bgpt.pro/mcp/) · MCP: https://bgpt.pro/mcp/sse

## Meta / Discovery

- 🆓 [Not Human Search](https://nothumansearch.ai) — Agent-first discovery engine for MCP servers. Search, score, and live-probe (`verify_mcp`) 8,600+ servers via JSON-RPC or REST API. Useful for pivoting between OSINT MCP tools. MCP: https://nothumansearch.ai/mcp

## Blockchain Intelligence

- 💰 [TWZRD Agent Intel](https://intel.twzrd.xyz) — Blockchain OSINT for AI agent trust scoring — reads public Solana on-chain data (wallet history, transaction patterns) to score agent trustworthiness. Free preflight + paid signed V5 trust receipts via x402 micropayments. MCP: https://intel.twzrd.xyz/mcp
- 💰 [The Stall](https://github.com/thebrierfox/the-stall) — Multi-tool blockchain OSINT server: OFAC sanctions screening (19,000+ SDN entries, fuzzy name match + AKA aliases), wallet risk scoring, agent KYA trust scoring, EVM and Solana transaction intelligence, and token security analysis. Pay-per-call via x402 USDC micropayments on Base — no accounts or API keys. MCP: https://the-stall.intuitek.ai/mcp

## Market & Trading

- 📦🆓💰 [Helium MCP](https://github.com/connerlambden/helium-mcp) — 37-dimensional news bias scoring across 216 sources, market data, and ML options pricing. Remote MCP + REST. [Demo](https://connerlambden.github.io/helium-news-explorer/) · [docs](https://heliumtrades.com/mcp-page/)

## Contributing

Contributions are welcome! Please open a pull request to add a new OSINT MCP server to the list.

## License

[MIT](LICENSE)
