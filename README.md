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

## SOCMINT

- 💰 [Expose Team](https://expose.team?utm_source=github.com&utm_campaign=soxoj_awesome_osint_mcp_servers) — AI-powered OSINT at lightspeed. Credit-based plans from $8/month.
- 📦🆓 [Maigret](https://github.com/BurtTheCoder/mcp-maigret) — Collect user account information from various public sources by username.
- 📦💰 [Xquik](https://github.com/Xquik-dev/x-twitter-scraper) — X (Twitter) data extraction and automation with 40+ REST API endpoints, real-time account monitoring, and trending topics. MCP server with API key auth.

## Network Scanning

- 📦🆓💰 [Shodan](https://github.com/BurtTheCoder/mcp-shodan) — Query the Shodan API and CVEDB for IP reconnaissance, DNS operations, vulnerability tracking, and device discovery. Free tier available with limited queries, requires Shodan API key.
- 📦🆓💰 [ZoomEye](https://github.com/zoomeye-ai/mcp_zoomeye) — Obtain network asset information by querying ZoomEye using dorks and other search parameters. 7-day free trial available, requires ZoomEye API key.
- 📦🆓 [DNSTwist](https://github.com/BurtTheCoder/mcp-dnstwist) — DNS fuzzing tool that helps detect typosquatting, phishing, and corporate espionage.
- 📦🆓 [OSINT Toolkit](https://www.pulsemcp.com/servers/himanshusanecha-osint-toolkit) — Unified interface for network reconnaissance with parallel execution of WHOIS, Nmap, DNS lookups, and typosquatting detection.
- 📦🆓💰 [ContrastAPI](https://github.com/UPinar/contrastapi) — Security intelligence server with 29 tools: domain recon (DNS, WHOIS, SSL, subdomains, WAF, Wayback) plus orchestrated `audit_domain`, IP reputation plus orchestrated `threat_report` (Shodan + AbuseIPDB + ASN), CVE/EPSS/KEV lookup plus `bulk_cve_lookup` (50/call), IOC enrichment plus `bulk_ioc_lookup` (50/call), threat intel, username OSINT, exploit search, and code security scanning. Free tier: 100 req/hr. Pro: 1000 req/hr with API key.

## Web Scraping

- 🆓💰 [AnySite](https://docs.anysite.io/mcp-server/overview) — Structured data access to 115+ endpoints across 40+ platforms (LinkedIn, Instagram, X, Reddit, YouTube, GitHub, Amazon, etc.) via five meta-tools. 7-day free trial with 1,000 credits.
- 📦🆓💰 [Bright Data](https://github.com/brightdata/brightdata-mcp) — Real-time web search, scraping, and structured data extraction from 60+ sources (Amazon, LinkedIn, TikTok, Google Maps, etc.) with CAPTCHA and anti-bot bypass. Free tier: 5,000 requests/month.

## Company Intelligence

- 📦🆓💰 [CompanyScope](https://github.com/Stewyboy1990/companyscope-mcp) — Company intelligence aggregating data from 8 public sources (Wikipedia, SEC EDGAR, OpenCorporates, RDAP, GitHub, and more) for corporate reconnaissance. Free tier 25 calls/day, pay-per-use tier on Apify.
- 📦🆓 [StockScope](https://github.com/Stewyboy1990/companyscope-mcp) — SEC EDGAR financial intelligence for stock research. Revenue, net income, margins, filings, and company comparisons for any US public company. Free, no API key needed.
- 📦💰 [US Business Data](https://github.com/avabuildsdata/mcp-us-business-data) — Search Secretary of State business registrations across 17 US states, building permits in 400+ cities, and Yellow Pages business leads. Returns entity details, filing status, and registered agents.

## Threat Intelligence

- 📦🆓 [VirusTotal](https://github.com/BurtTheCoder/mcp-virustotal) — Analyze URLs, files (by hash), IPs, and domains with detailed relationship mapping. Free API tier available, requires `VIRUSTOTAL_API_KEY`.

## Contributing

Contributions are welcome! Please open a pull request to add a new OSINT MCP server to the list.

## License

[MIT](LICENSE)
