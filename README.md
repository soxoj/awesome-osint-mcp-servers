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
- [Public Records & Compliance](#public-records--compliance)
- [Threat Intelligence](#threat-intelligence)
- [Geospatial & Geopolitical Intelligence](#geospatial--geopolitical-intelligence)
- [Research Intelligence](#research-intelligence)
- [Meta / Discovery](#meta--discovery)
- [Blockchain Intelligence](#blockchain-intelligence)
- [Market & Trading](#market--trading)

## SOCMINT

- 💰 [Expose Team](https://expose.team?utm_source=github.com&utm_campaign=soxoj_awesome_osint_mcp_servers) — AI-powered OSINT at lightspeed. Credit-based plans from $8/month.
- 📦🆓 [Maigret](https://github.com/BurtTheCoder/mcp-maigret) — Collect user account information from various public sources by username.
- 📦💰 [Xquik](https://github.com/Xquik-dev/x-twitter-scraper) — X (Twitter) data extraction and automation with 40+ REST API endpoints, real-time account monitoring, and trending topics. MCP server with API key auth.
- 📦🆓 [OSINT Tools MCP](https://github.com/frishtik/osint-tools-mcp-server) — Wraps seven classic OSINT CLIs behind one server: Sherlock and Blackbird (usernames), Maigret, Holehe (email), GHunt (Google accounts), theHarvester (domains) and SpiderFoot. Python, installs the underlying tools itself.
- 📦🆓 [LinkedIn MCP](https://github.com/eliasbiondo/linkedin-mcp-server) — Search LinkedIn people, companies and jobs, and pull structured profile, company and post data. Uses your own session cookie; no API key.
- 🆓💰 [BulkTranscripts](https://github.com/pratie/bulktranscripts-mcp) — YouTube channel uploads, in-channel topic search, and full transcripts as clean text. `get_latest_videos` is unmetered — poll it to watch a subject's channel and spend credits only on what is new. Hosted, 7 tools, no signup; 30 free credits shared per public IP, then one-time packs. MCP: https://bulktranscripts.co/mcp

## Network Scanning

- 📦🆓💰 [Shodan](https://github.com/BurtTheCoder/mcp-shodan) — Query the Shodan API and CVEDB for IP reconnaissance, DNS operations, vulnerability tracking, and device discovery. Free tier available with limited queries, requires Shodan API key.
- 📦🆓💰 [ZoomEye](https://github.com/zoomeye-ai/mcp_zoomeye) — Obtain network asset information by querying ZoomEye using dorks and other search parameters. 7-day free trial available, requires ZoomEye API key.
- 📦🆓 [DNSTwist](https://github.com/BurtTheCoder/mcp-dnstwist) — DNS fuzzing tool that helps detect typosquatting, phishing, and corporate espionage.
- 📦🆓 [OSINT Toolkit](https://www.pulsemcp.com/servers/himanshusanecha-osint-toolkit) — Unified interface for network reconnaissance with parallel execution of WHOIS, Nmap, DNS lookups, and typosquatting detection.
- 📦🆓💰 [ContrastAPI](https://github.com/UPinar/contrastapi) — Security intelligence server with 49 tools: domain recon (DNS, WHOIS, SSL, subdomains, WAF, Wayback) plus orchestrated `audit_domain`, IP reputation plus orchestrated `threat_report` (Shodan + AbuseIPDB + ASN), CVE/EPSS/KEV lookup plus `calculate_risk_score` (CVSS+EPSS+KEV+PoC fusion) and `bulk_cve_lookup` (50/call), `cve_leading` (MITRE/GHSA pre-NVD), IOC enrichment plus `bulk_ioc_lookup` (50/call), threat intel, MITRE ATLAS (167 AI/ML attack techniques + bulk drill) and D3FEND defenses (149 techniques + coverage report), web intelligence (robots.txt, redirect chain, email validation, brand assets, SEO audit), `check_dependencies` (requirements.txt / package.json audit), and code security scanning. Anonymous tier + Pro tier with API key.
- 🆓💰 [DomScan](https://domscan.net) — Domain intelligence with DNS, WHOIS/RDAP, SSL/TLS, subdomain enumeration, certificate search, typosquatting and brand monitoring, plus domain valuation and availability. One API and MCP server; free tools with paid API tiers.
- 🆓💰 [CrawlGraph](https://github.com/pucilpet/crawlgraph-mcp) — Passive web footprinting via the Common Crawl webgraph - mapping which sites reference a target, without ever touching the target (passive, no active scanning). Two tools for OSINT research: inbound linking to target and link-gap between two or more targets. `npx -y crawlgraph-mcp`. Free sign up for 15 targets/mo ; paid lifetime API for higher limits and link-gap research.
- 🆓💰 [DomainKits](https://domainkits.com/dev?utm_source=github&utm_campaign=awesome-osint-mcp) — Search newly registered, expired, and dropped domains across gTLDs for phishing, typosquatting, and brand-impersonation monitoring, with WHOIS, DNS, reverse-nameserver, IP geolocation, and Google Safe Browsing lookups. Requires paid API key.
- 📦🆓 [IPInfo](https://github.com/briandconnelly/mcp-server-ipinfo) — IP geolocation, ASN and network details, Tor exit-node checks, and interactive maps for sets of IPs via ipinfo.io. Free API token required.
- 📦💰 [StackScan](https://github.com/stackscan/stackscan-mcp) — Technographic lookups over 360M+ sites: what a domain is built on, who is behind it (industry, city, country, LinkedIn), and how many sites run a given technology and where. Batch domain lookup for list enrichment. Local stdio server, MIT, `npx -y @stackscan/mcp-server`. Charged per resolving domain; misses are not charged and `check_credits` is free.

## Web Scraping

- 🆓💰 [AnySite](https://docs.anysite.io/mcp-server/overview) — Structured data access to 115+ endpoints across 40+ platforms (LinkedIn, Instagram, X, Reddit, YouTube, GitHub, Amazon, etc.) via five meta-tools. 7-day free trial with 1,000 credits.
- 📦🆓💰 [Bright Data](https://github.com/brightdata/brightdata-mcp) — Real-time web search, scraping, and structured data extraction from 60+ sources (Amazon, LinkedIn, TikTok, Google Maps, etc.) with CAPTCHA and anti-bot bypass. Free tier: 5,000 requests/month.
- 🆓💰 [Parallel Search MCP](https://docs.parallel.ai/integrations/mcp/search-mcp) — Web search and page-content extraction (`web_search`, `web_fetch`) for LLM agents. Default endpoint works without an API key; an account with credits is needed for production rate limits. MCP: https://search.parallel.ai/mcp
- 📦🆓 [Wayback Machine MCP](https://github.com/Mearman/mcp-wayback-machine) — Query and save Internet Archive snapshots: check archive status, fetch archived URLs, search the CDX index, and compare two snapshots of a page. No API key for reads. `npx -y mcp-wayback-machine`

## Company Intelligence

- 📦🆓💰 [CompanyScope](https://github.com/Stewyboy1990/companyscope-mcp) — Company intelligence aggregating data from 8 public sources (Wikipedia, SEC EDGAR, OpenCorporates, RDAP, GitHub, and more) for corporate reconnaissance. Free tier 25 calls/day, pay-per-use tier on Apify.
- 📦🆓 [StockScope](https://github.com/Stewyboy1990/companyscope-mcp) — SEC EDGAR financial intelligence for stock research. Revenue, net income, margins, filings, and company comparisons for any US public company. Free, no API key needed.
- 🆓💰 [FilingFirehose](https://filingfirehose.com/mcp) — Hosted SEC EDGAR MCP for any US ticker: 8-K body-text parsing (catches buried items beyond what the filer reported), 10-K / 10-Q / S-3 / Schedule 13D reads, forensic risk scoring (LOW/MODERATE/ELEVATED/HIGH), and cyber-incident tracking. Free public endpoints + paid tiers from $9/mo. MCP: https://filingfirehose.com/mcp
- 📦💰 [US Business Data](https://github.com/avabuildsdata/mcp-us-business-data) — Search Secretary of State business registrations across 17 US states, building permits in 400+ cities, and Yellow Pages business leads. Returns entity details, filing status, and registered agents.
- 🆓💰 [OpenRegistry](https://github.com/sophymarine/openregistry) — Real-time access to 27 national corporate registries worldwide (UK Companies House, France Sirene, Germany Handelsregister, South Korea OPENDART, Australia ABR, Canada Corporations, etc.) via a unified JSON schema. Returns company profiles, officers, shareholders, beneficial ownership, filings, and raw documents. Free tier: 20 rpm without signup, 30 rpm with email. Paid up to $29/mo. OAuth 2.1, no API keys.
- 📦💰 [Checko MCP](https://github.com/Nymaxxx/checko-mcp) — Unofficial wrapper for the Russian Checko.ru API: verify counterparties (companies, sole proprietors, individuals) via EGRUL/EGRIP, arbitration cases, government contracts (44-FZ/223-FZ), Rosstat financials, inspections, Fedresurs and EFRSB bankruptcy records. 12 tools and 6 ready-made workflow prompts. Requires paid `CHECKO_API_KEY`.
- 🆓 [Fylings](https://github.com/HeyZod/fylings-mcp) — African company intelligence across 18+ official national registries (Nigeria's CAC, Tanzania's BRELA, Mauritius's CBRD, Senegal's RCCM, and more) via a unified schema, with the official registry source and a last-verified date on every record. Company search & verification, beneficial ownership, government-contract awards, and sanctions screening. Free, no API key. Hosted MCP: https://www.fylings.com/api/mcp
- 📦🆓 [Companies House MCP](https://github.com/stefanoamorelli/companies-house-mcp) — 38 tools over the UK Companies House API: company and officer search, profiles, filing history and documents, charges, insolvency, PSC/beneficial ownership and disqualifications. Free API key required. AGPL-3.0.

## Public Records & Compliance

- 🆓💰 [DataNexus MCP](https://smithery.ai/servers/dev-7bd0/mcp-server/) — Public records intelligence across 7 domains: domain recon (RDAP, DNS, SSL, subdomains, email security), patent search & inventor portfolios (EPO/WIPO), US government contract awards & vendor history (SAM.gov), regulatory filings & dockets (Regulations.gov + Federal Register), US/UK nonprofit 990 data & health scores, CVE/SBOM/EPSS vulnerability intelligence, and professional licence verification (NPI, FINRA, SAM exclusions). 55 tools, no API key required for free tier, hosted remote MCP.
- 📦💰 [Nummeropslag](https://github.com/andrey-tut/nummeropslag-api) — Privacy-first Danish phone-number intelligence using official CVR and telecom-register data. Look up registered companies, operators, number types, and community spam/trust signals without exposing private individuals' names. Requires a paid API key.
- 📦🆓 [Sanctions Screening MCP](https://github.com/cyanheads/sanctions-screening-mcp-server) — Screen names against the consolidated OFAC, EU, UK and UN sanctions lists, resolve companies to GLEIF LEIs, and trace ownership chains. Mirrors the lists into a local SQLite/FTS5 index, so matching runs offline with no API key and no rate limit; hits carry a raw Jaro-Winkler score and source provenance rather than a verdict. `npx -y @cyanheads/sanctions-screening-mcp-server`
- 📦🆓 [Sift](https://github.com/mefos-lab/sift) — 80 tools for cross-referencing public financial and corporate records across 9 sources: OpenSanctions, the ICIJ Offshore Leaks database (via Aleph), UK Companies House, SEC EDGAR, CourtListener, GLEIF, Wikidata and land registries. Ships 24 structural detection patterns (shell companies, nominee shields, phoenix companies, circular ownership) and interactive network graphs. Free OpenSanctions API key required.

## Threat Intelligence

- 📦🆓 [VirusTotal](https://github.com/BurtTheCoder/mcp-virustotal) — Analyze URLs, files (by hash), IPs, and domains with detailed relationship mapping. Free API tier available, requires `VIRUSTOTAL_API_KEY`.
- 📦🆓 [Voidly](https://www.npmjs.com/package/@voidly/mcp-server) — Global internet censorship intelligence: 116 tools across 119+ countries. Query OONI / IODA / CensoredPlanet evidence, look up 5,356 citable incidents, check if a domain or service is blocked in a country, fetch ISP-level risk scores, run ML-driven shutdown forecasts, and verify censorship claims. Free, no API key needed for read endpoints. `npx @voidly/mcp-server`.
- 📦🆓 [OpenOSINT](https://github.com/OpenOSINT/OpenOSINT) — AI-powered OSINT agent with interactive REPL, MCP server, and CLI.
- 📦🆓 [osint-agent-skills](https://github.com/frangelbarrera/osint-agent-skills) — 23 MCP tools (DNS, Shodan InternetDB, crt.sh, Wayback CDX, GitHub code search, OTX, HIBP, Etherscan, Mastodon) with zero-dependency Node.js server for Claude Code, Cursor, and Ollama.
- 📦🆓 [VulneraMCP](https://github.com/telmon95/VulneraMCP) — AI-powered bug bounty MCP server with recon (subfinder, httpx, gau, ffuf), vulnerability testing (XSS/SQLi/IDOR/CSRF), API/auth/cloud scanning, knowledge-graph analysis, and Markdown reporting. Integrates OWASP ZAP and CLI tools with PostgreSQL storage.
- 📦🆓 [Clearfront](https://github.com/scottmartinanderson/clearfront) — Self-OSINT footprint scanner exposing 30 tools over MCP: username enumeration (Sherlock, Maigret, WhatsMyName), email and breach checks (holehe, HIBP, Hudson Rock infostealer logs), domain and IP recon (crt.sh, Shodan, Censys, GreyNoise, Wayback Machine), and EXIF/GPS extraction. Correlates findings into an evidence graph and rates each by source, confidence and severity. Configurable sweep depth and a local web console. `pip install clearfront`, runs locally, most tools keyless.
- 📦🆓 [ScanMalware](https://github.com/scanmalware/mcp-server) — Submit a URL for sandboxed browser analysis, then pivot across the scan archive: search by domain, IP, ASN, JARM, favicon mmh3, TLSH/ssdeep fuzzy hash, screenshot hash, OCR text, or JavaScript fingerprint. Also exposes YARA matches, TLS/RDAP records, Certificate Transparency pivots, detected technologies, and pastejacking/clipboard events. 128 tools, no API key required. MCP: https://mcp.scanmalware.com/mcp
- 📦🆓 [Darknet MCP](https://github.com/badchars/darknet-mcp-server) — 66 tools for dark web and breach intelligence: ransomware group tracking and victim listings, stealer logs, HIBP breach lookups, IntelX search, Tor .onion fetching and exit-node checks, MalwareBazaar/ThreatFox/URLhaus feeds, and Bitcoin address intel. Many tools work with no API key; premium sources unlock with your own keys. `npx darknet-mcp-server`
- 📦🆓 [OpenCTI MCP](https://github.com/zxzinn/opencti-mcp) — Natural-language access to an OpenCTI instance: latest reports, campaigns by name, attack patterns, indicators, labels and marking definitions over the GraphQL API. Requires your own OpenCTI URL and token.

## Geospatial & Geopolitical Intelligence

- 📦🆓 [World Intel MCP](https://github.com/marc-shade/world-intel-mcp) — 120 tools for real-time global situational awareness across 30+ domains: GDELT and 119 RSS news feeds, ACLED conflict events, military aircraft tracking (ADS-B/OpenSky), NGA maritime warnings, submarine cables and datacenters, OFAC sanctions, USGS/NASA disaster feeds, plus geospatial datasets for bases, ports, pipelines and nuclear facilities. All sources are free public APIs; optional free keys (FRED, EIA, NASA FIRMS, ACLED, OpenSky) unlock a few of them. Python, installed from source.
- 📦🆓 [Satellite MCP](https://github.com/badchars/satellite-mcp) — 171 tools across 27 categories of geospatial intelligence: Sentinel-2 and Landsat scene search, NASA FIRMS wildfire detections, night-lights change detection, aircraft and vessel tracking, military and conflict data, sanctions, terrain and OpenStreetMap queries, plus spectral and change-detection math. Most tools need no key; premium imagery (Planet, NASA Earthdata, N2YO) uses your own. `npx satellite-mcp`
- 📦🆓 [GDELT MCP](https://github.com/cyanheads/gdelt-mcp-server) — Search and analyse global news coverage through the GDELT Project: article search, coverage timelines and breakdowns, tone distribution, and US television transcripts with clip, context and trending queries. No API key. `npx -y @cyanheads/gdelt-mcp-server`

## Research Intelligence

- 📦🆓💰 [BGPT MCP](https://github.com/connerlambden/bgpt-mcp) — Scientific paper search with structured full-text evidence: methods, sample sizes, results, limitations, quality scores, and falsification prompts. Useful for claim verification and literature OSINT. Remote MCP + REST. Free tier: 50 results. [docs](https://bgpt.pro/mcp/) · MCP: https://bgpt.pro/mcp/sse

## Meta / Discovery

- 🆓 [Not Human Search](https://nothumansearch.ai) — Agent-first discovery engine for MCP servers. Search, score, and live-probe (`verify_mcp`) 8,600+ servers via JSON-RPC or REST API. Useful for pivoting between OSINT MCP tools. MCP: https://nothumansearch.ai/mcp
- 📦🆓 [Claudii Exploratores](https://github.com/SOsintOps/claudii-exploratores) — OSINT suite exposing 898 curated OSINT tools across 24 categories (people, usernames, email, domains, IP, phones, companies, crypto, IBAN, media, social platforms…) as both a Claude Agent Skill and an MCP server. Auto-classifies an indicator, builds only the search URLs that fit it, and includes an offline ISO 13616 IBAN verifier and a reversible PII redactor. Python / FastMCP, AGPL-3.0. Alpha.

## Blockchain Intelligence

- 💰 [TWZRD Agent Intel](https://intel.twzrd.xyz) — Blockchain OSINT for AI agent trust scoring — reads public Solana on-chain data (wallet history, transaction patterns) to score agent trustworthiness. Free preflight + paid signed V5 trust receipts via x402 micropayments. MCP: https://intel.twzrd.xyz/mcp
- 💰 [The Stall](https://github.com/thebrierfox/the-stall) — Multi-tool blockchain OSINT server: OFAC sanctions screening (19,000+ SDN entries, fuzzy name match + AKA aliases), wallet risk scoring, agent KYA trust scoring, EVM and Solana transaction intelligence, and token security analysis. Pay-per-call via x402 USDC micropayments on Base — no accounts or API keys. MCP: https://the-stall.intuitek.ai/mcp

## Market & Trading

- 📦🆓💰 [Helium MCP](https://github.com/connerlambden/helium-mcp) — 37-dimensional news bias scoring across 216 sources, market data, and ML options pricing. Remote MCP + REST. [Demo](https://connerlambden.github.io/helium-news-explorer/) · [docs](https://heliumtrades.com/mcp-page/)

## Contributing

Contributions are welcome! Please open a pull request to add a new OSINT MCP server to the list.

## License

[MIT](LICENSE)
