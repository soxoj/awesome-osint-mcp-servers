# Contributing

Contributions are welcome. Before opening a PR, please read how submissions get reviewed — most rejections are for the same handful of reasons below.

## Scope

This list is for **OSINT** MCP servers: tools that gather or enrich intelligence from open sources (people, domains, IPs, companies, breach data, social platforms, blockchain wallets, public registries, etc.).

Out of scope, even if well-built:
- Generic DevSecOps / pentest tooling with no OSINT angle (recon-only scanners are fine, exploitation frameworks are not).
- Generic crypto/market trading, price feeds, or DeFi data with no investigative use.
- SEO, marketing, or growth tooling.
- Consumer shopping / e-commerce APIs.

If in doubt, ask: would an investigator or a security researcher doing recon use this to learn something about a person, company, domain, address, or attack surface? If not, it probably doesn't belong here.

## What we check before merging

1. **The project is real and working.**
   - For a hosted MCP endpoint: we send a raw `initialize` handshake (`curl -X POST <url> -d '{"jsonrpc":"2.0",...,"method":"initialize",...}'`) and confirm it responds.
   - For an npm/PyPI package: we check that `package.json` actually has a working `bin` entry (a null or missing `bin` means `npx <package>` fails — instant reject) or that the source registers the claimed tools.
   - Claimed tool/endpoint counts in the PR description must match what's actually in the code — we grep for `registerTool` / tool manifests / `tools/list` output rather than trusting the README.

2. **It fits an existing section, or a new section is justified.**
   We'd rather add one line to an existing category than create a one-entry section. New top-level sections are for genuinely new categories of OSINT, not a shelf for one submission.

3. **The entry follows the existing format.**
   `- {emoji} [Name](url) — one or two sentence description. MCP: <endpoint if hosted>`
   Emoji legend: 📦 Open Source · 🆓 Free / Free tier · 💰 Paid. Use only the emoji that actually apply (a closed-source paid API isn't 📦; a project with a public repo is 📦 even if the API itself costs money).

4. **Spam signals lower the odds of a merge.** We check the author's PR history across GitHub (`gh search prs --author <user> --state all`). None of these auto-reject on their own, but the more of them apply, the less likely the PR gets merged:
   - The identical PR opened simultaneously across many unrelated awesome-lists (crypto lists, payment lists, generic API directories) — reads as a growth-hacking pattern rather than a genuine submission to this list specifically.
   - A growth/marketing plan file committed to the repo (star targets, posting schedules, SEO playbooks).
   - AI-generated PR titles stuffed with emojis, vague templated bodies, or descriptions that don't match the diff.
   - Tracking params (`utm_source`, etc.) baked into the listed URL — we'll usually just ask for a clean link.

5. **Description is accurate and sells the actual tool**, not the company behind it. One or two sentences on what it does and what's required to use it (API key, free tier limits) is enough.

## Process

- Small, single-entry PRs only — one server per PR.
- We verify live (handshake / package inspection), not just by reading the README.
- If a submission fails on scope or looks like cross-posted spam, we close with a short explanation rather than leaving it open.
- If it's a real project that's simply in the wrong place or missing something (wrong emoji, wrong section, broken link), we'll ask for a fix instead of closing.
