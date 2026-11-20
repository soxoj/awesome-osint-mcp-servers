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
   - **Give us a measured tool count, and say how much of it is on-topic.** Run `tools/list` against your own server and paste the number you got, not the number in your README — we check it the same way. If the server does more than OSINT (market data, SEO, e-commerce, your own asset inventory), say so and roughly how much: "49 tools, a third of them weather and grid data" is a fine entry; "700 read-only tools" when `tools/list` returns 469 is not. A gated handshake is fine, but then say plainly that the count is yours rather than measured.
   - **Don't pin a number that moves.** Tool counts on young servers, corpus sizes and record totals grow weekly — one entry here went from 12 tools to 19 in a day. Prefer "200+", or no number at all, over an exact figure that will be wrong in a month.

2. **It fits an existing section, or a new section is justified.**
   We'd rather add one line to an existing category than create a one-entry section. New top-level sections are for genuinely new categories of OSINT, not a shelf for one submission.

3. **The entry follows the existing format.**
   ```
   - {emoji} [Name](url) — one or two sentence description. MCP: https://host/mcp
   - {emoji} [Name](url) — one or two sentence description. stdio (`npx -y package`)
   ```
   `MCP:` introduces a URL a client can connect to. If your server runs locally, don't put a shell command after `MCP:` — write ``stdio (`npx -y your-package`)`` or ``stdio (`uvx your-package`)`` instead, so a reader knows there's an install involved. Don't wrap the endpoint URL in backticks.
   Emoji legend: 📦 Open Source · 🆓 Free / Free tier · 💰 Paid. Use only the emoji that actually apply (a closed-source paid API isn't 📦; a project with a public repo is 📦 even if the API itself costs money).
   📦 means a reader can go read the implementation. A repository holding only a README, a manifest and client config examples isn't open source for our purposes, even with a licence file — several contributors have dropped the marker themselves once this came up. A licence file is required too: a public repo with no licence grants nobody anything.

4. **Spam signals lower the odds of a merge.** We check the author's PR history across GitHub (`gh search prs --author <user> --state all`). None of these auto-reject on their own, but the more of them apply, the less likely the PR gets merged:
   - The identical PR opened simultaneously across many unrelated awesome-lists (crypto lists, payment lists, generic API directories) — reads as a growth-hacking pattern rather than a genuine submission to this list specifically.
   - A growth/marketing plan file committed to the repo (star targets, posting schedules, SEO playbooks).
   - AI-generated PR titles stuffed with emojis, vague templated bodies, or descriptions that don't match the diff.
   - Tracking params (`utm_source`, etc.) baked into the listed URL — we'll usually just ask for a clean link.

5. **Description is accurate and sells the actual tool**, not the company behind it. One or two sentences on what it does and what's required to use it (API key, free tier limits) is enough.

6. **Keep it short.** The description — everything after the em dash — must stay under 400 characters, and ideally around 250. The median entry in the list is 225. Anything longer is documentation rather than an index entry: caveats, pricing tiers and per-tool costs belong in your own README, with a link to it. Only the text counts, so a long URL costs you nothing.

   ```bash
   grep -oP '^- \S+ \[[^\]]+\]\([^)]+\)\s+—\s+\K.*' README.md | awk 'length>400{print length": "$0}'
   ```

7. **Leave pricing mechanics out.** "Free tier", "needs an API key", "paid plans from $X/mo" is as much as an index entry can carry. Per-call price lists, credit-pack sizes, wallet chains and promotional limits change faster than this list gets reread, and a stale price is worse than no price: it's confidently wrong. One recent submission spent half its 400 characters on six per-tool prices in USDC.

8. **Updating an existing entry is welcome, especially your own.** Servers get rewritten and entries drift — one entry claimed 49 tools until its author came back with a corrected line showing 37. If you're editing a line that's over the 400-character cap, bring it under while you're there. Keep the diff to your own line: a rewrite that silently truncates a neighbouring entry is the one thing we always catch and always send back.

## Process

- Small, single-entry PRs only — one server per PR.
- We verify live (handshake / package inspection), not just by reading the README.
- If a submission fails on scope or looks like cross-posted spam, we close with a short explanation rather than leaving it open.
- If it's a real project that's simply in the wrong place or missing something (wrong emoji, wrong section, broken link), we'll ask for a fix instead of closing.
