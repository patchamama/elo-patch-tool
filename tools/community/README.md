# ELO Community helper (optional)

Reads vulnerability articles from the ELO Community knowledge board, asks an AI to analyse them and writes **draft** entries for the app's vulnerability catalog (`dev/vulndb.json`). It is separate from the Windows tool on purpose: Playwright cannot run inside the PowerShell `.bat`.

![Node](https://img.shields.io/badge/Node.js-18%2B-339933?logo=nodedotjs&logoColor=white)
![Playwright](https://img.shields.io/badge/Playwright-core-2EAD33?logo=playwright&logoColor=white)
![AI](https://img.shields.io/badge/AI-OpenAI%20·%20Anthropic%20·%20Ollama-6E56CF)

## What it does

1. **fetch** – signs in to the board with Playwright (Chrome), lists the newest articles inside your limit (`--since`, `--max`) and saves their text.
2. **analyze** – sends each article to the AI provider. The model rates the vulnerability (`high` / `medium` / `low`), says whether the article reports a solution, and proposes detection (probe + expect patterns or a fixed-version table), a mitigation flag and a **simulation** (canned `java -version` / flag output that makes the vulnerability look present).
3. **draft** – every answer is cleaned and re-validated, then written as a catalog entry with `"status": "draft"`.
4. **check** – validates and simulates the draft with the app itself.

Output goes to `%ProgramData%\ELO-Patch-Tools\quarantine\drafts\<timestamp>\` (the quarantine folder) or `--out DIR`:
`articles.json`, `analysis.json`, `draft-vulndb.json`, `report.md`.

## Usage

```powershell
npm install --prefix tools/community              # playwright-core only; use your installed Chrome
$env:ELO_COMMUNITY_USER     = 'you@example.org'    # environment only
$env:ELO_COMMUNITY_PASSWORD = '...'
$env:ANTHROPIC_API_KEY      = '...'                # or OPENAI_API_KEY; Ollama needs no key

node tools/community/bin/elo-community.js run --since 3m --max 20 --provider anthropic --model claude-sonnet-5-5
node tools/community/bin/elo-community.js run --since 30d --provider ollama --model llama3.1        # local, no key
node tools/community/bin/elo-community.js fetch   --since 1y --max 50                                  # only the articles
node tools/community/bin/elo-community.js analyze --articles C:\q\articles.json --provider openai --model gpt-4o
node tools/community/bin/elo-community.js check   --draft C:\q\draft-vulndb.json
```

Then follow `report.md`: validate (`--catalog-validate`), simulate (`--catalog-simulate`), review and set `"status": "active"` on the entries you accept, and install with `--catalog-install FILE --confirm-admin`. The previous installed catalog is quarantined first and can be restored with `--catalog-restore`.

Limits: `--since 30d | 8w | 3m | 1y | YYYY-MM-DD` (required for `fetch`/`run`), `--max N` (default 20, at most 200).

AI configuration: flags, or `config/ai.json` (copy `config/ai.example.json`; git-ignored). The file holds the **name** of the environment variable (`apiKeyEnv`), never the key.

## Safety rules

- **Credentials and keys** come from the environment only. They are never written to a file, a draft or the quarantine, and are redacted from error messages.
- **Articles are untrusted.** The prompt tells the model to treat them as data, and nothing the model returns is executed. `draft.js` keeps only: plain `java.exe` options as probe arguments (no paths, no shell), one `-XX:+/-Flag` as mitigation, https links, known `{placeholders}`, valid regular expressions and bounded text. Anything else is dropped and listed under `review.issues`.
- **Drafts never act.** A draft has `status: draft`; the scan ignores it until a person reviews it, validates it, simulates it and installs it. If detection cannot be derived safely, the entry is a placeholder that detects nothing and says so.
- Only `community.elo.com` over https is read; other hosts are refused.

## Verified and not verified

- Verified: the sign-in page (`form#eloLoginForm`, `input[name=username]`, `input[name=password]`, button *Anmelden*), all provider request shapes against mocks, the draft sanitizing, the date/count limits, and that generated drafts pass the app's real validator and simulation (Windows PowerShell 5.1) — see `npm test`.
- **Not verified:** the board's list/article markup after sign-in and the answers of real AI services. No account was available, so the selectors in `config/community.json` (`list`, `article`) are best-effort defaults; adjust them if the board differs. Treat every draft as a suggestion from a model, not a verified advisory.

## Tests

```powershell
npm test --prefix tools/community        # 23 tests, no network, no browser; the PowerShell cross-check runs on Windows
```
