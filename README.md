<div align="center">

# ELO Patch Tools

**Find, mitigate and update Java runtimes on ELO DMS servers — with a verified backup and one-click restore.**

![Platform](https://img.shields.io/badge/platform-Windows-0078D4?logo=windows&logoColor=white)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1-5391FE?logo=powershell&logoColor=white)
![Batch](https://img.shields.io/badge/single_file-.bat-4D4D4D?logo=windowsterminal&logoColor=white)
![UI](https://img.shields.io/badge/UI-HTML%20%2B%20vanilla%20JS-E34F26?logo=html5&logoColor=white)
![Java](https://img.shields.io/badge/Java-8%20·%2011%20·%2017%20·%2021%20·%2025-ED8B00?logo=openjdk&logoColor=white)
![Zulu](https://img.shields.io/badge/Azul-Zulu-0033A0)
![Temurin](https://img.shields.io/badge/Eclipse-Temurin-FF1472?logo=eclipseadoptium&logoColor=white)
![Tests](https://img.shields.io/badge/tests-PowerShell%20·%20Node%20·%20Playwright-2EAD33?logo=playwright&logoColor=white)
![Languages](https://img.shields.io/badge/UI-EN%20·%20DE%20·%20ES-informational)
![License](https://img.shields.io/badge/license-MIT-green)

</div>

> **Status: verified on disposable test runtimes and on one test ELO server.** The update was exercised live (real vendor APIs and downloads) on Temurin 17, Zulu 17 and Zulu 8 scratch runtimes, in a real browser, and once on the Zulu 21 of a test ELO host (6 services stopped and restarted). ELO compatibility with a newer runtime is never assumed: validate ELO yourself after updating. Web `--no-browser` is unavailable.

## Contents

[What it does](#what-it-does) · [Quick start](#quick-start) · [Restore a Java backup](#restore-a-java-backup) · [Vulnerability catalog](#the-vulnerability-catalog-devvulndbjson) · [Safety](#safety-and-limitations) · [Requirements](#requirements) · [Development](#development) · [Security information](#security-information)

## What it does

The runnable application is the single, self-contained **`ELO-Patch-Tools.bat`**. `dev/` holds sources and tests and is not needed to run it.

| Step | What happens |
| --- | --- |
| **1 · Scan** | Read-only search on every drive C: to Z: for `X:\java\bin` (first level) and `X:\<any folder>\java\bin` (second level, e.g. `C:\ELO\java\bin` or `C:\OtherFolder\java\bin`; system and linked folders are skipped), plus an optional folder you provide. Existing backups are listed first. |
| **2 · Runtime** | Pick one of the runtimes found (vendor, version, architecture, assessment). |
| **3 · Action** | **Update Java** to the newest release of the *same vendor and branch*, apply the **temporary mitigation** (`-XX:-UseBASE64Intrinsics`), or read the **manual instructions** (steps plus ready-to-run PowerShell commands: inspect, back up, mitigate, update, roll back; also in `--help`). |
| **4 · Confirm** | The preview names exact versions, backup ZIP, services to stop and risks. Nothing happens before you confirm. |
| **5 · Report** | Bilingual (EN/DE) technical report: server, Windows, RAM/disk, JVMs, update, backup, ELO version, environment state and restore commands. |

**Supported runtimes:** Azul Zulu and Eclipse Temurin · Java 8, 11, 17, 21, 25 (any branch the vendor publishes) · x86, x64, ARM64 · JDK or JRE · Windows. The newest GA release is resolved at preview time from the vendor API (`api.azul.com`, `api.adoptium.net`); host, URL shape and SHA256 are validated by a strict policy in code before any download.

```mermaid
flowchart LR
    A[Preview<br/>latest release] --> B[Backup ZIP<br/>manifest + SHA256]
    B --> C[Pinned HTTPS<br/>download + hash]
    C --> D[Safe extract<br/>+ Java self-test]
    D --> E[Stop services]
    E --> F[Swap runtime<br/>old one is renamed]
    F --> G[Re-test]
    G -->|ok| H[Start services]
    G -->|fail| R[Automatic rollback]
    R --> H
```

The backup ZIP and the previous runtime are **never deleted**.

## Quick start

```bat
ELO-Patch-Tools.bat                                   :: web wizard (recommended)
ELO-Patch-Tools.bat --help
ELO-Patch-Tools.bat --cli --scan --json
ELO-Patch-Tools.bat --cli --scan --manual-path "D:\ELO Server"
ELO-Patch-Tools.bat --cli --update-runtime --target 0 --confirm-admin --confirm-update
ELO-Patch-Tools.bat --cli --manual
```

Run it from an **administrator** session for the update and the mitigation. Read-only scans need no elevation and never prompt. The CLI update and mitigation require explicit flags plus a typed confirmation (`APPLY UPDATE` / `APPLY MITIGATION`) in an interactive console. `--keep-temp` keeps the extracted session files for diagnosis.

## Restore a Java backup

Every update first writes a verified backup ZIP next to the runtime, for example `C:\ELO\java.backup-20261124125509.zip` (the old runtime also stays as `C:\ELO\java.old-20261124125509`). There are three ways back:

**1. In the app (same session, one click).** After an update the *Report* step shows **Restore previous version**. Confirm the preview and the app:

1. stops the services that use the runtime (if any) and restarts them afterwards;
2. extracts the ZIP into a sibling directory, checking the SHA256 of every file against the manifest;
3. re-applies the permissions (DACL, and owner when permitted);
4. swaps it in. The updated runtime is kept as `java.replaced-<timestamp>`; nothing is deleted.

**Backups from earlier sessions need no scan.** The first step lists every `<runtime>.backup-<timestamp>.zip` found on drives C: to Z: (levels 1 and 2) in a collapsed *Existing backups* box. Each entry shows its Java version and whether that version is **vulnerable to CVE-2026-114938**, **listed as fixed** or **of unknown status** (only exact Temurin builds are classified; anything else is treated as potentially vulnerable). Restoring one:

- requires **stopping the ELO Tomcat services** that use the runtime; the preview lists them and ELO is unavailable until they start again;
- warns when the backup is a vulnerable version, because restoring brings the vulnerability back (mitigate with `-XX:-UseBASE64Intrinsics` or update again afterwards);
- is recorded in the technical report as the runtime's new state (potentially vulnerable, fixed or unknown), even if no scan was run.

The backend window (PowerShell) prints each step as it happens: scan start/end, previews, applied actions, failures, rejected requests and a security note after a restore. It never prints the session token.

If the update itself fails, the app already rolls back on its own. The in-app restore of the *latest update* is available while that browser session is open; backups of earlier sessions are restored from the first step.

**2. Manually, from any terminal (also after the session is gone).** The technical report prints these commands with your real paths. Stop the ELO services first:

```powershell
# PowerShell (administrator)
Remove-Item -LiteralPath 'C:\ELO\java' -Recurse -Force
Expand-Archive -LiteralPath 'C:\ELO\java.backup-20261124125509.zip' -DestinationPath 'C:\ELO\java.restore'
Move-Item -LiteralPath 'C:\ELO\java.restore\tree' -Destination 'C:\ELO\java'
```

```bat
:: cmd.exe (administrator)
rmdir /s /q "C:\ELO\java"
mkdir "C:\ELO\java.restore"
tar -xf "C:\ELO\java.backup-20261124125509.zip" -C "C:\ELO\java.restore"
move "C:\ELO\java.restore\tree" "C:\ELO\java"
```

**3. Simplest manual way.** Stop the services, rename the new `java` folder, rename `java.old-<timestamp>` back to `java`, start the services.

The ZIP holds `manifest.json` (every file, size, SHA256, permissions) and a `tree\` folder with the runtime. The CLI has no restore command.

## The vulnerability catalog (`dev/vulndb.json`)

Everything the tool knows about a vulnerability lives in **one JSON file** that is shared in this repository (it never contains passwords or API keys). The scan, the web UI, the CLI, the restore warnings and the technical report all read it, so supporting a new vulnerability is an edit of the JSON, not of the code.

| Section of an entry | What it holds |
| --- | --- |
| `id`, `severity` (`high` / `medium` / `low`), `status` (`active` / `draft` / `retired`) | Identity and level. A `draft` is validated but never used by the scan. |
| `advisories` | Links shown in the UI, the report and `--help` (https only), with their provenance. |
| `detection.probes` | The `java.exe` argument lists to run (`-version`, `-XX:+PrintFlagsFinal -version`, ...) and the **expect** patterns that mean something. Never a shell, never a path. |
| `detection.method` | `version-table`: fixed builds per vendor (Temurin build strings). `probe-expect`: a probe plus `vulnerablePattern` / `safePattern`. |
| `problem`, `solution` | The red alert of the UI (EN/DE), with `{n}` and `{list}` placeholders. |
| `actions` | `runtime-update`, `jvm-option` (one `-XX:` flag in `JAVA_TOOL_OPTIONS`, with a `verify` probe) and `restore-backup`. Only these three action types exist, so an entry can never run arbitrary commands. |
| `messages`, `report` | Texts of the restore warnings, the backend log and the final report. |
| `simulation` | Canned probe output that makes the vulnerability look present, so detection, alert, mitigation and report can be tested without a vulnerable Java. |

```powershell
# Validate a catalog (read-only), replay its simulations, install it, undo it
ELO-Patch-Tools.bat --cli --catalog-validate  C:\drafts\draft-vulndb.json
ELO-Patch-Tools.bat --cli --catalog-simulate  C:\drafts\draft-vulndb.json      # every entry, drafts included
ELO-Patch-Tools.bat --cli --catalog-simulate  CVE-2026-114938                  # one entry of the active catalog
ELO-Patch-Tools.bat --cli --catalog-install   C:\drafts\draft-vulndb.json --confirm-admin
ELO-Patch-Tools.bat --cli --catalog-list                                       # quarantined copies
ELO-Patch-Tools.bat --cli --catalog-restore   20261125101500123-vulndb.json --confirm-admin
```

**Quarantine.** Before the tool replaces a file it copies the old one to `%ProgramData%\ELO-Patch-Tools\quarantine\<timestamp>-<name>\` with a manifest (original path, SHA256, reason). A restore verifies the hash and quarantines whatever it replaces, so a restore can itself be undone. An installed catalog (`%ProgramData%\ELO-Patch-Tools\vulndb.json`) wins over the packaged one; a broken installed file falls back to the packaged catalog instead of disabling detection.

## AI-assisted drafts from the ELO Community (`tools/community`)

**Nothing is installed by default**: the patch tool (scan, update, mitigation, restore, catalog) is one .bat and needs no extra software. Only when you choose to use the community helper does it show what it needs (Node.js, the npm package `playwright-core` ~14 MB, Chrome, your ELO Community credentials and an AI key) and ask before installing or contacting anything.

An **optional** Node.js helper reads vulnerability articles from the [ELO Community board KBB103](https://community.elo.com/community/plugin/de.elo.ix.plugin.proxy/wf/apps/app/sol.knowledge.apps.KnowledgeBoard/#/?board=KBB103&page=1) with Playwright and asks an AI (OpenAI, Anthropic or a local Ollama) to rate the vulnerability (high / medium / low), report the solutions the article names and **draft** a catalog entry together with a simulation mock. It only writes drafts into the quarantine folder; nothing is installed or run automatically.

```powershell
node tools/community/bin/elo-community.js setup     # shows what it needs and installs ONLY after you type yes
# credentials: environment variables or the git-ignored tools/community/secrets.local.env
node tools/community/bin/elo-community.js run --since 3m --max 20 --provider anthropic --model claude-sonnet-5-5
node tools/community/bin/elo-community.js check      # validate + simulate the draft with the app
```

**In the web UI** the **Settings** button in the header (available at every step) opens *Settings: ELO Community + AI (optional)*:

- shows what is needed (credentials, extra software) and offers *Install the helper* only after you tick the consent box;
- takes your ELO Community user/password and the AI key (used for that one run, never stored, fields cleared afterwards) and has a **Test ELO Community access** button;
- lists the models your account offers in a collapsible list box, loaded automatically when a key is already saved (or with **Load available models**);
- runs the analysis and lists every **article found** with the AI's severity (high / medium / low) and why, a short summary, whether a **script is worthwhile** (and why not, e.g. it needs a vendor hotfix), the solutions the article reports and the draft it produced;
- lets you **improve one article** by pasting a solution text, notes or links and/or letting the AI **research the internet** (OpenAI / Anthropic), which re-drafts the catalog entry;
- **Check the drafts** validates them and replays their simulation inside the app.

The same commands are available from the terminal (ccess, models, efine).

Limits: `--since 30d|8w|3m|1y|YYYY-MM-DD` and `--max N`. Details, safety rules and the unverified parts are in [`tools/community/README.md`](tools/community/README.md).

## Languages and license

The web UI, the technical report and the catalog texts are available in **English, German and Spanish** (the Spanish selector is next to the language list; backend messages that have no Spanish version fall back to English). The project is released under the [MIT License](LICENSE).

## Safety and limitations

- **Services.** A runtime in use cannot be replaced. The preview lists the Windows services that use it (found through loaded modules and process ancestry, e.g. ELO's Procrun services); confirming stops exactly those right before the swap and starts them again afterwards, also after a failure. Any other process using the runtime blocks the update; the tool never kills processes.
- **Compatibility.** No ELO compatibility approval is claimed. Installing the vendor package with its installer remains the preferred long-term fix; the report says so.
- **Backups** cover content, owner, group and DACL. SACL (auditing) entries are not captured.
- **Quiescence** is checked fail-closed (nothing has the runtime loaded; java binaries open exclusively), but a service started by something else mid-swap cannot be excluded.
- Runtimes directly below a drive root (e.g. `C:\java`) are supported.
- The mitigation changes machine-wide `JAVA_TOOL_OPTIONS` and can affect other Java applications; running processes are not protected until restarted. Save the previous value and type independently: its rollback backup is session-only.
- The ELO version in the report is read from the installed Indexserver files (`servers\*\webapps\ix-*\version.txt`); no API, no credentials. Unknown stays unknown.
- Vulnerability *classification* is conservative: the catalog decides what is vulnerable, and version tables are supported for identifiable Temurin builds (other vendors stay inconclusive unless an entry uses a `probe-expect` rule), but the update still offers the newest release of their branch.
- The *Temporary mitigation* button is enabled only for a runtime the catalog classifies as vulnerable; for any other runtime (for example an Azul Zulu build, which the catalog does not evaluate) the page says so and only the update is offered.
- The static help texts of the UI (manual instructions, action descriptions) still describe the built-in vulnerability; the alert, severity, problem, solution, advisories, mitigation, restore warnings, report sources, CLI security block and scan rules come from the catalog.
- Raw JSON exports may include local paths; review them before sharing.
- The technical report states only what is known: anything unknown or unavailable (classification, evidence, vendor, ELO version, scopes, disks) is left out instead of printed as a placeholder.

## Requirements

- Windows with Windows PowerShell 5.1 (the execution policy must allow it; the launcher never overrides it).
- Administrator session for the update and the mitigation.
- Network access to `api.azul.com`, `cdn.azul.com`, `api.adoptium.net`, `github.com` and `release-assets.githubusercontent.com` for the update (the system proxy is honoured).
- Nothing else has to be installed to use the tool (the community helper in `tools/community` is optional and asks first).
- Run discovery only on trusted installations: obtaining a version executes the discovered `java.exe`.

## Development

| Layer | Technology |
| --- | --- |
| Packaging | One `.bat` that extracts embedded resources to a temp folder (`dev/build-bat.ps1` regenerates them) |
| Backend | Windows PowerShell 5.1 modules (`scan`, `server`, `update`, `catalog`, `vulndb`, `report`, `cli`), loopback HTTP server with session token |
| Catalog | `dev/vulndb.json`: detection probes + expect patterns, problem, actions, report and simulation per vulnerability |
| AI helper | Optional Node.js tool (`tools/community`): Playwright + OpenAI / Anthropic / Ollama, drafts only |
| Frontend | Single HTML file, vanilla JS, inline SVG icons, no external assets, strict CSP |
| Tests | PowerShell (`dev/*.tests.ps1`), Node (UI contract), opt-in live and browser E2E (Playwright + Chrome) |

- `dev/*.tests.ps1` — deterministic tests (vulndb, scan, server, cli, launcher, report, update, integration) in PowerShell 5.1; `dev/ui.tests.ps1` also needs PowerShell 7 and Node.js.
- `dev/update.live.tests.ps1` — opt-in (`ELO_LIVE_UPDATE_TEST=1`, administrator, network, ~1.5 GB): updates, restores and rolls back scratch Temurin 17, Zulu 17 and Zulu 8 runtimes through the server API.
- `dev/e2e/wizard.e2e.js` — opt-in (`ELO_E2E=1`, Chrome, `npm install --prefix dev/e2e`): real server + real browser through scan, update, report, restore and start over.
- `tools/community` — `npm test --prefix tools/community` (Node, no network).
- After editing any file in `dev/`, run `pwsh dev/build-bat.ps1` to regenerate the BAT.

## Security information

Checked on **2026-11-23**: the [Adoptium Temurin advisory](https://adoptium.net/news/2026/11/temurin-november-2026-cspu-java4shell/) and the [Oracle Linux CVE record](https://linux.oracle.com/cve/CVE-2026-114938.html) were fetched directly; the [OpenJDK advisory](https://openjdk.org/groups/vulnerability/advisories/2026-11-17) was reviewed as user-supplied text (direct retrieval returned HTTP 403). Advisories change: check current vendor guidance. Community content, AI output and remote catalogs must never authorize arbitrary commands.
