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
![Languages](https://img.shields.io/badge/UI-EN%20·%20DE-informational)

</div>

> **Status: verified on disposable test runtimes and on one test ELO server.** The update was exercised live (real vendor APIs and downloads) on Temurin 17, Zulu 17 and Zulu 8 scratch runtimes, in a real browser, and once on the Zulu 21 of a test ELO host (6 services stopped and restarted). ELO compatibility with a newer runtime is never assumed: validate ELO yourself after updating. Web `--no-browser` is unavailable.

## Contents

[What it does](#what-it-does) · [Quick start](#quick-start) · [Restore a Java backup](#restore-a-java-backup) · [Safety](#safety-and-limitations) · [Requirements](#requirements) · [Development](#development) · [Security information](#security-information)

## What it does

The runnable application is the single, self-contained **`ELO-Patch-Tools.bat`**. `dev/` holds sources and tests and is not needed to run it.

| Step | What happens |
| --- | --- |
| **1 · Scan** | Read-only search for Java in `X:\java\bin` and `X:\ELO\java\bin` on every drive C: to Z: (plus an optional folder). |
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

If the update itself fails, the app already rolls back on its own. The in-app restore is available while that browser session is open and only for the update made in it.

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

## Safety and limitations

- **Services.** A runtime in use cannot be replaced. The preview lists the Windows services that use it (found through loaded modules and process ancestry, e.g. ELO's Procrun services); confirming stops exactly those right before the swap and starts them again afterwards, also after a failure. Any other process using the runtime blocks the update; the tool never kills processes.
- **Compatibility.** No ELO compatibility approval is claimed. Installing the vendor package with its installer remains the preferred long-term fix; the report says so.
- **Backups** cover content, owner, group and DACL. SACL (auditing) entries are not captured.
- **Quiescence** is checked fail-closed (nothing has the runtime loaded; java binaries open exclusively), but a service started by something else mid-swap cannot be excluded.
- Runtimes directly below a drive root (e.g. `C:\java`) are supported.
- The mitigation changes machine-wide `JAVA_TOOL_OPTIONS` and can affect other Java applications; running processes are not protected until restarted. Save the previous value and type independently: its rollback backup is session-only.
- The ELO version in the report is read from the installed Indexserver files (`servers\*\webapps\ix-*\version.txt`); no API, no credentials. Unknown stays unknown.
- Vulnerability *classification* is conservative and limited to identifiable Temurin builds; other vendors stay inconclusive, but the update still offers the newest release of their branch.
- Raw JSON exports may include local paths; review them before sharing.

## Requirements

- Windows with Windows PowerShell 5.1 (the execution policy must allow it; the launcher never overrides it).
- Administrator session for the update and the mitigation.
- Network access to `api.azul.com`, `cdn.azul.com`, `api.adoptium.net`, `github.com` and `release-assets.githubusercontent.com` for the update (the system proxy is honoured).
- Run discovery only on trusted installations: obtaining a version executes the discovered `java.exe`.

## Development

| Layer | Technology |
| --- | --- |
| Packaging | One `.bat` that extracts embedded resources to a temp folder (`dev/build-bat.ps1` regenerates them) |
| Backend | Windows PowerShell 5.1 modules (`scan`, `server`, `update`, `catalog`, `report`, `cli`), loopback HTTP server with session token |
| Frontend | Single HTML file, vanilla JS, inline SVG icons, no external assets, strict CSP |
| Tests | PowerShell (`dev/*.tests.ps1`), Node (UI contract), opt-in live and browser E2E (Playwright + Chrome) |

- `dev/*.tests.ps1` — deterministic tests (scan, server, cli, launcher, report, update, integration) in PowerShell 5.1; `dev/ui.tests.ps1` also needs PowerShell 7 and Node.js.
- `dev/update.live.tests.ps1` — opt-in (`ELO_LIVE_UPDATE_TEST=1`, administrator, network, ~1.5 GB): updates, restores and rolls back scratch Temurin 17, Zulu 17 and Zulu 8 runtimes through the server API.
- `dev/e2e/wizard.e2e.js` — opt-in (`ELO_E2E=1`, Chrome, `npm install --prefix dev/e2e`): real server + real browser through scan, update, report, restore and start over.
- After editing any file in `dev/`, run `pwsh dev/build-bat.ps1` to regenerate the BAT.

## Security information

Checked on **2026-11-23**: the [Adoptium Temurin advisory](https://adoptium.net/news/2026/11/temurin-november-2026-cspu-java4shell/) and the [Oracle Linux CVE record](https://linux.oracle.com/cve/CVE-2026-114938.html) were fetched directly; the [OpenJDK advisory](https://openjdk.org/groups/vulnerability/advisories/2026-11-17) was reviewed as user-supplied text (direct retrieval returned HTTP 403). Advisories change: check current vendor guidance. Community content, AI output and remote catalogs must never authorize arbitrary commands.
