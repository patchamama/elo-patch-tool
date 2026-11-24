# ELO Patch Tools

A Windows tool for investigating CVE-2026-114938 in Java runtimes that may be associated with ELO DMS, applying a temporary mitigation, and updating the runtime to the newest release of its branch with a verified backup and automatic rollback. The runnable application is the self-contained `ELO-Patch-Tools.bat`; `dev/` contains development sources and tests and is not required to run it.

> **Status: verified on disposable test runtimes; review before production use.** The runtime update was exercised live (real vendor APIs and downloads) on Eclipse Temurin 17, Azul Zulu 17 and Azul Zulu 8 scratch runtimes and in a real browser; it has not been applied to a production ELO installation. ELO compatibility with a newer runtime is never assumed. Web `--no-browser` is unavailable. Do not use this tool as proof that a production installation is protected.

## What it does

1. **Scan** (read-only): finds Java in `X:\java\bin` and `X:\ELO\java\bin` on every drive C: to Z: (plus an optional folder you provide).
2. **Choose a runtime**, then an action:
   - **Update Java runtime**: installs the newest GA release of the *same vendor and branch* (Azul Zulu or Eclipse Temurin; Java 8, 11, 17, 21, 25 and any other branch the vendor publishes; x86, x64, ARM64; JDK or JRE). The release is resolved at preview time from the vendor's official API (`api.azul.com`, `api.adoptium.net`); the package host, URL shape and SHA256 are validated by a strict policy in code before anything is downloaded.
   - **Temporary mitigation**: `-XX:-UseBASE64Intrinsics` in the machine `JAVA_TOOL_OPTIONS` (not a Java update).
   - **Manual instructions** for patching by hand.
3. **Confirm**: the preview names the exact versions, backup ZIP, services to stop and risks; nothing happens before you confirm.
4. **Report**: bilingual (English/German) technical report with server name, Windows version, RAM/disk, detected JVMs, the update and backup, the ELO Indexserver version read from the installed files, the environment-variable state, and PowerShell/cmd commands to restore the backup.
5. **Restore**: one click restores the previous runtime from the backup ZIP (every file is hash-checked before the swap; the updated runtime is kept next to it).

The update transaction: verified backup ZIP (manifest, SHA256 per file, owner/group/DACL) -> pinned HTTPS download -> extraction with traversal/link/size checks -> Java self-test (`java -version` plus a small embedded class run with the staged runtime) -> rename old runtime, install new -> re-test -> on any failure the old runtime is restored. The backup ZIP and the previous runtime are never deleted.

## Requirements

- Windows with Windows PowerShell 5.1; the host execution policy must permit execution. The launcher does not override that policy.
- A local administrator session for the update and the mitigation. Read-only scanning does not require elevation, although permissions may limit coverage.
- Run discovery only on trusted installations: obtaining a version executes the discovered `java.exe`.
- Network access to the vendor hosts (`api.azul.com`, `cdn.azul.com`, `api.adoptium.net`, `github.com`, `release-assets.githubusercontent.com`) for the update. The system proxy is honoured.

## Quick start

```bat
ELO-Patch-Tools.bat --help
ELO-Patch-Tools.bat
ELO-Patch-Tools.bat --cli --scan --json
ELO-Patch-Tools.bat --cli --scan --manual-path "D:\ELO Server"
ELO-Patch-Tools.bat --cli --update-runtime --target 0 --confirm-admin --confirm-update
ELO-Patch-Tools.bat --cli --manual
```

Without options, the tool starts a local web interface (a five-step wizard: Scan, Runtime, Action, Confirm, Report). Read-only CLI scans do not prompt; the CLI update and mitigation require explicit flags plus a typed confirmation (`APPLY UPDATE` / `APPLY MITIGATION`) in an interactive console. Automatic discovery checks only `X:\java\bin\java.exe` and `X:\ELO\java\bin\java.exe` on ready fixed or removable drives C: through Z:. It can return multiple installations; it does not establish ELO ownership. If Java is elsewhere, supply a local directory in the web interface (Advanced) or with `--manual-path`; after the root checks, the scanner searches that directory with a depth limit of 5 and an entry budget of 10,000. Errors, skipped reparse points, cancellation and limits can leave coverage incomplete; a missing finding does not prove absence. `--keep-temp` retains extracted session resources for diagnosis; normal exit otherwise attempts to remove them, but forced termination may leave them behind.

## Safety and limitations

- **Services.** A runtime that is in use cannot be replaced. The preview lists the Windows services (found through loaded modules and process ancestry, for example the ELO Procrun services) that use the runtime; confirming the update stops exactly those services right before the swap and starts them again afterwards, also after a failure or rollback. Verified once against a real throwaway Windows service running a Java child from a scratch runtime (stopped, runtime replaced, service started again); the production ELO services were never touched. Any other process using the runtime blocks the update; the tool never kills processes.
- **Compatibility.** No compatibility approval by ELO is claimed. Consult ELO and the JVM vendor before replacing a runtime. Installing the vendor package with its own installer remains the preferred long-term fix; the report says so when a runtime was patched in place.
- **Backups** contain content, owner, group and DACL. SACL (auditing) entries are not captured. A restore re-applies the DACL (and the owner when permitted).
- **Quiescence** is checked fail-closed (no process with the runtime loaded, exclusive open of the java binaries) but a service started by something else in the middle of the swap cannot be excluded.
- Runtimes directly below a drive root (for example `C:\java`) are supported; the whole transaction stays inside that drive.
- The optional mitigation changes machine-wide `JAVA_TOOL_OPTIONS` and can affect other Java applications. It requires administrator privileges, an explicit preview and confirmation. Save the previous value and type independently: the automatic rollback backup is session-only. Existing Java processes are not protected until restarted.
- The ELO version in the report is read from the installed Indexserver files (`servers\*\webapps\ix-*\version.txt`); there is no API lookup, no credentials, and an unknown version is reported as unknown. Raw JSON exports may include local paths and diagnostics; review them before sharing.
- Version rules for the *vulnerability classification* are conservative and limited to identifiable Temurin builds. Other vendors (including Zulu) stay inconclusive for classification, but the update still offers the newest release of their branch.

## Security information

Information was checked on **2026-11-23**: the [Adoptium Temurin advisory](https://adoptium.net/news/2026/11/temurin-november-2026-cspu-java4shell/) and [Oracle Linux CVE record](https://linux.oracle.com/cve/CVE-2026-114938.html) were fetched directly. The [OpenJDK advisory](https://openjdk.org/groups/vulnerability/advisories/2026-11-17) was reviewed as user-supplied text because direct retrieval returned HTTP 403. Advisories can change; check the current vendor guidance.

## Development tests

The scripts in `dev/` are development-only; they are not part of the BAT's runtime dependencies.

- `dev/*.tests.ps1` (scan, server, cli, launcher, report, update, integration): deterministic, mocks and synthetic filesystem fixtures, Windows PowerShell 5.1. `dev/ui.tests.ps1` additionally requires PowerShell 7 and Node.js.
- `dev/update.live.tests.ps1` (opt-in, `ELO_LIVE_UPDATE_TEST=1`, administrator, network, ~1.5 GB): updates, restores and rolls back scratch Temurin 17, Zulu 17 and Zulu 8 runtimes through the server API using the real vendor APIs.
- `dev/e2e/wizard.e2e.js` (opt-in, `ELO_E2E=1`, Chrome and `npm install --prefix dev/e2e`): drives the real server in a real browser through scan, update, report, restore and start over on a disposable runtime.
- `dev/build-bat.ps1` regenerates the embedded blocks of the BAT from `dev/`; run it after editing any source there.

Community content, AI output and remotely supplied catalogs must not directly authorize arbitrary commands.
