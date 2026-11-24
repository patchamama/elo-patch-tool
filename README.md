# ELO Patch Tools

A Windows proof-of-concept for investigating CVE-2026-114938 in Java runtimes that may be associated with ELO DMS. The runnable application is the self-contained `ELO-Patch-Tools.bat`; `dev/` contains development sources and tests and is not required to run it.

> **Status: incomplete; test environments only.** The web interface can replace an Eclipse Temurin 17 (x64) runtime with a pinned official Temurin 17.0.21.1+2 after explicit confirmation (verified backup ZIP, pinned HTTPS download and SHA256, Java self-test, automatic rollback); it was verified live on a disposable Temurin runtime only. Other vendors (for example Azul Zulu), other Java branches and ARM64 are refused. ELO API version lookup is unavailable. Web `--no-browser` is unavailable. End-to-end browser testing, live mitigation, and independent security verification are outstanding. Do not use this candidate as proof that a production installation is protected.

## Requirements

- Windows with Windows PowerShell 5.1; the host execution policy must permit execution. The launcher does not override that policy.
- A local administrator session only for the optional machine-wide mitigation. Read-only scanning does not require elevation, although permissions may limit coverage.
- Run discovery only on trusted installations: obtaining a version executes the discovered `java.exe`.

## Quick start

```bat
ELO-Patch-Tools.bat --help
ELO-Patch-Tools.bat
ELO-Patch-Tools.bat --cli --scan --json
ELO-Patch-Tools.bat --cli --scan --manual-path "D:\ELO Server"
ELO-Patch-Tools.bat --cli --manual
```

Without options, the tool starts a local web interface. Read-only CLI scans do not prompt. Automatic discovery checks only `C:\java\bin\java.exe` and `C:\ELO\java\bin\java.exe`, and the equivalent root layouts on other ready fixed or removable drives from C: through Z:. It can return multiple installations; it does not establish ELO ownership. If Java is elsewhere, supply a local directory in the web interface or with `--manual-path`; after the root checks, the scanner searches that directory with a depth limit of 5 and an entry budget of 10,000. Errors, skipped reparse points, cancellation and limits can leave coverage incomplete; a missing finding does not prove absence. `--keep-temp` retains extracted session resources for diagnosis; normal exit otherwise attempts to remove them, but forced termination may leave them behind. In CLI mode, `--no-browser` is accepted; in web mode it currently fails explicitly because a private launch handler is not packaged.

## Safety and limitations

- The optional mitigation changes machine-wide `JAVA_TOOL_OPTIONS` and can affect other Java applications. It requires administrator privileges, an explicit preview and confirmation. Save the previous value and type independently: the automatic rollback backup is session-only.
- The flag `-XX:-UseBASE64Intrinsics` is a **temporary mitigation**, not a Java update. Existing Java processes are not automatically protected or restarted. A new-JVM probe does not prove the running ELO service inherited the option.
- The HTML technical report is available in English and German from the web interface. It includes available Windows, memory and disk information, findings, session evidence and official references. ELO product version remains unknown until an installation-specific API contract is verified. Raw JSON exports may include local paths and diagnostics; review them before sharing.
- No compatibility approval by ELO is claimed. Consult ELO and the JVM vendor before replacing a runtime. The runtime update is a separate, confirmed action; it stops no service and restarts none (a running ELO service blocks the update), and it never deletes the backup ZIP or the previous runtime. The technical report lists the ZIP and the PowerShell/cmd commands to restore it.
- Version rules are conservative and limited to identifiable Temurin builds. Unknown vendors or builds remain inconclusive; potential vulnerability does not establish exploitability.

## Security information

Information was checked on **2026-11-23**: the [Adoptium Temurin advisory](https://adoptium.net/news/2026/11/temurin-november-2026-cspu-java4shell/) and [Oracle Linux CVE record](https://linux.oracle.com/cve/CVE-2026-114938.html) were fetched directly. The [OpenJDK advisory](https://openjdk.org/groups/vulnerability/advisories/2026-11-17) was reviewed as user-supplied text because direct retrieval returned HTTP 403. Advisories can change; check the current vendor guidance.

## Development tests

The scripts in `dev/` are development-only; they are not part of the BAT's runtime dependencies. Focused tests include `dev/scan.tests.ps1`, `dev/server.tests.ps1`, `dev/cli.tests.ps1`, `dev/launcher.tests.ps1`, `dev/report.tests.ps1`, `dev/update.tests.ps1`, and `dev/integration.tests.ps1`. The UI test `dev/ui.tests.ps1` additionally requires PowerShell 7 and Node.js. Update tests use mocks and memory fixtures. `dev/update.live.tests.ps1` is an opt-in live test for a disposable machine (set `ELO_LIVE_UPDATE_TEST=1`, run as administrator with network access): it updates, restores and rolls back a scratch Temurin 17.0.2 runtime through the server API. `dev/build-bat.ps1` regenerates the embedded blocks of the BAT from `dev/`; run it after editing any source there.

Planned work includes supporting further vendors for the runtime update (Azul Zulu is the runtime found on the test ELO host and is currently refused), independently verifying security boundaries, integrating a verified ELO API, and the separately deferred wizard and security-catalog features. Community content, AI output and remotely supplied catalogs must not directly authorize arbitrary commands.
