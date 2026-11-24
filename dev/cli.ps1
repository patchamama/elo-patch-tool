# Windows PowerShell 5.1. Safe to dot-source; no startup work or file dependencies.
# Embedders load trusted scanner/backend code first, then invoke Invoke-EloCli.
function Get-EloCliReadme {
@'
ELO Patch Tools - built-in README
================================
Usage (embedded launcher): ELO-Patch-Tools.bat [options]
  --help                  Show this complete README; no scan or changes.
  --cli                   Select command-line mode (default here). Read-only modes
                          are noninteractive; modifications require a live console.
  --scan                  Read-only discovery of exact drive-root Java layouts.
  --json                  Emit one JSON report (including errors); no progress noise.
  --manual-path "D:\ELO"   Add a literal local directory; searched after root checks.
  --manual                Show manual mitigation/recovery instructions; no scan.
  --no-browser            Never open a browser (this module never does).
  --keep-temp             Retain launcher extraction for diagnosis if supported.
                          This module creates no temporary files; the launcher owns cleanup.
  --mitigate --target N   Request mitigation for zero-based result index N.
  --confirm-admin         Explicitly declare administrative change authorization.
  --confirm-mitigation    Explicitly authorize the documented global mitigation.
                          Both flags AND an actual admin check are required, but
                          are NOT consent to apply. After the exact dynamic preview,
                          type APPLY MITIGATION at a live interactive console.
                          Denial, EOF, redirected input/output or no console abort.
  --update-runtime        Separate option: update the selected runtime to the newest release of its branch
                          (Eclipse Temurin / Azul Zulu). Needs --target N --confirm-admin --confirm-update and
                          a typed APPLY UPDATE; a verified backup ZIP and automatic rollback are included.
No credentials, arbitrary commands, downloads, automatic updates or restarts.
Unknown/duplicate options, conflicting modes and malformed paths are rejected.
Quote paths with spaces. UNC, relative, device and command-like paths are rejected.

Examples:
  ELO-Patch-Tools.bat --help
  ELO-Patch-Tools.bat --cli --scan --json --no-browser
  ELO-Patch-Tools.bat --scan --manual-path "D:\ELO Server"
  ELO-Patch-Tools.bat --cli --mitigate --target 0 --confirm-admin --confirm-mitigation

Technical HTML report (web mode):
Launch the BAT without --cli, select English or German, then use Download technical
HTML report. This authenticated, read-only operation reports sanitized scanner and
session evidence, server/Windows/RAM/disk metadata and vendor-specific guidance.
The HTML includes session scan state; partial/cancelled/failed scans are not complete
assessments. Earlier session observations are retained. No credentials are requested
or stored: an official installation-specific ELO API contract is not verified and
ELO version remains unknown. Machine-option readback and disposable JVM flag probes
are separate scopes; neither proves mitigation in the currently running ELO process.
The CLI updates a runtime only with --update-runtime plus a typed confirmation; the web interface offers the same update step by step.
CLI JSON and UI JSON exports are raw diagnostics, NOT this sanitized HTML report.
Review raw exports before sharing; never enter secrets into paths or JVM options.

Security/evidence:
Scanning does not write ELO files or machine configuration. It may execute trusted
local java.exe -version, which is code execution: scan trusted installations only.
The packaged launcher checks ready fixed or removable drives C: through Z: for
\java\bin\java.exe and \ELO\java\bin\java.exe at each drive root. An optional
manual directory is searched after root checks, with depth 5 and 10,000 entries.
Discovery is not exhaustive; errors, limits or cancellation can reduce coverage.
A missing match is not proof of absence or safety; ELO ownership is not verified.
Reports retain raw version evidence, errors, coverage and scanner source references.
PotentiallyVulnerable is conservative classification, not confirmed exploitability.
The scanner's supplied Temurin source refers to November 2026 (2026-11):
https://adoptium.net/news/2026/11/temurin-november-2026-cspu-java4shell/
Parent verification date: 2026-11-23. Official Adoptium vendor advisory above and
Oracle Linux https://linux.oracle.com/cve/CVE-2026-114938.html were directly fetched.
OpenJDK https://openjdk.org/groups/vulnerability/advisories/2026-11-17 was reviewed
as user-supplied text, NOT independently fetched. This module does not fetch sources.
Unknown JVM vendors/builds remain inconclusive; no ELO compatibility or whole-system
security claim follows from source verification or a KnownFixed classification.
Validate vendor advisories and ELO support/compatibility before taking action.
JSON contains local paths and raw evidence: review it before sharing.

Manual mitigation and recovery (performed by an authorized administrator):
1. Verify the affected vendor/build and supported ELO JVM configuration. Record the
   exact current options, whether JAVA_TOOL_OPTIONS exists, and its registry type.
   Keep a durable backup outside this tool; session-only backup is lost on exit.
2. Temporarily append -XX:-UseBASE64Intrinsics to supported JVM startup options.
   Preserve existing options exactly; do not replace them or duplicate the flag.
   A separate backend may append it to MACHINE JAVA_TOOL_OPTIONS: this affects ALL
   future inheriting JVMs, not just ELO, and can break unrelated applications.
3. Test the target JVM with -XX:+PrintFlagsFinal -version and confirm the final
   UseBASE64Intrinsics value is false. Unsupported flags must abort the change.
4. Existing JVMs are NOT protected. Coordinate service environment propagation and
   a supported restart separately; this tool never restarts services. A disposable
   probe does not prove the running ELO service inherited the option.
5. On failure restore the exact previous options/type (delete JAVA_TOOL_OPTIONS if
   previously absent). Verify readback and the actual service configuration. If
   backend rollback fails, stop and perform manual recovery before any retry.
6. For permanent runtime updates consult ELO/vendor support, verify provenance,
   compatibility and architecture, back up the runtime/configuration, and plan and
   test replacement and restoration. Runtime update: use the web interface or --update-runtime (verified backup, rollback and a typed confirmation).

Trusted embedding contract:
Dot-source this module without side effects. Invoke-EloCli accepts string[] Arguments,
Scanner scriptblock (ManualPath -> Invoke-EloJavaScan-shaped result), and optional
Actions hashtable of IsAdmin(), Preview(result), Apply(preview) scriptblocks. Only
trusted packaged code may supply adapters; command-line input cannot select code.
Default Scanner calls the already loaded Invoke-EloJavaScan; missing APIs fail closed.
New-EloCliBackendAdapters bridges an existing trusted backend Session to
ConvertTo-EloUiResults, New-EloMitigationPreview and Invoke-EloMitigation without HTTP.
The session must be fresh/idle with no worker or recovery pending. Backend retains
ownership of eligibility, fingerprint, expiry, option preservation, probes, backup,
write/readback and rollback. CLI itself never writes ELO or environment settings.
Preview is printed BEFORE confirmation and included in the final report. Console
adapters IsInteractive(), Write(text), ReadLine() are injectable trusted scriptblocks.
The default console writes previews/prompts to stderr, keeping JSON stdout clean.
Noninteractive actions refuse even with confirmation flags. Read-only modes never
access the console adapters. The exact case-sensitive answer APPLY MITIGATION is
required after preview; EOF, denial or console failure cannot reach Apply.
Backend preview Summary must contain exact current/proposed JAVA_TOOL_OPTIONS and
Warnings must describe scope/recovery. The backend revalidates its preview on Apply.
Invoke-EloCli returns { ExitCode, Output }; the embedding launcher emits Output and
propagates ExitCode. Direct execution does this too. No sibling files are loaded.
--no-browser/--keep-temp are returned as launcher hints, not cleanup guarantees.
Exit codes: 0 success/help/manual; 1 failed/cancelled scan or action; 2 invalid usage;
3 reserved. Only modification requests prompt; no credentials.
'@
}

function New-EloCliBackendAdapters {
    param([Parameter(Mandatory=$true)][hashtable]$Session)
    # These blocks capture only a trusted session, never a CLI-supplied code string.
    $admin = { & $Session.Adapters.Admin }.GetNewClosure()
    $preview = {
        param($Result)
        if ($Session.Worker -or $Session.RecoveryRequired -or $Session.State -ne 'idle') {
            throw 'fresh_idle_backend_session_required'
        }
        $null = ConvertTo-EloUiResults $Session ([pscustomobject]@{ Results=@($Result) })
        $Session.State = 'completed'
        $ids = @($Session.Targets.Keys)
        if ($ids.Count -ne 1) { throw 'backend_target_mapping_failed' }
        $view = New-EloMitigationPreview $Session $ids[0]
        @{ Summary=$view.summary.en; Warnings=$view.warnings; View=$view
           ResultId=$ids[0]; PreviewId=$view.previewId }
    }.GetNewClosure()
    $apply = {
        param($Preview)
        if ($Session.RecoveryRequired -or $Session.Worker -or $Session.State -ne 'completed') {
            throw 'backend_not_ready'
        }
        Invoke-EloMitigation $Session ([pscustomobject]@{
            resultId=$Preview.ResultId; previewId=$Preview.PreviewId; actionId='mitigate'
        })
    }.GetNewClosure()
    $updatePreview = {
        param($Result)
        if ($Session.Worker -or $Session.RecoveryRequired -or $Session.State -ne 'idle') {
            throw 'fresh_idle_backend_session_required'
        }
        $null = ConvertTo-EloUiResults $Session ([pscustomobject]@{ Results=@($Result) })
        $Session.State = 'completed'
        $ids = @($Session.Targets.Keys)
        if ($ids.Count -ne 1) { throw 'backend_target_mapping_failed' }
        $view = New-EloRuntimeUpdatePreview $Session $ids[0]
        @{ Summary=$view.summary.en; Warnings=$view.warnings; View=$view
           ResultId=$ids[0]; PreviewId=$view.previewId }
    }.GetNewClosure()
    $updateApply = {
        param($Preview)
        if ($Session.RecoveryRequired -or $Session.Worker -or $Session.State -ne 'completed') {
            throw 'backend_not_ready'
        }
        Invoke-EloRuntimeUpdateAction $Session ([pscustomobject]@{
            resultId=$Preview.ResultId; previewId=$Preview.PreviewId; actionId='update-runtime'
        })
    }.GetNewClosure()
    @{ IsAdmin=$admin; Preview=$preview; Apply=$apply; UpdatePreview=$updatePreview; UpdateApply=$updateApply }
}

function New-EloCliConsole {
    @{
        IsInteractive = {
            # Refuse redirected streams, non-console hosts and PowerShell -NonInteractive.
            # Embedders with another UI must supply a trusted equivalent adapter.
            try {
                $nonInteractive = @([Environment]::GetCommandLineArgs() | Where-Object { $_ -match '^(?i)[-/]noni' }).Count -gt 0
                [Environment]::UserInteractive -and $Host.Name -eq 'ConsoleHost' -and
                    -not $nonInteractive -and -not [Console]::IsInputRedirected -and
                    -not [Console]::IsOutputRedirected -and -not [Console]::IsErrorRedirected
            } catch { $false }
        }
        Write = { param($Text) [Console]::Error.WriteLine([string]$Text) }
        ReadLine = { [Console]::ReadLine() }
    }
}

function Invoke-EloCli {
    param(
        [string[]]$Arguments = @(),
        [scriptblock]$Scanner = { param($ManualPath) Invoke-EloJavaScan -ManualPath $ManualPath -ErrorAction Stop },
        [hashtable]$Actions = @{},
        [hashtable]$Console = (New-EloCliConsole)
    )
    $ErrorActionPreference = 'Stop'
    $report = [ordered]@{ readOnly=$true; noBrowser=$true; keepTemp=$false
        security=@{ verifiedOn='2026-11-23'; sourceDate='2026-11'
            source='https://adoptium.net/news/2026/11/temurin-november-2026-cspu-java4shell/'
            provenance='Parent verification supplied to this module; no runtime fetching.'
            advisories=@(
                @{ url='https://adoptium.net/news/2026/11/temurin-november-2026-cspu-java4shell/'; provenance='Official Adoptium vendor advisory directly fetched by parent.' },
                @{ url='https://linux.oracle.com/cve/CVE-2026-114938.html'; provenance='Oracle Linux source directly fetched by parent.' },
                @{ url='https://openjdk.org/groups/vulnerability/advisories/2026-11-17'; provenance='User-supplied OpenJDK text reviewed by parent; not independently fetched.' }
            )
            warning='Unknown JVM vendors/builds remain inconclusive; source verification is not ELO compatibility verification or proof of whole-system safety or exploitability.' }
        scan=$null; action=$null; error=$null }
    $code = 2
    # JSON is recognized early so even malformed command lines receive JSON errors.
    $json = $Arguments -ccontains '--json'
    try {
        $options = @{}
        $allowed = @('--help','--cli','--scan','--json','--no-browser','--keep-temp',
            '--manual-path','--manual','--mitigate','--target','--confirm-admin',
            '--confirm-mitigation','--confirm-update','--update-runtime')
        for ($i=0; $i -lt $Arguments.Count; $i++) {
            $arg = $Arguments[$i]
            if ($allowed -cnotcontains $arg -or $options.ContainsKey($arg)) { throw 'Unknown or duplicate option.' }
            $value = $true
            if ($arg -cin @('--manual-path','--target')) {
                $i++
                if ($i -ge $Arguments.Count -or $Arguments[$i].StartsWith('--')) { throw 'Missing option value.' }
                $value = $Arguments[$i]
            }
            $options[$arg] = $value
        }
        $modes = @('--help','--manual','--mitigate','--update-runtime') | Where-Object { $options.ContainsKey($_) }
        if (@($modes).Count -gt 1 -or ($options.ContainsKey('--scan') -and @($modes).Count -gt 0)) { throw 'Conflicting modes.' }
        $isAction = $options.ContainsKey('--mitigate') -or $options.ContainsKey('--update-runtime')
        if (-not $isAction -and
            ($options.ContainsKey('--target') -or $options.ContainsKey('--confirm-admin') -or $options.ContainsKey('--confirm-mitigation') -or $options.ContainsKey('--confirm-update'))) {
            throw 'Action arguments require --mitigate or --update-runtime.'
        }
        if ($options.ContainsKey('--mitigate') -and $options.ContainsKey('--confirm-update')) { throw 'Use --confirm-mitigation with --mitigate.' }
        if ($options.ContainsKey('--update-runtime') -and $options.ContainsKey('--confirm-mitigation')) { throw 'Use --confirm-update with --update-runtime.' }
        if ($options.ContainsKey('--help') -or $options.ContainsKey('--manual')) {
            $text = Get-EloCliReadme
            if ($json) { $text = @{ readme=$text } | ConvertTo-Json -Depth 4 }
            return [pscustomobject]@{ ExitCode=0; Output=$text }
        }
        $report.keepTemp = $options.ContainsKey('--keep-temp')
        $manualPath = $null
        if ($options.ContainsKey('--manual-path')) {
            $manualPath = [string]$options['--manual-path']
            if ($manualPath.Length -gt 1024 -or $manualPath -cnotmatch '^[A-Za-z]:\\' -or
                $manualPath -match '[\x00-\x1f\x7f"<>|?*/;`$]' -or $manualPath.Substring(2).Contains(':')) { throw 'Invalid literal local manual path.' }
            foreach ($part in $manualPath.Substring(3).Split('\')) {
                if ($part -match '[. ]$' -or $part -match '^(?i:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)') { throw 'Invalid path component.' }
            }
        }
        # Both actions share one flow: preview, render, typed confirmation, apply.
        $kind = 'mitigation'; $confirmFlag = '--confirm-mitigation'; $phrase = 'APPLY MITIGATION'; $previewName = 'Preview'; $applyName = 'Apply'
        if ($options.ContainsKey('--update-runtime')) { $kind = 'update'; $confirmFlag = '--confirm-update'; $phrase = 'APPLY UPDATE'; $previewName = 'UpdatePreview'; $applyName = 'UpdateApply' }
        if ($isAction) {
            if (-not $options.ContainsKey('--target') -or [string]$options['--target'] -cnotmatch '^(0|[1-9][0-9]{0,5})$' -or
                -not $options.ContainsKey('--confirm-admin') -or -not $options.ContainsKey($confirmFlag)) {
                throw ($(if ($kind -eq 'update') { 'Update' } else { 'Mitigation' }) + ' requires --target N --confirm-admin '+$confirmFlag+'; read --help first.')
            }
            $code = 1
            foreach ($name in @('IsAdmin',$previewName,$applyName)) {
                if ($Actions[$name] -isnot [scriptblock]) { throw 'Trusted action backend not available.' }
            }
            if ((& $Actions.IsAdmin) -ne $true) { throw 'Administrator privileges required.' }
        }
        $code = 1
        $scan = & $Scanner $manualPath
        if ($null -eq $scan -or $null -eq $scan.Results -or $null -eq $scan.Cancelled) { throw 'Invalid scanner response.' }
        $report.scan = $scan
        if ($scan.Cancelled) { throw 'Scan cancelled; no action performed.' }
        if ($isAction) {
            $index = [int]$options['--target']; $rows = @($scan.Results)
            # A mitigation needs a potentially vulnerable JVM; an update only needs a runtime the backend can identify.
            if ($index -ge $rows.Count -or ($kind -eq 'mitigation' -and $rows[$index].Status -cne 'PotentiallyVulnerable')) { throw 'Target not eligible.' }
            $preview = & $Actions[$previewName] $rows[$index]
            if ($null -eq $preview -or [string]::IsNullOrWhiteSpace([string]$preview.Summary)) { throw 'Backend preview required.' }
            $report.action = @{ preview=$preview; result=$null }
            foreach ($name in @('IsInteractive','Write','ReadLine')) {
                if ($Console[$name] -isnot [scriptblock]) { throw 'Interactive console required; no action performed.' }
            }
            if ((& $Console.IsInteractive) -ne $true) { throw 'Interactive console required; noninteractive action refused.' }
            # Suppress adapter return values so they cannot pollute the JSON success stream.
            # Render before reading: flags alone can never authorize a mutation.
            $null = & $Console.Write ([string]$preview.Summary)
            if ($null -ne $preview.Warnings) {
                $null = & $Console.Write (ConvertTo-Json -InputObject $preview.Warnings -Depth 10)
            }
            $null = & $Console.Write ('Type '+$phrase+' to authorize this exact preview; anything else cancels:')
            $answer = & $Console.ReadLine
            if ($answer -isnot [string] -or $answer -cne $phrase) { throw ($(if ($kind -eq 'update') { 'Update' } else { 'Mitigation' }) + ' cancelled; no action performed.') }
            if ((& $Actions.IsAdmin) -ne $true) { throw 'Administrator privileges required.' }
            $report.readOnly = $false
            $result = & $Actions[$applyName] $preview
            $report.action.result = $result
            if ($null -eq $result -or $result.ok -ne $true) { throw 'Backend did not confirm success.' }
        }
        $code = 0
    } catch { $report.error = $_.Exception.Message }
    if ($json) { $output = ConvertTo-Json -InputObject $report -Depth 30 -Compress }
    else {
        # JSON in text mode too: preserves full raw evidence, coverage and action details.
        $output = "ELO Patch Tools (result indexes start at 0)`r`n" + (ConvertTo-Json -InputObject $report -Depth 30)
    }
    [pscustomobject]@{ ExitCode=$code; Output=$output }
}

if ($MyInvocation.InvocationName -ne '.') {
    $response = Invoke-EloCli -Arguments $args
    Write-Output $response.Output
    exit $response.ExitCode
}
