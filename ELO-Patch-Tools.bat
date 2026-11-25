@echo off
setlocal DisableDelayedExpansion
rem Single-file tool. A runtime update runs only after explicit confirmation.
rem Use normal cmd quoting; do not invoke with CALL (second expansion is unsafe).
rem For percent-delimited names in the BAT path invoke via a quoted path variable.
rem Production never overrides execution policy. Extracted scripts must be allowed
rem by local policy; AllSigned/Restricted may prevent startup. No bypass fallback.
set "ELO_PATCH_SOURCE=%~f0"
set "ELO_PATCH_SESSION="
rem Only an ASCII session ID crosses FOR /F; Unicode TEMP paths stay in the environment.
set "ELO_PATCH_BASE=%TEMP%"
if not defined ELO_PATCH_BASE set "ELO_PATCH_BASE=%TMP%"
if not defined ELO_PATCH_BASE exit /b 1
for /f "usebackq delims=" %%D in (`powershell.exe -NoProfile -NonInteractive -Command "$ErrorActionPreference='Stop'; $dir=$null; try { $files=@{BOOTSTRAP_PS='launcher.ps1';BACKEND_PS='backend.ps1';SCAN_PS='scan.ps1';SERVER_PS='server.ps1';CLI_PS='cli.ps1';UI_HTML='ui.html';REPORT_PS='report.ps1';UPDATE_PS='update.ps1';CATALOG_PS='catalog.ps1';VULNDB_PS='vulndb.ps1';VULNDB_JSON='vulndb.json'}; $blocks=@{}; $active=$null; $buffer=New-Object 'System.Collections.Generic.List[string]'; foreach($line in [IO.File]::ReadAllLines($env:ELO_PATCH_SOURCE,[Text.Encoding]::UTF8)) { if($line.TrimStart().StartsWith('::ELO_PATCH_',[StringComparison]::OrdinalIgnoreCase)) { if($line -cnotmatch '^::ELO_PATCH_(BEGIN|END):(BOOTSTRAP_PS|BACKEND_PS|SCAN_PS|SERVER_PS|CLI_PS|UI_HTML|REPORT_PS|UPDATE_PS|CATALOG_PS|VULNDB_PS|VULNDB_JSON)$') { throw 'Malformed extraction marker' }; $kind=$Matches[1]; $name=$Matches[2]; if($kind -ceq 'BEGIN') { if($null -ne $active -or $blocks.ContainsKey($name)) { throw 'Duplicate or nested extraction marker' }; $active=$name; $buffer.Clear() } else { if($active -cne $name) { throw 'Unmatched extraction marker' }; $blocks[$name]=[string]::Join([Environment]::NewLine,$buffer); $active=$null } } elseif($null -ne $active) { $buffer.Add($line) } }; if($null -ne $active -or $blocks.Count -ne $files.Count) { throw 'Missing extraction marker' }; $id=[guid]::NewGuid().ToString('N'); $dir=Join-Path $env:ELO_PATCH_BASE ('elo-patch-'+$id); [void][IO.Directory]::CreateDirectory($dir); foreach($name in $files.Keys) { [IO.File]::WriteAllText((Join-Path $dir $files[$name]),$blocks[$name],[Text.Encoding]::UTF8) }; Write-Output $id } catch { if($null -ne $dir -and [IO.Directory]::Exists($dir)) { [IO.Directory]::Delete($dir,$true) }; [Console]::Error.WriteLine($_.Exception.Message); exit 1 }"`) do set "ELO_PATCH_SESSION=%ELO_PATCH_BASE%\elo-patch-%%D"
if not defined ELO_PATCH_SESSION exit /b 1
rem Keep a live console for CLI confirmation; read-only modes never prompt.
powershell.exe -NoProfile -File "%ELO_PATCH_SESSION%\launcher.ps1" %*
set "ELO_PATCH_EXIT=%errorlevel%"
rem Also clean up when policy prevents the bootstrap from starting.
if exist "%ELO_PATCH_SESSION%\launcher.ps1" if not exist "%ELO_PATCH_SESSION%\keep-temp" powershell.exe -NoProfile -NonInteractive -Command "try { [IO.Directory]::Delete($env:ELO_PATCH_SESSION,$true) } catch { [Console]::Error.WriteLine('Session cleanup failed.'); exit 1 }"
if errorlevel 1 if "%ELO_PATCH_EXIT%"=="0" set "ELO_PATCH_EXIT=1"
exit /b %ELO_PATCH_EXIT%

::ELO_PATCH_BEGIN:BOOTSTRAP_PS
$ErrorActionPreference = 'Stop'
$keepTemp = $false
$code = 1
try {
    $keepCount = @($args | Where-Object { $_ -ceq '--keep-temp' }).Count
    if ($keepCount -gt 1) { throw 'Duplicate --keep-temp option.' }
    $keepTemp = $keepCount -eq 1
    if ($keepTemp) {
        [IO.File]::WriteAllText((Join-Path $PSScriptRoot 'keep-temp'), '')
        [Console]::Error.WriteLine('Retaining extracted resources: ' + $PSScriptRoot)
    }
    . (Join-Path $PSScriptRoot 'backend.ps1') -LoadOnly
    $response = Invoke-EloPackagedTool -Arguments $args
    if ($null -ne $response.Output) { Write-Output $response.Output }
    $code = $response.ExitCode
} catch {
    # Never print arbitrary browser-launch exceptions: they can contain the token.
    [Console]::Error.WriteLine('Packaged tool startup failed; check local script policy and resource integrity.')
    $code = 1
} finally {
    if (-not $keepTemp) {
        try { [IO.Directory]::Delete($PSScriptRoot, $true) }
        catch { [Console]::Error.WriteLine('Session cleanup failed.'); $code = 1 }
    }
}
exit $code
::ELO_PATCH_END:BOOTSTRAP_PS

::ELO_PATCH_BEGIN:BACKEND_PS
# Trusted, packaged adapters only. Dot-sourcing -LoadOnly never starts a scan/server.
param([switch]$LoadOnly)
$script:EloPackagedRoot = $PSScriptRoot
. (Join-Path $PSScriptRoot 'scan.ps1')
. (Join-Path $PSScriptRoot 'server.ps1')
. (Join-Path $PSScriptRoot 'report.ps1')
. (Join-Path $PSScriptRoot 'vulndb.ps1')
. (Join-Path $PSScriptRoot 'catalog.ps1')
. (Join-Path $PSScriptRoot 'update.ps1')
. (Join-Path $PSScriptRoot 'cli.ps1')
function New-EloPackagedActionPair {
    param([scriptblock]$TrustedPreview,[scriptblock]$TrustedApply)
    $private = @{ BackendPreview=$null; PublicPreview=$null }
    # The CLI serializes its preview into its report. Keep backend capability IDs
    # in this closure, never in that public report or the console preview.
    $preview = {
        param($Result)
        $private.BackendPreview = & $TrustedPreview $Result
        $private.PublicPreview = @{
            Summary=$private.BackendPreview.Summary
            Warnings=$private.BackendPreview.Warnings
        }
        $private.PublicPreview
    }.GetNewClosure()
    $apply = {
        param($Preview)
        if (-not [object]::ReferenceEquals($Preview,$private.PublicPreview) -or -not $private.BackendPreview) {
            throw 'Packaged preview mismatch.'
        }
        $backendPreview = $private.BackendPreview
        $private.BackendPreview = $null; $private.PublicPreview = $null
        & $TrustedApply $backendPreview
    }.GetNewClosure()
    @{ Preview=$preview; Apply=$apply }
}
function New-EloPackagedCliActions {
    param([hashtable]$Session)
    $trusted = New-EloCliBackendAdapters -Session $Session
    $mitigation = New-EloPackagedActionPair $trusted.Preview $trusted.Apply
    $update = New-EloPackagedActionPair $trusted.UpdatePreview $trusted.UpdateApply
    @{ IsAdmin=$trusted.IsAdmin; Preview=$mitigation.Preview; Apply=$mitigation.Apply; UpdatePreview=$update.Preview; UpdateApply=$update.Apply }
}
function Invoke-EloPackagedTool {
    param([string[]]$Arguments = @())
    $ErrorActionPreference = 'Stop'
    if ($Arguments -ccontains '--cli' -or $Arguments -ccontains '--help') {
        $scan = {
            param($ManualPath)
            $roots = @([IO.DriveInfo]::GetDrives() | Where-Object {
                $_.IsReady -and $_.DriveType -in @([IO.DriveType]::Fixed,[IO.DriveType]::Removable)
            } | ForEach-Object { $_.RootDirectory.FullName })
            Invoke-EloJavaScan -DriveRoots $roots -ManualPath $ManualPath -ErrorAction Stop
        }
        $actions = @{}
        if ($Arguments -ccontains '--mitigate' -or $Arguments -ccontains '--update-runtime') {
            # This creates no listener and performs no machine reads or writes.
            $session = New-EloServerSession -Port 49152 -UiHtml 'CLI session' -ScanSource 'CLI scanner'
            $actions = New-EloPackagedCliActions -Session $session
        }
        $result = Invoke-EloCli -Arguments $Arguments -Scanner $scan -Actions $actions
        # The module README describes its standalone default; clarify the BAT route.
        if ($Arguments -ccontains '--help') {
            $note = 'Packaged launcher: default is web. Use --cli for all non-help CLI modes. Web accepts only --no-browser and --keep-temp. Web --no-browser is unavailable without a trusted private launch handler; this package supplies none and fails explicitly. Runtime update is NOT IMPLEMENTED. Production honors local PowerShell policy. Close the server normally for cleanup; forced termination can leave temporary resources. --keep-temp retains resources, not a durable mitigation backup.'
            if ($Arguments -ccontains '--json' -and $result.ExitCode -eq 0) {
                $help = ConvertFrom-Json $result.Output
                $help.readme = $note + "`r`n`r`n" + $help.readme
                $result.Output = ConvertTo-Json $help -Depth 4
            } elseif ($result.ExitCode -eq 0) { $result.Output = $note + "`r`n`r`n" + $result.Output }
        }
        return $result
    }
    $seen = @{}
    foreach ($argument in $Arguments) {
        if ($argument -cnotin @('--no-browser','--keep-temp') -or $seen.ContainsKey($argument)) {
            return [pscustomobject]@{ ExitCode=2; Output='Invalid web option. Use --help or --cli for command-line modes.' }
        }
        $seen[$argument] = $true
    }
    try {
        $html = [IO.File]::ReadAllText((Join-Path $script:EloPackagedRoot 'ui.html'),[Text.Encoding]::UTF8)
        $source = [IO.File]::ReadAllText((Join-Path $script:EloPackagedRoot 'scan.ps1'),[Text.Encoding]::UTF8)
        Start-EloServer -UiHtml $html -ScanSource $source -NoBrowser:($seen.ContainsKey('--no-browser'))
        return [pscustomobject]@{ ExitCode=0; Output=$null }
    } catch {
        $failure = ConvertTo-EloErrorResponse $_.Exception
        # Stable error codes only; no exception text or launch URI reaches console.
        [Console]::Error.WriteLine($failure.Body.error)
        if ($failure.Body.error -ceq 'no_browser_requires_private_launch_handler') {
            [Console]::Error.WriteLine('Web --no-browser is unavailable: no trusted private launch handler is packaged. Use --cli for headless read-only operation.')
        }
        return [pscustomobject]@{ ExitCode=1; Output=$null }
    }
}
if (-not $LoadOnly) {
    $response = Invoke-EloPackagedTool -Arguments $args
    if ($null -ne $response.Output) { Write-Output $response.Output }
    exit $response.ExitCode
}
::ELO_PATCH_END:BACKEND_PS

::ELO_PATCH_BEGIN:SCAN_PS
# Self-contained Windows PowerShell 5.1 scanner. Dot-source to load; no startup work.
# This does not modify ELO/configuration, download files, or claim exploitability.
# Launching an installed java.exe executes local code; use only on trusted installations.
function Get-EloJavaClassification {
    # Classifies one java -version evidence text against the catalog rules (vulndb.json): one finding per
    # rule, the overall Status is the worst one (PotentiallyVulnerable > Inconclusive > KnownFixed).
    param([AllowEmptyString()][string]$Evidence, $Rules = $null)
    if ($null -eq $Rules -and (Get-Command Get-EloScanRules -CommandType Function -ErrorAction SilentlyContinue)) { $Rules = Get-EloScanRules }
    $usable = @($Rules | Where-Object { $_ -and [string]$_.Parser -ceq 'temurin-build' -and [string]$_.Vendor -ceq 'Temurin' })
    if ($usable.Count -eq 0) { $usable = @(@{ Id = ''; Severity = ''; Fixed = @(); Source = '' }) }
    $findings = @(); $first = $null
    foreach ($rule in $usable) {
        $item = Get-EloJavaClassificationForRule -Evidence $Evidence -Fixed @($rule.Fixed) -Source ([string]$rule.Source)
        if ($null -eq $first) { $first = $item }
        if ($rule.Id) { $findings += [pscustomobject]@{ Id = [string]$rule.Id; Severity = [string]$rule.Severity; Status = $item.Status; Source = $item.Source; Reason = $item.Reason } }
        $rank = @{ PotentiallyVulnerable = 3; Inconclusive = 2; KnownFixed = 1 }
        if ($rank[$item.Status] -gt $rank[$first.Status]) { $first = $item }
    }
    $first | Add-Member -NotePropertyName Findings -NotePropertyValue $findings -Force
    return $first
}
function Get-EloJavaClassificationForRule {
    param([AllowEmptyString()][string]$Evidence, [string[]]$Fixed = @(), [string]$Source = '')
    $source = $Source
    $fixed = @($Fixed)
    $vendor = 'Unknown'
    if ($Evidence -match '(?i)\bTemurin\b') { $vendor = 'Temurin' }
    # Include VM build tokens as well as runtime tokens: conflicting versions must
    # not disappear merely because a VM line ends with ', mixed mode, sharing)'.
    $builds = @([regex]::Matches($Evidence, '(?i)\(build\s+([^\s,)]+)') | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique)
    $build = $null
    $status = 'Inconclusive'
    $reason = 'Vendor/build evidence is unknown or outside the supported comparison rules; exploitability is not determined.'
    $zuluToken = '(?i)\bZulu(?=[0-9]|\b)'
    $otherVendor = '(?i)\b(Oracle|Corretto|Microsoft|GraalVM|Semeru|OpenJ9|Liberica|SapMachine|Dragonwell)\b'
    $conflictingVendor = $Evidence -match $otherVendor -or $Evidence -match $zuluToken
    $runtimeLines = @($Evidence -split '\r?\n' | Where-Object { $_ -match '(?i)Runtime Environment' })
    $foreignRuntime = @($runtimeLines | Where-Object { $_ -notmatch '(?i)\bTemurin\b' }).Count -gt 0
    if ($conflictingVendor -or $foreignRuntime) { $vendor = 'Unknown' }
    # Zulu's product version can immediately follow its name (e.g. Zulu21).
    # Identify the runtime, but never apply Temurin's advisory to it.
    $zuluRuntime = '(?i)\bRuntime Environment\s+(?:Azul\s+)?Zulu(?=[0-9]|\b)'
    if ($runtimeLines.Count -gt 0 -and @($runtimeLines | Where-Object { $_ -notmatch $zuluRuntime }).Count -eq 0 -and $Evidence -notmatch '(?i)\bTemurin\b' -and $Evidence -notmatch $otherVendor) {
        $vendor = 'Azul Zulu'
    }
    # Stable canonical versions only, with bounded numeric components. No EA,
    # custom suffixes, leading zero aliases, or overflow-prone numeric parsing.
    $number = '(?:0|[1-9][0-9]{0,8})'
    $stablePattern = '^([1-9][0-9]{0,2})(?:\.' + $number + '){0,3}\+' + $number + '$'
    if ($builds.Count -eq 1) {
        $build = $builds[0]
        $temurinBuildPattern = '(?im)^.*\bTemurin\b[^\r\n]*\(build\s+' + [regex]::Escape($build) + '(?=[,)])'
        $headers = @([regex]::Matches($Evidence, '(?im)^\s*(?:openjdk|java) version "([^"]+)"') | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique)
        $labels = @([regex]::Matches($Evidence, '(?i)\bTemurin-([0-9][^\s()]+)') | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique)
        $consistent = $headers.Count -le 1 -and $labels.Count -le 1
        if ($headers.Count -eq 1 -and $headers[0] -cne ($build -split '\+')[0]) { $consistent = $false }
        if ($labels.Count -eq 1 -and $labels[0] -cne $build) { $consistent = $false }
        if ($consistent -and $vendor -eq 'Temurin' -and $build -cmatch $stablePattern -and $Evidence -match $temurinBuildPattern) {
            if ($fixed -ccontains $build) {
                $status = 'KnownFixed'
                $reason = 'Exact Temurin build listed as fixed in the supplied advisory; this is not a broader system security assessment.'
            } else {
                $feature = ($build -split '[.+]')[0]
                $milestone = @($fixed | Where-Object { ($_ -split '\.')[0] -eq $feature })
                if ($milestone.Count -eq 1) {
                    $release = ($build -split '\+')[0] -split '\.'
                    $fixedRelease = ($milestone[0] -split '\+')[0] -split '\.'
                    $comparison = 0
                    for ($i = 0; $i -lt 5 -and $comparison -eq 0; $i++) {
                        $left = 0; $right = 0
                        if ($i -lt 4) {
                            if ($i -lt $release.Count) { $left = [int]$release[$i] }
                            if ($i -lt $fixedRelease.Count) { $right = [int]$fixedRelease[$i] }
                        } else {
                            $left = [int]($build -split '\+')[1]
                            $right = [int]($milestone[0] -split '\+')[1]
                        }
                        $comparison = $left.CompareTo($right)
                    }
                    if ($comparison -lt 0) {
                        $status = 'PotentiallyVulnerable'
                        $reason = "Stable Temurin build precedes supplied fixed milestone $($milestone[0]) in feature line $feature. Conservative potential vulnerability only, not confirmed affectedness or exploitability."
                    }
                }
            }
        }
    }
    # java -version often proves only bitness, not the instruction-set architecture.
    $isa = @()
    if ($Evidence -match '(?i)\b(amd64|x86_64|x64)\b') { $isa += 'x64' }
    if ($Evidence -match '(?i)\b(aarch64|arm64)\b') { $isa += 'ARM64' }
    if ($Evidence -match '(?i)\b(i[3-6]86|x86)\b') { $isa += 'x86' }
    $bit64 = $Evidence -match '(?i)\b64-Bit\b'
    $bit32 = $Evidence -match '(?i)\b32-Bit\b'
    $architecture = 'Unknown'
    if ($isa.Count -eq 1 -and -not ($bit64 -and $bit32)) {
        if (-not (($isa[0] -eq 'x86' -and $bit64) -or ($isa[0] -ne 'x86' -and $bit32))) { $architecture = $isa[0] }
    } elseif ($isa.Count -eq 0) {
        if ($bit64 -and -not $bit32) { $architecture = '64-bit' }
        if ($bit32 -and -not $bit64) { $architecture = '32-bit' }
    }
    [pscustomobject]@{ Status = $status; Vendor = $vendor; Build = $build; FullVersion = $build; Architecture = $architecture; Reason = $reason; Source = $source }
}

function Invoke-EloJavaVersion {
    param(
        [Parameter(Mandatory = $true)][string]$JavaPath,
        [ValidateRange(1, 120)][int]$TimeoutSeconds = 10,
        [scriptblock]$ShouldCancel = { $false },
        [string[]]$Arguments = @('-version')
    )
    $result = [ordered]@{ Succeeded = $false; Cancelled = $false; Evidence = ''; Error = $null; ExitCode = $null }
    # Only plain java options from the catalog: never a path, a pipe or a shell construct.
    foreach ($a in @($Arguments)) { if ($a -cnotmatch '^-[A-Za-z0-9:+=_.\-]{1,64}$') { $result.Error = 'Probe arguments are not plain java options.'; return [pscustomobject]$result } }
    $process = $null
    try {
        if (& $ShouldCancel) { $result.Cancelled = $true; return [pscustomobject]$result }
        if (-not [IO.File]::Exists($JavaPath)) { throw 'Java executable does not exist.' }
        $info = New-Object System.Diagnostics.ProcessStartInfo
        $info.FileName = $JavaPath
        $info.Arguments = (@($Arguments) -join ' ')
        $info.UseShellExecute = $false
        $info.CreateNoWindow = $true
        $info.RedirectStandardOutput = $true
        $info.RedirectStandardError = $true
        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $info
        if (-not $process.Start()) { throw 'Java process could not start.' }
        # Drain both streams concurrently to avoid stderr/stdout pipe deadlocks.
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        $clock = [Diagnostics.Stopwatch]::StartNew()
        while (-not $process.WaitForExit(100)) {
            if (& $ShouldCancel) { $result.Cancelled = $true; break }
            if ($clock.Elapsed.TotalSeconds -ge $TimeoutSeconds) { $result.Error = 'Java version probe timed out.'; break }
        }
        if ($result.Cancelled -or $result.Error) {
            if (-not $process.HasExited) { $process.Kill() }
        } else {
            # Inherited pipe handles must not leave the scanner waiting forever.
            $remaining = [Math]::Max(0, [int](1000 * ($TimeoutSeconds - $clock.Elapsed.TotalSeconds)))
            $tasks = [System.Threading.Tasks.Task[]]@($stdout, $stderr)
            if (-not [System.Threading.Tasks.Task]::WaitAll($tasks, $remaining)) { throw 'Java output collection timed out.' }
            $result.Evidence = ($stdout.Result + "`n" + $stderr.Result).Trim()
            $result.ExitCode = $process.ExitCode
            $result.Succeeded = $process.ExitCode -eq 0
            if (-not $result.Succeeded) { $result.Error = 'Java version probe returned a nonzero exit code.' }
        }
    } catch { $result.Error = $_.Exception.Message }
    finally {
        if ($null -ne $process) {
            try { if (-not $process.HasExited) { $process.Kill() } } catch { }
            $process.Dispose()
        }
    }
    [pscustomobject]$result
}

function Get-EloJavaCandidates {
    param(
        [string[]]$DriveRoots,
        [string]$ManualPath,
        [ValidateRange(0, 12)][int]$MaxDepth = 5,
        [ValidateRange(1, 100000)][int]$MaxEntries = 10000,
        [scriptblock]$ShouldCancel = { $false },
        [scriptblock]$GetChildren = { param($Path) Get-ChildItem -LiteralPath $Path -Force -ErrorAction Stop },
        [scriptblock]$IsReparsePoint = { param($Path) ((Get-Item -LiteralPath $Path -Force -ErrorAction Stop).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 }
    )
    $locations = New-Object 'System.Collections.Generic.List[string]'
    $issues = New-Object 'System.Collections.Generic.List[string]'
    $candidates = New-Object 'System.Collections.Generic.List[object]'
    $scanned = New-Object 'System.Collections.Generic.List[string]'
    $attempts = New-Object 'System.Collections.Generic.List[object]'
    $queue = New-Object 'System.Collections.Generic.Queue[object]'
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $seenLocations = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $state = @{ Cancelled = $false; LimitReached = $false; DepthLimitReached = $false; VisitedEntries = 0 }
    # The entry budget applies only to optional manual directory traversal.
    $readChildren = {
        param($Path)
        if (& $ShouldCancel) { $state.Cancelled = $true; return }
        if ($state.VisitedEntries -ge $MaxEntries) { $state.LimitReached = $true; return }
        $attempt = [pscustomobject]@{ Location = $Path; Outcome = 'Inspecting'; EntriesSeen = 0 }
        $attempts.Add($attempt)
        $before = $state.VisitedEntries
        try {
            if (& $IsReparsePoint $Path) {
                $attempt.Outcome = 'SkippedReparsePoint'
                $issues.Add("Skipped reparse point: $Path")
                return
            }
            & $GetChildren $Path | Select-Object -First ($MaxEntries - $state.VisitedEntries) | ForEach-Object {
                if (& $ShouldCancel) { $state.Cancelled = $true }
                if (-not $state.Cancelled) { $state.VisitedEntries++; $_ }
            }
            $scanned.Add($Path)
            $attempt.Outcome = 'Enumerated'
            if ($state.VisitedEntries -ge $MaxEntries) { $state.LimitReached = $true; $attempt.Outcome = 'BudgetBounded' }
            if ($state.Cancelled) { $attempt.Outcome = 'Cancelled' }
        } catch {
            $attempt.Outcome = 'Error'
            $issues.Add("Cannot enumerate ${Path}: $($_.Exception.Message)")
        } finally { $attempt.EntriesSeen = $state.VisitedEntries - $before }
    }
    $drainQueue = {
        while ($queue.Count -gt 0 -and -not $state.Cancelled -and -not $state.LimitReached) {
            if (& $ShouldCancel) { $state.Cancelled = $true; break }
            $item = $queue.Dequeue()
            if (-not $seen.Add($item.Path)) { continue }
            foreach ($entry in @(& $readChildren $item.Path)) {
                if ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) { continue }
                if ($entry.PSIsContainer) {
                    if ($item.Depth -lt $MaxDepth) {
                        $queue.Enqueue([pscustomobject]@{ Path = $entry.FullName; Depth = $item.Depth + 1; EloRoot = $item.EloRoot; Rationale = $item.Rationale })
                    } else { $state.DepthLimitReached = $true }
                } elseif ($entry.Name -ieq 'java.exe') {
                    if ($seenLocations.Add($entry.FullName)) {
                        $locations.Add($entry.FullName)
                        $candidates.Add([pscustomobject]@{ Location = $entry.FullName; EloCandidateRoot = $item.EloRoot; EloPathRationale = $item.Rationale })
                    }
                }
            }
        }
    }
    if (& $ShouldCancel) { $state.Cancelled = $true }
    if (-not $state.Cancelled) {
        if (-not $PSBoundParameters.ContainsKey('DriveRoots')) {
            $DriveRoots = @(67..90 | ForEach-Object { '{0}:\' -f [char]$_ })
        }
        # One layout check: <base><relative> must be a real java.exe below non-reparse folders.
        $checkLayout = {
            param($base, $relative, $rationale)
            do {
                if (& $ShouldCancel) { $state.Cancelled = $true; return }
                $path = $base + $relative
                $attempt = [pscustomobject]@{ Location = $path; Outcome = 'Inspecting'; EntriesSeen = 0 }
                $attempts.Add($attempt)
                try {
                    $parts = $relative -split '\\'
                    $ancestor = $base
                    $skip = $false
                    if (& $IsReparsePoint $ancestor) {
                        $issues.Add("Skipped reparse point: $ancestor")
                        $attempt.Outcome = 'SkippedReparsePoint'; $skip = $true
                    }
                    foreach ($part in $parts) {
                        if ($skip) { break }
                        if (& $ShouldCancel) { $state.Cancelled = $true; $skip = $true; $attempt.Outcome = 'Cancelled'; break }
                        $ancestor += $part
                        if (& $IsReparsePoint $ancestor) {
                            $issues.Add("Skipped reparse point: $ancestor")
                            $attempt.Outcome = 'SkippedReparsePoint'; $skip = $true; break
                        }
                        $ancestor += '\'
                    }
                    if ($skip) { return }
                    foreach ($entry in @(& $GetChildren $path)) {
                        if (& $ShouldCancel) { $state.Cancelled = $true; $attempt.Outcome = 'Cancelled'; break }
                        if (-not $entry.PSIsContainer -and $entry.FullName -ieq $path -and -not ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -and $seenLocations.Add($entry.FullName)) {
                            $locations.Add($entry.FullName)
                            $candidates.Add([pscustomobject]@{ Location = $entry.FullName; EloCandidateRoot = $base; EloPathRationale = $rationale })
                            $attempt.EntriesSeen++
                        }
                    }
                    if (-not $state.Cancelled) { $attempt.Outcome = 'Checked'; $scanned.Add($path) }
                } catch {
                    if ($_.Exception -is [System.Management.Automation.ItemNotFoundException] -or $_.Exception -is [System.IO.DriveNotFoundException] -or $_.Exception.InnerException -is [System.Management.Automation.ItemNotFoundException] -or $_.Exception.InnerException -is [System.IO.DriveNotFoundException] -or $_.FullyQualifiedErrorId -match '^(PathNotFound|DriveNotFound),') {
                        $attempt.Outcome = 'NotFound'
                    } else {
                        $attempt.Outcome = 'Error'
                        $issues.Add("Cannot inspect ${path}: $($_.Exception.Message)")
                    }
                }
            } while ($false)
        }
        foreach ($root in $DriveRoots) {
            if ($root -notmatch '^[C-Z]:\\$') { continue }
            foreach ($relative in @('java\bin\java.exe', 'ELO\java\bin\java.exe')) {
                if (& $ShouldCancel) { $state.Cancelled = $true; break }
                & $checkLayout $root $relative 'Exact drive-root Java layout; ELO ownership is not verified.'
            }
            # Generalized layout: X:\java\bin (first level) and X:\<any folder>\java\bin (second level).
            if (-not $state.Cancelled) {
                $folders = @()
                try {
                    if (-not (& $IsReparsePoint $root)) {
                        $folders = @(& $GetChildren $root | Where-Object { $_.PSIsContainer -and -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) } | Select-Object -First 1000)
                    }
                } catch { $folders = @() }
                foreach ($folder in $folders) {
                    if (& $ShouldCancel) { $state.Cancelled = $true; break }
                    $name = [string]$folder.Name
                    if ($name -ieq 'ELO' -or $name -ieq 'java' -or $name -in @('Windows', '$Recycle.Bin', 'System Volume Information', 'Recovery', 'PerfLogs')) { continue }
                    & $checkLayout ($root + $name + '\') 'java\bin\java.exe' 'Second-level Java layout (X:\<folder>\java\bin); ELO ownership is not verified.'
                }
            }            if ($state.Cancelled) { break }
        }
    }
    if (-not $state.Cancelled -and $ManualPath) {
        $queue.Enqueue([pscustomobject]@{ Path = $ManualPath; Depth = 0; EloRoot = $ManualPath; Rationale = 'User-selected explicit manual directory; ELO ownership is not verified.' })
        & $drainQueue
    }
    [pscustomobject]@{
        Locations = $locations.ToArray(); Candidates = $candidates.ToArray(); Issues = $issues.ToArray(); Cancelled = $state.Cancelled
        LimitReached = $state.LimitReached; DepthLimitReached = $state.DepthLimitReached; VisitedEntries = $state.VisitedEntries
        ScannedLocations = $scanned.ToArray(); CoverageRecords = $attempts.ToArray()
        Coverage = "Exact drive-root Java executables first, then optional manual directory traversal; manual depth $MaxDepth and entry budget $MaxEntries. ScannedLocations lists checked paths and enumerated directories (possibly partial); CoverageRecords lists attempts and outcomes. Absence of results is not proof of absence."
    }
}

function Invoke-EloJavaScan {
    param(
        [string[]]$DriveRoots,
        [string]$ManualPath,
        [ValidateRange(0, 12)][int]$MaxDepth = 5,
        [ValidateRange(1, 100000)][int]$MaxEntries = 10000,
        [scriptblock]$ShouldCancel = { $false },
        [scriptblock]$GetChildren = { param($Path) Get-ChildItem -LiteralPath $Path -Force -ErrorAction Stop },
        [scriptblock]$IsReparsePoint = { param($Path) ((Get-Item -LiteralPath $Path -Force -ErrorAction Stop).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 },
        [scriptblock]$ProbeJava = { param($Path, $Cancel) Invoke-EloJavaVersion -JavaPath $Path -ShouldCancel $Cancel },
        [scriptblock]$ProbeExtra = { param($Path, $ProbeArgs, $Timeout, $Cancel) Invoke-EloJavaVersion -JavaPath $Path -Arguments $ProbeArgs -TimeoutSeconds $Timeout -ShouldCancel $Cancel },
        $Rules = $null
    )
    $arguments = @{ ManualPath = $ManualPath; MaxDepth = $MaxDepth; MaxEntries = $MaxEntries; ShouldCancel = $ShouldCancel; GetChildren = $GetChildren; IsReparsePoint = $IsReparsePoint }
    if ($PSBoundParameters.ContainsKey('DriveRoots')) { $arguments.DriveRoots = $DriveRoots }
    $discovery = Get-EloJavaCandidates @arguments
    $results = New-Object 'System.Collections.Generic.List[object]'
    $cancelled = $discovery.Cancelled
    foreach ($candidate in $discovery.Candidates) {
        $location = $candidate.Location
        if ($cancelled -or (& $ShouldCancel)) { $cancelled = $true; break }
        try { $probe = & $ProbeJava $location $ShouldCancel }
        catch { $probe = [pscustomobject]@{ Succeeded = $false; Cancelled = $false; Evidence = ''; Error = $_.Exception.Message; ExitCode = $null } }
        $classification = Get-EloJavaClassification -Evidence $probe.Evidence -Rules $Rules
        # Catalog entries of method probe-expect run their own java probe and match the output with expect patterns.
        $hadVersionRules = (@($classification.Findings).Count -gt 0); $probeStatuses = @()
        foreach ($rule in @($Rules | Where-Object { $_ -and [string]$_.Method -ceq 'probe-expect' })) {
            if (& $ShouldCancel) { break }
            $extra = $null
            try { $extra = & $ProbeExtra $location @($rule.ProbeArgs) ([int]$rule.TimeoutSec) $ShouldCancel } catch { $extra = $null }
            $fs = 'Inconclusive'; $fr = 'The catalog probe did not complete; the vulnerability is not determined.'
            if ($extra -and $extra.Succeeded) {
                try {
                    $re = New-Object Text.RegularExpressions.Regex([string]$rule.VulnerablePattern, [Text.RegularExpressions.RegexOptions]::None, [TimeSpan]::FromSeconds(2))
                    if ($re.IsMatch([string]$extra.Evidence)) { $fs = 'PotentiallyVulnerable'; $fr = 'The catalog probe output matches the vulnerable pattern.' }
                    elseif ($rule.SafePattern -and (New-Object Text.RegularExpressions.Regex([string]$rule.SafePattern, [Text.RegularExpressions.RegexOptions]::None, [TimeSpan]::FromSeconds(2))).IsMatch([string]$extra.Evidence)) { $fs = 'KnownFixed'; $fr = 'The catalog probe output matches the safe pattern.' }
                    else { $fr = 'The catalog probe output matches neither the vulnerable nor the safe pattern.' }
                } catch { $fr = 'The catalog pattern could not be evaluated.' }
            }
            $classification.Findings = @($classification.Findings) + [pscustomobject]@{ Id = [string]$rule.Id; Severity = [string]$rule.Severity; Status = $fs; Source = [string]$rule.Source; Reason = $fr }
            $rank = @{ PotentiallyVulnerable = 3; Inconclusive = 2; KnownFixed = 1 }
            $probeStatuses += $fs
            if ($hadVersionRules) {
                if ($rank[$fs] -gt $rank[$classification.Status] -or ($fs -ceq 'Inconclusive' -and $classification.Status -ceq 'KnownFixed')) { $classification.Status = $fs; $classification.Reason = $fr; $classification.Source = [string]$rule.Source }
            }
        }
        if (-not $hadVersionRules -and $probeStatuses.Count -gt 0) {
            $worst = 'KnownFixed'; foreach ($s in $probeStatuses) { if ($rank[$s] -gt $rank[$worst]) { $worst = $s } }
            $classification.Status = $worst; $last = @($classification.Findings)[-1]; $classification.Reason = $last.Reason; $classification.Source = $last.Source
        }        if (-not $probe.Succeeded) { $classification.Status = 'Inconclusive'; $classification.Reason = 'Java version probe did not complete successfully; exploitability is not determined.' }
        $runtimeRoot = Split-Path -Path $location -Parent
        $rootReason = 'Executable directory; runtime layout is not verified.'
        if ((Split-Path -Path $runtimeRoot -Leaf) -ieq 'bin') {
            $runtimeRoot = Split-Path -Path $runtimeRoot -Parent
            $rootReason = 'Parent of bin/java.exe; inferred runtime layout, not verified by configuration.'
        }
        $results.Add([pscustomobject]@{
            Location = $location; RuntimeRoot = $runtimeRoot; RuntimeRootRationale = $rootReason
            EloCandidateRoot = $candidate.EloCandidateRoot; EloPathRationale = $candidate.EloPathRationale
            FullVersion = $classification.FullVersion; Architecture = $classification.Architecture
            Status = $classification.Status; Vendor = $classification.Vendor; Build = $classification.Build
            Evidence = $probe.Evidence; Error = $probe.Error; ExitCode = $probe.ExitCode; Reason = $classification.Reason; Source = $classification.Source; Findings = @($classification.Findings)
        })
        if ($probe.Cancelled) { $cancelled = $true; break }
    }
    [pscustomobject]@{ Results = $results.ToArray(); Discovery = $discovery; Cancelled = $cancelled }
}
::ELO_PATCH_END:SCAN_PS

::ELO_PATCH_BEGIN:CLI_PS
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
  --catalog-validate FILE Validate a vulnerability catalog (JSON) without using it. Read-only.
  --catalog-simulate ID|FILE  Replay the catalog entry's (or every entry of a FILE, e.g. an AI draft) simulated java output through the real classifier
                          (shows how the vulnerability would be detected; no Java is run). Read-only.
  --catalog-install FILE  Install a reviewed catalog (needs --confirm-admin). The installed file it
                          replaces is copied to the quarantine folder first.
  --catalog-list          List quarantined catalog copies (%ProgramData%\ELO-Patch-Tools\quarantine).
  --catalog-restore ID    Put a quarantined copy back (needs --confirm-admin); the file it replaces is
                          quarantined too, so a restore can be undone.
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
\java\bin\java.exe, \ELO\java\bin\java.exe and \<folder>\java\bin\java.exe (any first-level folder)
at each drive root. An optional
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

PowerShell commands for the manual route (administrator; adjust paths and service names):
   # Run in an ADMINISTRATOR PowerShell. Adjust the paths and service names to your scan result.
   
   # 1) Find the runtime, its version and the services that use it
   & 'C:\ELO\java\bin\java.exe' -version
   Get-Content 'C:\ELO\java\release' | Select-String 'IMPLEMENTOR|JAVA_RUNTIME_VERSION|OS_ARCH'
   Get-CimInstance Win32_Service | Where-Object { $_.PathName -match 'ELO' } | Select-Object Name, State, PathName
   [Environment]::GetEnvironmentVariable('JAVA_TOOL_OPTIONS', 'Machine')
   
   # 2) Back up the runtime (ZIP) before changing anything
   Compress-Archive -LiteralPath 'C:\ELO\java' -DestinationPath 'C:\ELO\java-backup.zip'
   
   # 3) Temporary mitigation (machine-wide): KEEP the old value and append, never overwrite
   $old = [Environment]::GetEnvironmentVariable('JAVA_TOOL_OPTIONS', 'Machine'); $old
   [Environment]::SetEnvironmentVariable('JAVA_TOOL_OPTIONS', (($old + ' -XX:-UseBASE64Intrinsics').Trim()), 'Machine')
   # Undo: [Environment]::SetEnvironmentVariable('JAVA_TOOL_OPTIONS', $old, 'Machine')   (use $null if it was empty)
   # Services only see the change after they are restarted.
   
   # 4) Update the runtime by hand (download the newest release of the SAME vendor and branch first)
   (Get-FileHash 'C:\Downloads\new-java.zip' -Algorithm SHA256).Hash        # compare with the vendor's published SHA256
   Stop-Service 'ELO-SRV01-1' -Force                                        # every service that uses this Java
   Rename-Item 'C:\ELO\java' 'java.old'
   Expand-Archive -LiteralPath 'C:\Downloads\new-java.zip' -DestinationPath 'C:\ELO\java-new'
   Move-Item (Get-ChildItem 'C:\ELO\java-new' -Directory | Select-Object -First 1).FullName 'C:\ELO\java'
   & 'C:\ELO\java\bin\java.exe' -version
   Start-Service 'ELO-SRV01-1'
   
   # 5) If something fails: stop the services, put the old runtime back, start the services
   Stop-Service 'ELO-SRV01-1' -Force
   Rename-Item 'C:\ELO\java' 'java.failed'; Rename-Item 'C:\ELO\java.old' 'java'
   Start-Service 'ELO-SRV01-1'
   # Or restore from the ZIP: Expand-Archive 'C:\ELO\java-backup.zip' -DestinationPath 'C:\ELO\restore'; then move the java folder back

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

function Assert-EloCliCatalogPath {
    param([string]$Path)
    if ($Path.Length -gt 1024 -or $Path -cnotmatch '^[A-Za-z]:\\' -or $Path -match '[\x00-\x1f\x7f"<>|?*/;`$]' -or $Path.Substring(2).Contains(':')) { throw 'Invalid literal local file path.' }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw 'Catalog file not found.' }
    return $Path
}
function Invoke-EloCli {
    param(
        [string[]]$Arguments = @(),
        [scriptblock]$Scanner = { param($ManualPath) Invoke-EloJavaScan -ManualPath $ManualPath -ErrorAction Stop },
        [hashtable]$Actions = @{},
        [hashtable]$Console = (New-EloCliConsole)
    )
    $ErrorActionPreference = 'Stop'
    # Advisories, dates and sources come from the catalog (vulndb.json).
    $securitySource=''; $securityAdvisories=@(); $securityVerified=''
    foreach ($v in (Get-EloActiveVulnerabilities)) {
        if (-not $securityVerified -or [string]$v.verifiedOn -gt $securityVerified) { $securityVerified=[string]$v.verifiedOn }
        foreach ($vendor in $v.detection.vendors.PSObject.Properties) { if (-not $securitySource) { $securitySource=[string]$vendor.Value.fixedSource } }
        # Directly fetched sources are listed before user-supplied ones.
        foreach ($kind in @('Fetched','Supplied')) { foreach ($adv in @(@($v.advisories) | Where-Object { [string]$_.provenance -ceq $kind })) { $securityAdvisories+=@{ url=[string]$adv.url; provenance=[string]$adv.provenanceNote } } }
    }
    $report = [ordered]@{ readOnly=$true; noBrowser=$true; keepTemp=$false
        security=@{ verifiedOn=$securityVerified; sourceDate=($securityVerified.Substring(0,[Math]::Min(7,$securityVerified.Length)))
            source=$securitySource
            provenance='Parent verification supplied to this module; no runtime fetching.'
            advisories=$securityAdvisories
            warning='Unknown JVM vendors/builds remain inconclusive; source verification is not ELO compatibility verification or proof of whole-system safety or exploitability.' }
        scan=$null; action=$null; error=$null }
    $code = 2
    # JSON is recognized early so even malformed command lines receive JSON errors.
    $json = $Arguments -ccontains '--json'
    try {
        $options = @{}
        $allowed = @('--help','--cli','--scan','--json','--no-browser','--keep-temp',
            '--manual-path','--manual','--mitigate','--target','--confirm-admin',
            '--confirm-mitigation','--confirm-update','--update-runtime',
            '--catalog-validate','--catalog-install','--catalog-simulate','--catalog-list','--catalog-restore')
        for ($i=0; $i -lt $Arguments.Count; $i++) {
            $arg = $Arguments[$i]
            if ($allowed -cnotcontains $arg -or $options.ContainsKey($arg)) { throw 'Unknown or duplicate option.' }
            $value = $true
            if ($arg -cin @('--manual-path','--target','--catalog-validate','--catalog-install','--catalog-simulate','--catalog-restore')) {
                $i++
                if ($i -ge $Arguments.Count -or $Arguments[$i].StartsWith('--')) { throw 'Missing option value.' }
                $value = $Arguments[$i]
            }
            $options[$arg] = $value
        }
        $catalogMode = @('--catalog-validate','--catalog-install','--catalog-simulate','--catalog-list','--catalog-restore') | Where-Object { $options.ContainsKey($_) }
        $modes = @('--help','--manual','--mitigate','--update-runtime') | Where-Object { $options.ContainsKey($_) }
        if (@($catalogMode).Count -gt 0 -and (@($catalogMode).Count -gt 1 -or @($modes).Count -gt 0 -or $options.ContainsKey('--scan') -or $options.ContainsKey('--manual-path') -or $options.ContainsKey('--target') -or $options.ContainsKey('--confirm-mitigation') -or $options.ContainsKey('--confirm-update'))) { throw 'Conflicting modes.' }
        if (@($modes).Count -gt 1 -or ($options.ContainsKey('--scan') -and @($modes).Count -gt 0)) { throw 'Conflicting modes.' }
        $isAction = $options.ContainsKey('--mitigate') -or $options.ContainsKey('--update-runtime')
        if (-not $isAction -and @($catalogMode).Count -eq 0 -and
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
        # Catalog maintenance (vulndb.json): validate, simulate, install (with quarantine of the old file), list, restore.
        if (@($catalogMode).Count -gt 0) {
            $verb = [string]@($catalogMode)[0]
            $isChange = $verb -cin @('--catalog-install','--catalog-restore')
            if ($isChange -and -not $options.ContainsKey('--confirm-admin')) { throw ($verb + ' requires --confirm-admin; the previous file is quarantined first and can be restored.') }
            if ($options.ContainsKey('--confirm-admin') -and -not $isChange) { throw '--confirm-admin only applies to --catalog-install and --catalog-restore.' }
            if ($isChange -and (& $Actions.IsAdmin) -ne $true) { throw 'Administrator privileges required.' }
            $arg = [string]$options[$verb]
            $result = $null
            switch ($verb) {
                '--catalog-validate' {
                    $path = Assert-EloCliCatalogPath $arg
                    $db = Read-EloVulnDbFile $path
                    $result = @{ valid = $true; file = $path; vulnerabilities = @(@($db.vulnerabilities) | ForEach-Object { @{ id = [string]$_.id; severity = [string]$_.severity; status = [string]$_.status } }) }
                }
                '--catalog-install' {
                    $path = Assert-EloCliCatalogPath $arg
                    $installed = Install-EloVulnDb -Source $path
                    $result = @{ installed = $installed.installed; quarantinedPrevious = $installed.quarantined }
                }
                '--catalog-simulate' {
                    if ($arg -cmatch '^[A-Za-z]:\\') {
                        # A catalog FILE (e.g. an AI draft): simulate every entry in it, active or not.
                        $db = Read-EloVulnDbFile (Assert-EloCliCatalogPath $arg)
                        $result = @(@($db.vulnerabilities) | ForEach-Object { $s = Invoke-EloVulnSimulation $_ $db; @{ id = [string]$_.id; status = [string]$_.status; passed = [bool]$s.Passed; detected = [string]$s.Status; reason = [string]$s.Reason } })
                    } else {
                        if ($arg -cnotmatch '^[A-Za-z0-9._\-]{3,64}$') { throw 'Invalid vulnerability id.' }
                        $db = Get-EloVulnDb
                        $entry = @($db.vulnerabilities | Where-Object { $_.id -ceq $arg }) | Select-Object -First 1
                        if (-not $entry) { throw 'Unknown vulnerability id.' }
                        $result = Invoke-EloVulnSimulation $entry $db
                    }
                }
                '--catalog-list' { $result = @(Get-EloQuarantineEntries | ForEach-Object { @{ id = [string]$_.id; originalPath = [string]$_.originalPath; reason = [string]$_.reason; createdUtc = [string]$_.createdUtc } }) }
                '--catalog-restore' {
                    $restored = Restore-EloFileFromQuarantine -Id $arg
                    $result = @{ restored = $restored.restored; from = $restored.from; replacedCopy = $restored.replacedCopy }
                }
            }
            $report.readOnly = ($verb -cnotin @('--catalog-install','--catalog-restore')); $report.action = @{ catalog = $verb.Substring(2); result = $result }
            $code = 0
            if ($json) { $output = ConvertTo-Json -InputObject $report -Depth 30 -Compress } else { $output = "ELO Patch Tools catalog`r`n" + (ConvertTo-Json -InputObject $report -Depth 30) }
            return [pscustomobject]@{ ExitCode = $code; Output = $output }
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
::ELO_PATCH_END:CLI_PS

::ELO_PATCH_BEGIN:SERVER_PS
# Windows PowerShell 5.1. Dot-source only: loading this module does no work.
# Start-EloServer is an explicit foreground host; no services are restarted.
# ScanSource and UiHtml are trusted packaged resources, NEVER HTTP parameters.
# Embedding/HTML contract:
# - Default Port=0 binds an available IPv4 loopback port before forming the origin.
# - Default launch opens /#token=...; HTML must remove the fragment immediately.
# - A wrapper's --no-browser maps to -NoBrowser. Supply -LaunchHandler to deliver
#   the URI privately to a trusted local UI/channel. Handler output is suppressed;
#   it MUST NOT log/persist the URI. Without a handler startup fails explicitly.
# - -OpenBrowser is retained for callers; combining it with -NoBrowser is invalid.
# - Non-2xx JSON is {error:<stable code>,warnings:[{en,de}]}, never raw diagnostics.
#   HTML integration must display these warnings (not mislabel every 403 as auth),
#   and allow the three exact advisory URLs from Get-EloSecurityMetadata.
function Stop-EloRequest {
    param([int]$Status, [string]$Code = 'rejected')
    $e = New-Object System.InvalidOperationException($Code)
    $e.Data['Status'] = $Status
    throw $e
}
function New-EloSecret {
    $bytes = New-Object byte[] 32
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    return ([BitConverter]::ToString($bytes)).Replace('-', '').ToLowerInvariant()
}
function Test-EloSecret {
    param([string]$Left, [string]$Right)
    if ($Left.Length -ne 64 -or $Right.Length -ne 64) { return $false }
    $difference = 0
    for ($i = 0; $i -lt 64; $i++) { $difference = $difference -bor ([int][char]$Left[$i] -bxor [int][char]$Right[$i]) }
    return $difference -eq 0
}
function New-EloServerSession {
    param([ValidateRange(1024,65535)][int]$Port, [Parameter(Mandatory=$true)][string]$UiHtml,
        [Parameter(Mandatory=$true)][string]$ScanSource)
    @{
        Port=$Port; Origin="http://127.0.0.1:$Port"; Token=(New-EloSecret); UiHtml=$UiHtml; ScanSource=$ScanSource
        State='idle'; Results=@(); Targets=@{}; Preview=$null; Worker=$null; Backup=$null; RecoveryRequired=$false; LastError=$null
        ReportJvms=@(); ReportActions=@(); ReportIndexes=@{}; UpdateContext=$null; ReportRecovery=$null; LastUpdate=$null; Backups=@{}; BackupsCache=$null; BackupsLogged=-1; LastRejected=''
        Adapters=@{
            NewUpdateContext={ param($Root,$Runtime,$StopServices) New-EloUpdateContext -Adapters (New-EloWindowsUpdateAdapters -ApprovedRoot $Root -Runtime $Runtime -AllowServiceStop:([bool]$StopServices)) -Production }
            BackupRoots={ @([IO.DriveInfo]::GetDrives() | Where-Object { $_.IsReady -and $_.DriveType -in @([IO.DriveType]::Fixed,[IO.DriveType]::Removable) -and $_.Name -cmatch '^[C-Z]:\\$' } | ForEach-Object { $_.RootDirectory.FullName }) }
            ScanRules={ if (Get-Command Get-EloScanRules -CommandType Function -ErrorAction SilentlyContinue) { ,@(Get-EloScanRules) } else { ,@() } }
            Log={ param($Message) Write-Host ((Get-Date).ToString('HH:mm:ss')+'  '+$Message) }
            Identity={ param($Path) Get-EloRuntimeIdentity $Path }
            EloVersion={ param($Roots) Get-EloInstalledIndexserverVersion $Roots }
            ResolveRelease={ param($Identity) Resolve-EloLatestRelease -Vendor $Identity.Vendor -Branch $Identity.Branch -Architecture $Identity.Architecture -ImageType $Identity.ImageType }
            RuntimeUsers={ param($Path) Get-EloRuntimeUsers $Path }
            RestoreBackup={ param($Root,$Runtime,$Backup,$StopServices,$Stamp)
                $services=New-EloWindowsUpdateAdapters -ApprovedRoot $Root -Runtime $Runtime -AllowServiceStop:([bool]$StopServices)
                $quiesce=$null; $resume=$null
                if ($StopServices) { $quiesce={ & $services.Quiesce @{Runtime=$Runtime} }.GetNewClosure(); $resume={ & $services.Resume @{Runtime=$Runtime} $null }.GetNewClosure() }
                Invoke-EloBackupRestore -Root $Root -Runtime $Runtime -Backup $Backup -Quiesce $quiesce -Resume $resume -Stamp $Stamp
            }
            Admin={ Test-EloAdministrator }; ReadOptions={ Get-EloMachineOptions }
            WriteOptions={ param($Value) Set-EloMachineOptions $Value }
            Fingerprint={ param($Path) Get-EloJavaFingerprint $Path }
            Verify={ param($Path,$Options) Invoke-EloFlagProbe $Path $Options }
            Clock={ [DateTime]::UtcNow }; Resources={ Get-EloReportWindowsResources }
            ReportOptions={ @{Machine=[Environment]::GetEnvironmentVariable('JAVA_TOOL_OPTIONS','Machine');User=[Environment]::GetEnvironmentVariable('JAVA_TOOL_OPTIONS','User');Process=[Environment]::GetEnvironmentVariable('JAVA_TOOL_OPTIONS','Process')} }
        }
    }
}
function Test-EloLocalPath {
    param([string]$Path, [switch]$RequireDirectory)
    if ([string]::IsNullOrWhiteSpace($Path) -or $Path.Length -gt 1024 -or $Path -cnotmatch '^[A-Za-z]:\\' -or
        $Path -match '[\x00-\x1f\x7f"<>|?*/]' -or $Path.Substring(2).Contains(':')) { Stop-EloRequest 400 'invalid_path' }
    foreach ($part in $Path.Substring(3).Split('\')) {
        if ($part -match '[. ]$' -or $part -match '^(?i:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)') { Stop-EloRequest 400 'invalid_path' }
    }
    $canonical = [IO.Path]::GetFullPath($Path)
    if ($RequireDirectory) {
        $drive = New-Object IO.DriveInfo($canonical.Substring(0,3))
        if ($drive.DriveType -notin @([IO.DriveType]::Fixed,[IO.DriveType]::Removable) -or -not $drive.IsReady) { Stop-EloRequest 400 'nonlocal_path' }
        if (-not [IO.Directory]::Exists($canonical)) { Stop-EloRequest 400 'inaccessible_path' }
        # Reject junctions in every ancestor, not just the final component.
        $item = Get-Item -LiteralPath $canonical -Force -ErrorAction Stop
        while ($null -ne $item) {
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { Stop-EloRequest 400 'reparse_path' }
            $item = $item.Parent
        }
        $enumerator = [IO.Directory]::EnumerateFileSystemEntries($canonical).GetEnumerator()
        try { $null = $enumerator.MoveNext() } finally { if ($enumerator -is [IDisposable]) { $enumerator.Dispose() } }
    }
    return $canonical
}
function ConvertFrom-EloBody {
    param([string]$Body, [string[]]$Required=@(), [string[]]$Optional=@())
    # The protocol only needs a flat object with string values. Restrict grammar
    # before ConvertFrom-Json: reject arrays, nesting, duplicate keys and coercions.
    $str = '"(?:[^"\\\x00-\x1f]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*"'
    if ($Body.Length -gt 8192 -or $Body -notmatch ('\A\s*\{\s*(?:'+$str+'\s*:\s*'+$str+'\s*(?:,\s*'+$str+'\s*:\s*'+$str+'\s*)*)?\}\s*\z')) { Stop-EloRequest 400 'invalid_json' }
    $keys = @{}
    foreach ($match in [regex]::Matches($Body, '('+$str+')\s*:')) {
        $key = ConvertFrom-Json -InputObject $match.Groups[1].Value
        if ($keys.ContainsKey($key) -or ($Required -cnotcontains $key -and $Optional -cnotcontains $key)) { Stop-EloRequest 400 'invalid_parameters' }
        $keys[$key] = $true
    }
    foreach ($key in $Required) { if (-not $keys.ContainsKey($key)) { Stop-EloRequest 400 'missing_parameter' } }
    return ConvertFrom-Json -InputObject $Body
}
function Assert-EloBoundary {
    param($Session,$Request)
    if ($Request.Remote -cne '127.0.0.1') { Stop-EloRequest 403 'loopback_only' }
    if ($Request.Headers['Host'] -cne "127.0.0.1:$($Session.Port)") { Stop-EloRequest 403 'host_rejected' }
    if ($Request.Headers.ContainsKey('Origin') -and $Request.Headers['Origin'] -cne $Session.Origin) { Stop-EloRequest 403 'origin_rejected' }
    if ($Request.Headers.ContainsKey('Sec-Fetch-Site') -and $Request.Headers['Sec-Fetch-Site'] -notin @('same-origin','none')) { Stop-EloRequest 403 'cross_site' }
    if ($Request.Method -cnotin @('GET','POST')) { Stop-EloRequest 405 'method_rejected' }
    if ($Request.Method -ceq 'POST' -and $Request.Headers['Origin'] -cne $Session.Origin) { Stop-EloRequest 403 'origin_required' }
}
function Start-EloScanWorker {
    param($Session,[string]$ManualPath)
    if ($Session.Worker) { Stop-EloRequest 409 'scan_busy' }
    $Session.Preview = $null; $Session.Results = @(); $Session.Targets = @{}; $Session.LastError=$null
    $control = [hashtable]::Synchronized(@{Cancel=$false})
    $roots = @([IO.DriveInfo]::GetDrives() | Where-Object { $_.IsReady -and $_.DriveType -in @([IO.DriveType]::Fixed,[IO.DriveType]::Removable) } | ForEach-Object { $_.RootDirectory.FullName })
    $ps = [PowerShell]::Create()
    $wrapper = @'
param($source,$roots,$manual,$control,$rules)
$ErrorActionPreference='Stop'
. ([scriptblock]::Create($source))
$cancel = { [bool]$control.Cancel }.GetNewClosure()
Invoke-EloJavaScan -DriveRoots $roots -ManualPath $manual -ShouldCancel $cancel -Rules $rules
'@
    try {
        $null = $ps.AddScript($wrapper).AddArgument($Session.ScanSource).AddArgument($roots).AddArgument($ManualPath).AddArgument($control).AddArgument((& $Session.Adapters.ScanRules))
        $handle = $ps.BeginInvoke()
        $Session.Worker = @{PowerShell=$ps; Handle=$handle; Control=$control}
        $Session.State = 'scanning'
    } catch { $ps.Dispose(); $Session.State='error'; throw }
}
function Get-EloSecurityMetadata {
    # Advisories of every active catalog vulnerability (vulndb.json). Verification dates and provenance come
    # from the catalog; this module does not fetch them.
    $items=@(); $verified=@()
    foreach ($v in (Get-EloActiveVulnerabilities)) {
        if ($v.verifiedOn) { $verified+=[string]$v.verifiedOn }
        foreach ($a in @($v.advisories)) { $items+=@{id=[string]$a.id;url=[string]$a.url;title=@{en=[string]$a.title.en;de=[string]$a.title.de}} }
    }
    if ($items.Count -eq 0) { return @{verifiedOn=$null;advisories=@()} }
    return @{verifiedOn=[string]($verified | Sort-Object -Descending | Select-Object -First 1);advisories=$items}
}
function Get-EloVulnerabilityInfo {
    # What the UI needs per active vulnerability: severity, problem and solution texts, and the action ids.
    $list=@()
    foreach ($v in (Get-EloActiveVulnerabilities)) {
        $list+=@{id=[string]$v.id;alias=[string](@($v.aliases) | Select-Object -First 1);severity=[string]$v.severity
            title=@{en=[string]$v.title.en;de=[string]$v.title.de};problem=@{en=[string]$v.problem.en;de=[string]$v.problem.de};solution=@{en=[string]$v.solution.en;de=[string]$v.solution.de}
            actions=@(@($v.actions) | ForEach-Object { [string]$_.id })}
    }
    return $list
}
function Get-EloMitigationAction {
    # The jvm-option action of the first active vulnerability that has one.
    foreach ($v in (Get-EloActiveVulnerabilities)) {
        $a=Get-EloVulnAction $v 'jvm-option'
        if ($a) { return @{Vulnerability=$v;Action=$a} }
    }
    return $null
}
function ConvertTo-EloUiResults {
    param($Session,$Scan)
    $rows = New-Object 'System.Collections.Generic.List[object]'
    $targets = @{}
    if (@($Scan.Results).Count -gt 250) { Stop-EloRequest 422 'narrow_scan_root' }
    foreach ($item in $Scan.Results) {
        $id = New-EloSecret
        $status = 'inconclusive'
        if ($item.Status -ceq 'PotentiallyVulnerable') { $status='vulnerable' }
        # Narrow exact-build allowlist from parent-verified Temurin evidence.
        # No extrapolation to later versions, other vendors or ELO compatibility.
        $rules=@(); if ($Session.Adapters.ScanRules) { $rules=@(& $Session.Adapters.ScanRules | Where-Object { $_.Vendor -ceq 'Temurin' }) }
        $fixed=@($rules | ForEach-Object { $_.Fixed } | ForEach-Object { [string]$_ })
        $sources=@($rules | ForEach-Object { [string]$_.Source })
        if ($item.Status -ceq 'KnownFixed' -and $item.Vendor -ceq 'Temurin' -and $fixed -ccontains $item.FullVersion -and
            $item.Build -ceq $item.FullVersion -and $sources -ccontains [string]$item.Source) { $status='patched' }
        $architecture = 'unknown'
        if ($item.Architecture -in @('x86','x64','ARM64')) { $architecture=$item.Architecture.ToLowerInvariant() }
        $version = 'Unknown'; if ($item.FullVersion) { $version=[string]$item.FullVersion }
        $vendor = 'Unknown'; if ($item.Vendor) { $vendor=[string]$item.Vendor }
        $rationale = [string]$item.EloPathRationale
        if ([string]::IsNullOrWhiteSpace($rationale)) { $rationale='ELO association is not verified.' }
        $rationale += " Runtime-root inference: $($item.RuntimeRootRationale)"
        $provenance='Parent verification 2026-11-23: OpenJDK advisory reviewed as user-supplied text, not fetched directly; Oracle Linux CVE-2026-114938 and Temurin vendor advisory fetched directly by parent. This module did not fetch them. Exact listed Temurin builds only; no ELO compatibility or other vendor verification. Patched is a narrow advisory classification, not a whole-system safety claim.'
        $evidence = "$provenance`nScanner classification: $($item.Status). $($item.Reason)`n$($item.Evidence)`nReported architecture: $($item.Architecture)`nProbe error: $($item.Error)`nRule source: $($item.Source)"
        # One finding per catalog vulnerability evaluated for this runtime (UI statuses).
        $findings=@()
        foreach ($f in @($item.Findings | Where-Object { $_ -and $_.Id })) {
            $fs='inconclusive'; if ($f.Status -ceq 'PotentiallyVulnerable') { $fs='vulnerable' } elseif ($f.Status -ceq 'KnownFixed' -and $status -ceq 'patched') { $fs='patched' }
            $sev='high'; if (@('high','medium','low') -ccontains [string]$f.Severity) { $sev=[string]$f.Severity }
            $findings+=[pscustomobject]@{id=[string]$f.Id;severity=$sev;status=$fs}
        }
        $row = [ordered]@{id=$id;path=[string]$item.Location;runtimeRoot=[string]$item.RuntimeRoot;version=$version;vendor=$vendor;architecture=$architecture;status=$status
            findings=@($findings)
            eloRationale=@{en=$rationale;de="ELO-Zuordnung nicht verifiziert. Technischer Nachweis: $rationale"}
            classificationEvidence=@{en=$evidence;de="Elternagent pruefte Quellen am 2026-11-23: OpenJDK nur als Benutzertext, Oracle Linux und Temurin direkt abgerufen. Keine ELO-Kompatibilitaets- oder andere Herstellerpruefung. Technischer Nachweis: $evidence"}}
        foreach ($pair in @(@($row.path,1024),@($row.runtimeRoot,1024),@($version,128),@($vendor,256),@($row.eloRationale.en,2048),@($row.eloRationale.de,2048),@($row.classificationEvidence.en,4096),@($row.classificationEvidence.de,4096))) {
            if ([string]::IsNullOrWhiteSpace($pair[0]) -or $pair[0].Length -gt $pair[1] -or $pair[0] -match '[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]') { Stop-EloRequest 422 'evidence_out_of_bounds' }
        }
        $rows.Add([pscustomobject]$row); $targets[$id]=$item
    }
    $payload = @{results=@($rows.ToArray());security=(Get-EloSecurityMetadata)}
    if ([Text.Encoding]::UTF8.GetByteCount(($payload | ConvertTo-Json -Depth 8 -Compress)) -gt 4MB) { Stop-EloRequest 422 'narrow_scan_root' }
    $Session.Results=$rows.ToArray(); $Session.Targets=$targets
    $primary=Get-EloPrimaryVulnerability
    $scanTemplate='Scan finished: {count} Java runtime(s) found, {vulnerable} vulnerable ({id}).'
    if ($primary -and $primary.messages.logScan) { $scanTemplate=[string]$primary.messages.logScan }
    Write-EloLog $Session (Format-EloVulnText $scanTemplate @{count=$rows.Count;vulnerable=@($rows | Where-Object { $_.status -ceq 'vulnerable' }).Count;id=$(if ($primary) { [string]$primary.id } else { '' })})
    $Session.ReportIndexes=@{}
    foreach ($row in $Session.Results) {
        $item=$targets[$row.id]
        # Reclassify raw probe evidence with the packaged scanner. Never trust a
        # UI label, path heuristic, or asserted vendor as report proof.
        $evidence=@{FullVersion=$null;Vendor='Unknown';Status='Inconclusive'}
        if (Get-Command Get-EloJavaClassification -CommandType Function -ErrorAction SilentlyContinue) {
            $evidence=Get-EloJavaClassification ([string]$item.Evidence)
        }
        $observed=(-not [string]::IsNullOrWhiteSpace($evidence.FullVersion) -and $null -ne $item.ExitCode -and $item.ExitCode -eq 0 -and -not $item.Error -and $evidence.FullVersion -ceq $item.FullVersion)
        $classification='Unknown'; $code='Unknown'
        if ($observed -and $evidence.Status -ceq $item.Status) {
            if ($item.Status -ceq 'PotentiallyVulnerable') { $classification='PotentiallyVulnerable'; $code='AdvisoryRangeMatch' }
            if ($row.status -ceq 'patched') { $classification='Fixed'; $code='AdvisoryFixedVersion' }
        }
        $Session.ReportJvms+=@{Version=$evidence.FullVersion;Verified=$observed;ExecutionVerified=$observed
            Vendor=$evidence.Vendor;VendorVerified=($observed -and @('Temurin','Azul Zulu') -ccontains $evidence.Vendor)
            Classification=$classification;ClassificationVerified=($classification -ne 'Unknown');EvidenceCode=$code}
        $Session.ReportIndexes[$row.id]=$Session.ReportJvms.Count
    }
}
function Update-EloScanWorker {
    param($Session)
    $w=$Session.Worker
    if (-not $w -or -not $w.Handle.IsCompleted) { return }
    try {
        $output=@($w.PowerShell.EndInvoke($w.Handle))
        if ($w.PowerShell.HadErrors) {
            $failure=ConvertTo-EloErrorResponse $w.PowerShell.Streams.Error[0].Exception
            Stop-EloRequest $failure.Status $failure.Body.error
        }
        if ($output.Count -ne 1) { Stop-EloRequest 500 'scan_failed' }
        ConvertTo-EloUiResults $Session $output[0]
        if ($output[0].Cancelled -or $w.Control.Cancel) { $Session.State='cancelled' }
        elseif ($output[0].Discovery -and (($null -ne $output[0].Discovery.Issues -and @($output[0].Discovery.Issues).Count -gt 0) -or $output[0].Discovery.LimitReached -or $output[0].Discovery.DepthLimitReached)) {
            Stop-EloRequest 422 'scan_incomplete'
        } else { $Session.State='completed' }
    } catch {
        $failure=ConvertTo-EloErrorResponse $_.Exception
        $Session.LastError=@{Status=$failure.Status;Code=$failure.Body.error}
        $Session.Results=@(); $Session.Targets=@{}; $Session.State='error'
    }
    finally { $w.PowerShell.Dispose(); $Session.Worker=$null }
}
function Test-EloAdministrator {
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    try { $principal=New-Object Security.Principal.WindowsPrincipal($identity); return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
    finally { $identity.Dispose() }
}
function Get-EloMachineOptions {
    $key=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\CurrentControlSet\Control\Session Manager\Environment',$false)
    try {
        $exists=$key.GetValueNames() -contains 'JAVA_TOOL_OPTIONS'
        $value=$null; $kind='String'
        if ($exists) {
            $value=$key.GetValue('JAVA_TOOL_OPTIONS',$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            $kind=[string]$key.GetValueKind('JAVA_TOOL_OPTIONS')
            if ($kind -notin @('String','ExpandString') -or $value -isnot [string]) { Stop-EloRequest 409 'unsupported_environment_type' }
        }
        return @{Exists=$exists; Value=$value; Kind=$kind}
    } finally { $key.Dispose() }
}
function Set-EloMachineOptions {
    param($Record)
    $key=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\CurrentControlSet\Control\Session Manager\Environment',$true)
    if (-not $key) { throw 'environment_unavailable' }
    try {
        if ($Record.Exists) {
            $kind=[Microsoft.Win32.RegistryValueKind][Enum]::Parse([Microsoft.Win32.RegistryValueKind],[string]$Record.Kind)
            $key.SetValue('JAVA_TOOL_OPTIONS',[string]$Record.Value,$kind)
        }
        else { $key.DeleteValue('JAVA_TOOL_OPTIONS',$false) }
        $key.Flush()
    } finally { $key.Dispose() }
}
function Merge-EloJavaOptions {
    param([AllowNull()][AllowEmptyString()][string]$Existing,$Action=$null)
    if ($null -eq $Action) { $Action=(Get-EloMitigationAction).Action }
    $option=[string]$Action.option; $flag=[string]$Action.conflictPattern
    if ($Existing.Length -gt 1000 -or $Existing -match '[\x00-\x08\x0a-\x1f\x7f]') { Stop-EloRequest 409 'unsupported_options' }
    # Conservative JAVA_TOOL_OPTIONS token grammar: whitespace separates outside
    # balanced single/double quotes. Escaped quotes are deliberately unsupported:
    # differing JVM escape rules must not cause us to rewrite the wrong token.
    $kept=New-Object Text.StringBuilder
    $i=0
    while ($i -lt $Existing.Length) {
        if ($Existing[$i] -eq ' ' -or $Existing[$i] -eq "`t") { $null=$kept.Append($Existing[$i]); $i++; continue }
        $start=$i; $quote=[char]0; $decoded=New-Object Text.StringBuilder
        while ($i -lt $Existing.Length) {
            $ch=$Existing[$i]
            if ($quote -eq [char]0 -and ($ch -eq ' ' -or $ch -eq "`t")) { break }
            if ($ch -eq [char]34 -or $ch -eq [char]39) {
                if ($i -gt 0 -and $Existing[$i-1] -eq '\') { Stop-EloRequest 409 'ambiguous_option_quoting' }
                if ($quote -eq [char]0) { $quote=$ch }
                elseif ($quote -eq $ch) { $quote=[char]0 }
                else { $null=$decoded.Append($ch) }
            } else { $null=$decoded.Append($ch) }
            $i++
        }
        if ($quote -ne [char]0) { Stop-EloRequest 409 'malformed_option_quoting' }
        $token=$decoded.ToString()
        if ($token -cmatch ('^-XX:[+-]'+[regex]::Escape($flag)+'$')) { continue }
        if ($token -match ('^-XX:.*'+[regex]::Escape($flag))) { Stop-EloRequest 409 'ambiguous_intrinsics_option' }
        $null=$kept.Append($Existing.Substring($start,$i-$start))
    }
    if ($kept.Length -eq 0) { return $option }
    return $kept.ToString() + ' ' + $option
}
function Get-EloJavaFingerprint {
    param([string]$Path)
    $canonical=Test-EloLocalPath $Path
    $directory=Split-Path -Parent $canonical
    $null=Test-EloLocalPath $directory -RequireDirectory
    $file=Get-Item -LiteralPath $canonical -Force -ErrorAction Stop
    if ($file.PSIsContainer -or $file.Name -ine 'java.exe' -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)) { Stop-EloRequest 409 'invalid_java_target' }
    return (Get-FileHash -LiteralPath $canonical -Algorithm SHA256 -ErrorAction Stop).Hash
}
function Test-EloFlagEvidence {
    param([string]$Evidence,$Action=$null)
    if ($null -eq $Action) { $Action=(Get-EloMitigationAction).Action }
    $re=New-Object Text.RegularExpressions.Regex([string]$Action.verify.expect,[Text.RegularExpressions.RegexOptions]::None,[TimeSpan]::FromSeconds(2))
    $matches=$re.Matches($Evidence)
    return $matches.Count -eq 1 -and $matches[0].Groups[1].Value -ceq [string]$Action.verify.mustBe
}
function Invoke-EloFlagProbe {
    param([string]$JavaPath,[string]$Options)
    # These other JVM injection mechanisms make the exact effective environment
    # ambiguous. Do not remove/overwrite them: refuse the operation instead.
    foreach ($name in @('_JAVA_OPTIONS','JDK_JAVA_OPTIONS')) {
        foreach ($scope in @('Process','User','Machine')) {
            if ([Environment]::GetEnvironmentVariable($name,$scope)) { Stop-EloRequest 409 'ambiguous_jvm_options' }
        }
    }
    $p=New-Object Diagnostics.Process
    try {
        $info=New-Object Diagnostics.ProcessStartInfo
        $verifyArgs=(@((Get-EloMitigationAction).Action.verify.args) | ForEach-Object { [string]$_ }) -join ' '
        $info.FileName=$JavaPath; $info.Arguments=$verifyArgs
        $info.UseShellExecute=$false; $info.CreateNoWindow=$true
        $info.RedirectStandardOutput=$true; $info.RedirectStandardError=$true
        $info.EnvironmentVariables['JAVA_TOOL_OPTIONS']=$Options
        $p.StartInfo=$info
        if (-not $p.Start()) { return $false }
        # Drain continuously with a hard output budget, not ReadToEndAsync's
        # unbounded accumulation. The short-lived probe cannot block the host forever.
        $stdout=New-Object Text.StringBuilder; $stderr=New-Object Text.StringBuilder
        $ob=New-Object char[] 1024; $eb=New-Object char[] 1024
        $ot=$p.StandardOutput.ReadAsync($ob,0,$ob.Length); $et=$p.StandardError.ReadAsync($eb,0,$eb.Length)
        $clock=[Diagnostics.Stopwatch]::StartNew(); $od=$false; $ed=$false
        while (-not ($od -and $ed -and $p.HasExited)) {
            if ($clock.Elapsed.TotalSeconds -gt 10 -or ($stdout.Length+$stderr.Length) -gt 1MB) { return $false }
            if (-not $od -and $ot.IsCompleted) {
                $n=$ot.GetAwaiter().GetResult(); if ($n -eq 0) { $od=$true } else { $null=$stdout.Append($ob,0,$n); $ot=$p.StandardOutput.ReadAsync($ob,0,$ob.Length) }
            }
            if (-not $ed -and $et.IsCompleted) {
                $n=$et.GetAwaiter().GetResult(); if ($n -eq 0) { $ed=$true } else { $null=$stderr.Append($eb,0,$n); $et=$p.StandardError.ReadAsync($eb,0,$eb.Length) }
            }
            Start-Sleep -Milliseconds 10
        }
        return $p.ExitCode -eq 0 -and (Test-EloFlagEvidence ($stdout.ToString()+"`n"+$stderr.ToString()))
    } finally { try { if (-not $p.HasExited) { $p.Kill() } } catch { }; $p.Dispose() }
}
function Test-EloSameOptions {
    param($Left,$Right)
    return $Left.Exists -eq $Right.Exists -and $Left.Value -ceq $Right.Value -and $Left.Kind -ceq $Right.Kind
}
function New-EloMitigationPreview {
    param($Session,[string]$ResultId)
    $Session.Preview=$null
    if (-not (& $Session.Adapters.Admin)) { Stop-EloRequest 403 'administrator_required' }
    $target=$Session.Targets[$ResultId]
    if (-not $target -or $target.Status -cne 'PotentiallyVulnerable') { Stop-EloRequest 409 'target_not_eligible' }
    $before=& $Session.Adapters.ReadOptions
    # Preserve raw REG_EXPAND_SZ bytes, but do not pretend a process-local probe
    # proves Windows' future service expansion against an unknown environment.
    if ($before.Kind -ceq 'ExpandString' -and $before.Value -match '%') { Stop-EloRequest 409 'ambiguous_environment_expansion' }
    $spec=Get-EloMitigationAction
    if (-not $spec) { Stop-EloRequest 409 'target_not_eligible' }
    $after=@{Exists=$true;Value=(Merge-EloJavaOptions $before.Value $spec.Action);Kind=$before.Kind}
    $fingerprint=& $Session.Adapters.Fingerprint $target.Location
    # Preview is read-only, including registry/configuration. A disposable JVM is
    # started only after explicit action confirmation, never during preview.
    $preview=@{Id=(New-EloSecret);ResultId=$ResultId;ActionId='mitigate';Before=$before;After=$after;Fingerprint=$fingerprint
        JavaPath=$target.Location;Expires=(& $Session.Adapters.Clock).AddMinutes(2)}
    $old='(absent)'; if ($before.Exists) { $old="[$($before.Value)]" }
    $values=@{option=[string]$spec.Action.option;variable=[string]$spec.Action.variable;old=$old;kind=[string]$before.Kind;new=[string]$after.Value}
    $summaryEn=Format-EloVulnText ([string]$spec.Action.summary.en) $values
    $summaryDe=Format-EloVulnText ([string]$spec.Action.summary.de) $values
    $Session.Preview=$preview
    return @{previewId=$preview.Id;summary=@{en=$summaryEn;de=$summaryDe};warnings=@(
        @{en='Existing JVMs are NOT protected. No restart is performed. Windows services may retain an old environment even after restart; a verified PrintFlagsFinal probe is not proof of service protection. Coordinate supported ELO configuration with your administrator.';de='Bestehende JVMs sind NICHT geschuetzt. Kein Neustart. Windows-Dienste koennen alte Umgebungswerte behalten. Der PrintFlagsFinal-Test beweist keinen Schutz des Dienstes. Unterstuetzte ELO-Konfiguration mit Administrator klaeren.'},
        @{en='Global options can break unrelated JVMs. Advisory source verification does not establish ELO or JVM-option compatibility. Session-only backup is lost on exit: save the previous value from this preview before confirmation. No runtime update is available.';de='Globale Optionen koennen andere JVMs stoeren. Quellenpruefung beweist keine ELO- oder JVM-Optionskompatibilitaet. Sitzungssicherung geht beim Beenden verloren: alten Wert vor Bestaetigung sichern. Laufzeit-Update nicht verfuegbar.'})}
}
function Invoke-EloMitigation {
    param($Session,$Body)
    $preview=$Session.Preview; $Session.Preview=$null # consume even on failure
    if (-not $preview -or $preview.Id -cne $Body.previewId -or $preview.ResultId -cne $Body.resultId -or $preview.ActionId -cne $Body.actionId -or
        (& $Session.Adapters.Clock) -ge $preview.Expires) { Stop-EloRequest 409 'preview_expired_or_mismatched' }
    if (-not (& $Session.Adapters.Admin)) { Stop-EloRequest 403 'administrator_required' }
    $target=$Session.Targets[$Body.resultId]
    if (-not $target -or $target.Location -cne $preview.JavaPath -or $target.Status -cne 'PotentiallyVulnerable' -or
        (& $Session.Adapters.Fingerprint $preview.JavaPath) -cne $preview.Fingerprint -or
        -not (Test-EloSameOptions (& $Session.Adapters.ReadOptions) $preview.Before)) { Stop-EloRequest 409 'stale_preview' }
    if (-not (& $Session.Adapters.Verify $preview.JavaPath $preview.After.Value)) { Stop-EloRequest 422 'probe_failed_no_change' }
    # Recheck after the potentially slow probe; refuse stale writes.
    if (-not (Test-EloSameOptions (& $Session.Adapters.ReadOptions) $preview.Before) -or
        (& $Session.Adapters.Fingerprint $preview.JavaPath) -cne $preview.Fingerprint) { Stop-EloRequest 409 'stale_preview' }
    # Prior success is historical; a new write attempt can invalidate it.
    foreach ($action in $Session.ReportActions) {
        if ($action.Kind -ceq 'Mitigation') { $action.Status='Unknown'; $action.Verified=$false }
    }
    $Session.ReportActions+=@{Kind='Mitigation';Status='Unknown';RuntimeIndex=$Session.ReportIndexes[$Body.resultId]}
    $Session.Backup=$preview.Before
    try {
        & $Session.Adapters.WriteOptions $preview.After
        if (-not (Test-EloSameOptions (& $Session.Adapters.ReadOptions) $preview.After) -or
            -not (& $Session.Adapters.Verify $preview.JavaPath $preview.After.Value)) { throw 'verification_failed' }
    } catch {
        $attempt=$Session.ReportActions[-1]
        $attempt.Status='Failed'; $attempt.EvidenceCode='ValidationFailed'; $attempt.EvidenceVerified=$true
        try {
            & $Session.Adapters.WriteOptions $preview.Before
            if (-not (Test-EloSameOptions (& $Session.Adapters.ReadOptions) $preview.Before)) { throw 'rollback_mismatch' }
        } catch {
            $Session.State='error'; $Session.RecoveryRequired=$true
            Stop-EloRequest 500 'rollback_failed_manual_recovery_required'
        }
        Stop-EloRequest 422 'verification_failed_rolled_back'
    }
    $index=$Session.ReportIndexes[$Body.resultId]
    $attempt=$Session.ReportActions[-1]
    $attempt.Status='Proven'; $attempt.Verified=$true
    $attempt.EvidenceCode='MachineOptionSet'; $attempt.EvidenceVerified=$true
    $Session.ReportActions+=@{Kind='Mitigation';Status='Proven';Verified=$true;RuntimeIndex=$index
        EvidenceCode='NewlyLaunchedJvmFlagVerified';EvidenceVerified=$true}
    return @{ok=$true}
}
function Stop-EloRequestDetail {
    param([int]$Status,[string]$Code,[string]$Detail)
    $e = New-Object System.InvalidOperationException($Code)
    $e.Data['Status'] = $Status
    if ($Detail -cmatch '^[A-Za-z0-9_:+.\-]{1,100}$') { $e.Data['Detail'] = $Detail }
    throw $e
}
function ConvertTo-EloUpdateCode {
    param([string]$Message)
    $code=([string]$Message -split "`r?`n")[0]
    if ($code -cmatch '^[a-z0-9_]{1,64}(:[A-Za-z0-9_+.\-]{1,32})?') { return $Matches[0] }
    return 'update_failed'
}
function Write-EloLog {
    # One line for the backend (PowerShell) window. Never the token, never request bodies.
    param($Session,[string]$Message)
    try {
        if ($Session.Adapters.Log -is [scriptblock]) {
            $clean=($Message -replace '[\x00-\x1f\x7f]',' ')
            if ($Session.Token) { $clean=$clean.Replace([string]$Session.Token,'[redacted]') }
            & $Session.Adapters.Log $clean.Substring(0,[Math]::Min(600,$clean.Length))
        }
    } catch { }
}
function Read-EloBackupRelease {
    # Vendor and version of the runtime inside a backup ZIP, read from tree/release (bounded, read-only).
    param([string]$ZipPath)
    $version='unknown'; $vendor='unknown'
    try {
        Add-Type -AssemblyName System.IO.Compression -ErrorAction Stop
        $stream=[IO.File]::OpenRead($ZipPath); $zip=New-Object IO.Compression.ZipArchive($stream,[IO.Compression.ZipArchiveMode]::Read,$true)
        try {
            $entry=$zip.GetEntry('tree/release')
            if ($entry -and $entry.Length -le 65536) {
                $reader=New-Object IO.StreamReader($entry.Open())
                try { $text=$reader.ReadToEnd() } finally { $reader.Dispose() }
                if ($text -cmatch '(?m)^JAVA_RUNTIME_VERSION="([^"\r\n]{1,64})"') { $version=$Matches[1] } elseif ($text -cmatch '(?m)^JAVA_VERSION="([^"\r\n]{1,64})"') { $version=$Matches[1] }
                if ($text -cmatch '(?m)^IMPLEMENTOR="([^"\r\n]{1,64})"') {
                    $implementor=$Matches[1]
                    if ($implementor -match '(?i)adoptium|temurin') { $vendor='Temurin' } elseif ($implementor -match '(?i)azul') { $vendor='Azul Zulu' } else { $vendor='other' }
                }
            }
        } finally { $zip.Dispose(); $stream.Dispose() }
    } catch { }
    return @{Version=$version;Vendor=$vendor}
}
function Get-EloBackupAssessment {
    # Risk of a Java build against every active catalog vulnerability (version-table rules):
    # vulnerable (any rule says so) | patched (all rules say fixed) | unknown. Other vendors and unlisted
    # branches are never called safe. Also returns the vulnerability that decides the message.
    param([string]$Vendor,[string]$Version)
    $primary=Get-EloPrimaryVulnerability
    $result=@{Risk='unknown';Vulnerability=$primary}
    if ($Vendor -cne 'Temurin') { return $result }
    try {
        $v=ConvertTo-EloJavaVersion $Version
        $verdicts=@(); $deciding=$null
        foreach ($rule in @(Get-EloScanRules | Where-Object { $_.Vendor -ceq 'Temurin' })) {
            $milestone=@(@($rule.Fixed) | Where-Object { ($_ -split '\.')[0] -ceq $v.Branch })
            if ($milestone.Count -ne 1) { $verdicts+='unknown'; continue }
            if ((Compare-EloJavaVersion $v (ConvertTo-EloJavaVersion $milestone[0])) -lt 0) { $verdicts+='vulnerable'; if (-not $deciding) { $deciding=$rule.Id } }
            else { $verdicts+='patched' }
        }
        if ($verdicts -contains 'vulnerable') { $result.Risk='vulnerable' }
        elseif ($verdicts.Count -gt 0 -and @($verdicts | Where-Object { $_ -cne 'patched' }).Count -eq 0) { $result.Risk='patched' }
        if ($deciding) { $result.Vulnerability=@(Get-EloActiveVulnerabilities | Where-Object { $_.id -ceq $deciding })[0] }
    } catch { }
    return $result
}
function Get-EloBackupRisk {
    param([string]$Vendor,[string]$Version)
    return [string](Get-EloBackupAssessment $Vendor $Version).Risk
}
function Get-EloVulnMessageValues {
    # Placeholder values for catalog messages about one vulnerability.
    param($Vulnerability,[string]$Vendor='',[string]$Version='',[string]$Runtime='')
    $option=''
    if ($Vulnerability) { $a=Get-EloVulnAction $Vulnerability 'jvm-option'; if ($a) { $option=[string]$a.option } }
    return @{vendor=$Vendor;version=$Version;runtime=$Runtime;option=$option
        id=$(if ($Vulnerability) { [string]$Vulnerability.id } else { '' });alias=$(if ($Vulnerability) { [string](@($Vulnerability.aliases) | Select-Object -First 1) } else { '' })}
}
function Get-EloRestoreSecurityWarning {
    # Bilingual security warning for restoring a backup, from the catalog message of the deciding vulnerability.
    param([string]$Risk,$Vulnerability,[string]$Vendor,[string]$Version)
    if (-not $Vulnerability -or -not $Vulnerability.messages) { return @() }
    $name='restoreUnknown'; if ($Risk -ceq 'vulnerable') { $name='restoreVulnerable' } elseif ($Risk -ceq 'patched') { $name='restoreFixed' }
    $m=$Vulnerability.messages.$name
    if (-not $m) { return @() }
    $values=Get-EloVulnMessageValues $Vulnerability $Vendor $Version
    return @(@{en=(Format-EloVulnText ([string]$m.en) $values);de=(Format-EloVulnText ([string]$m.de) $values)})
}function Get-EloBackupList {
    # Backup ZIPs written by this tool (<runtime>.backup-<yyyyMMddHHmmss>.zip) next to a runtime, on every
    # drive at level 1 (X:\) and level 2 (X:\<folder>\). Read-only, bounded, cached for 30 s. The ids are
    # server-side capabilities: the UI never sends a path.
    param($Session)
    $now=& $Session.Adapters.Clock
    if ($Session.BackupsCache -and $Session.BackupsCache.Expires -gt $now) { return $Session.BackupsCache.Items }
    $found=New-Object 'System.Collections.Generic.List[object]'
    $skip=@('Windows','$Recycle.Bin','System Volume Information','Recovery','PerfLogs')
    try {
        foreach ($root in @(& $Session.Adapters.BackupRoots)) {
            $dirs=New-Object 'System.Collections.Generic.List[string]'; $dirs.Add($root)
            try { foreach ($d in @([IO.Directory]::GetDirectories($root) | Select-Object -First 1000)) { if ($skip -cnotcontains (Split-Path -Leaf $d) -and -not ((Get-Item -LiteralPath $d -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { $dirs.Add($d) } } } catch { }
            foreach ($dir in $dirs) {
                try { $files=@([IO.Directory]::GetFiles($dir,'*.backup-*.zip')) } catch { continue }
                foreach ($file in $files) {
                    if ($found.Count -ge 50) { break }
                    $leaf=Split-Path -Leaf $file
                    if ($leaf -cnotmatch '^([A-Za-z0-9_.-]{1,64})\.backup-(\d{14})\.zip$') { continue }
                    $runtimeName=$Matches[1]; $stamp=$Matches[2]
                    $created=[datetime]::MinValue
                    if (-not [datetime]::TryParseExact($stamp,'yyyyMMddHHmmss',[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal,[ref]$created)) { continue }
                    $info=New-Object IO.FileInfo($file)
                    if ($info.Length -lt 1024 -or ($info.Attributes -band [IO.FileAttributes]::ReparsePoint)) { continue }
                    $release=Read-EloBackupRelease $file
                    $risk=Get-EloBackupRisk $release.Vendor $release.Version
                    $found.Add(@{Path=$file;Runtime=(Join-Path $dir $runtimeName);Root=$dir.TrimEnd('\');Stamp=$stamp;Version=$release.Version;Vendor=$release.Vendor;Risk=$risk;Created=$created.ToString('yyyy-MM-dd HH:mm');Size=[long]$info.Length})
                }
            }
        }
    } catch { }
    $Session.Backups=@{}; $items=@()
    foreach ($entry in @($found | Sort-Object { $_.Stamp } -Descending)) {
        $sha=[Security.Cryptography.SHA256]::Create()
        try { $id=([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes([string]$Session.Token+'|'+([string]$entry.Path).ToLowerInvariant()))) -replace '-','').ToLowerInvariant() } finally { $sha.Dispose() }
        $Session.Backups[$id]=$entry
        $items+=@{id=$id;path=[string]$entry.Path;runtime=[string]$entry.Runtime;version=[string]$entry.Version;vendor=[string]$entry.Vendor;risk=[string]$entry.Risk;created=[string]$entry.Created;size=[long]$entry.Size}
    }
    $Session.BackupsCache=@{Expires=$now.AddSeconds(30);Items=$items}
    if ($Session.BackupsLogged -ne $items.Count) {
        $Session.BackupsLogged=$items.Count
        $bad=@($items | Where-Object { $_.risk -cne 'patched' }).Count
        if ($items.Count -gt 0) { Write-EloLog $Session "Existing Java backups found: $($items.Count) ($bad vulnerable or of unknown security status). They can be restored without scanning." }
    }
    return $items
}
function Get-EloUpdateTarget {
    # Shared eligibility for update and restore: a scanned java.exe below a directory.
    param($Session,[string]$ResultId)
    $target=$Session.Targets[$ResultId]
    if (-not $target -or [string]$target.Location -cnotmatch '^[A-Za-z]:\\.+\\bin\\java\.exe$') { Stop-EloRequest 409 'target_not_eligible' }
    $runtime=[IO.Path]::GetDirectoryName([IO.Path]::GetDirectoryName([string]$target.Location))
    $root=[IO.Path]::GetDirectoryName($runtime)
    if ([string]::IsNullOrEmpty($root)) { Stop-EloRequestDetail 409 'update_preview_refused' 'runtime_is_a_drive_root' }
    return @{Target=$target;Runtime=$runtime;Root=$root}
}
function Get-EloUpdateUsers {
    # Services that will be stopped/restarted; any other process blocks the change.
    param($Session,[string]$Runtime)
    try { $users=& $Session.Adapters.RuntimeUsers $Runtime } catch { Stop-EloRequestDetail 409 'update_preview_refused' 'runtime_users_unreadable' }
    $blockers=@($users.Processes | ForEach-Object { ([string]$_.Name -creplace '[^A-Za-z0-9_.\-]','') } | Select-Object -Unique -First 3)
    if ($blockers.Count -gt 0) { Stop-EloRequestDetail 409 'update_preview_refused' ('runtime_in_use_by_'+($blockers -join '+')) }
    return @($users.Services)
}
function Format-EloServiceList {
    param($Services)
    return ((@($Services | ForEach-Object { [string]$_.Name } | Select-Object -First 12)) -join ', ')
}
function New-EloRuntimeUpdatePreview {
    param($Session,[string]$ResultId)
    $Session.Preview=$null; $Session.UpdateContext=$null
    if (-not (& $Session.Adapters.Admin)) { Stop-EloRequest 403 'administrator_required' }
    $info=Get-EloUpdateTarget $Session $ResultId
    $runtime=$info.Runtime; $root=$info.Root; $target=$info.Target
    try { $identity=& $Session.Adapters.Identity $runtime } catch { Stop-EloRequestDetail 409 'update_preview_refused' (ConvertTo-EloUpdateCode $_.Exception.Message) }
    try { $release=& $Session.Adapters.ResolveRelease $identity } catch { Stop-EloRequestDetail 409 'update_preview_refused' (ConvertTo-EloUpdateCode $_.Exception.Message) }
    if ((Compare-EloJavaVersion (ConvertTo-EloJavaVersion ([string]$identity.Version)) (ConvertTo-EloJavaVersion ([string]$release.Version))) -ge 0) { Stop-EloRequest 409 'update_not_needed' }
    $services=Get-EloUpdateUsers $Session $runtime
    $now=& $Session.Adapters.Clock
    $stamp=$now.ToString('yyyyMMddHHmmss')
    $paths=@{Runtime=$runtime;Old=($runtime+'.old-'+$stamp);Stage=($runtime+'.stage-'+$stamp);Backup=($runtime+'.backup-'+$stamp+'.zip');Download=($runtime+'.download-'+$stamp+'.zip')}
    $package=@{}; foreach ($key in @('Vendor','Branch','Architecture','ImageType','Version','Uri','Sha256','Size')) { $package[$key]=[string]$release[$key] }
    try {
        $context=& $Session.Adapters.NewUpdateContext $root $runtime ($services.Count -gt 0)
        $module=New-EloUpdatePreview -Context $context -Paths $paths -Package $package
    } catch { Stop-EloRequestDetail 409 'update_preview_refused' (ConvertTo-EloUpdateCode $_.Exception.Message) }
    $Session.UpdateContext=$context
    $preview=@{Id=(New-EloSecret);ResultId=$ResultId;ActionId='update-runtime';Module=$module;Paths=$paths;Package=$package;Root=$root;Services=$services
        JavaPath=[string]$target.Location;FromVersion=[string]$identity.Version;Expires=$now.AddMinutes(2)}
    $Session.Preview=$preview
    $from=[string]$identity.Version; $to=$package.Version
    $vendor=$package.Vendor; $kind=$package.ImageType.ToUpperInvariant()
    $summaryEn="Replace the $vendor $kind $($package.Branch) runtime in $runtime ($from) with the newest release of the same branch, $to ($($package.Architecture), SHA256 $($package.Sha256)). Steps: verified ZIP backup $($paths.Backup); HTTPS download from the vendor; extraction to $($paths.Stage); Java self-test; rename the old runtime to $($paths.Old); install; re-test. Any failure restores the old runtime. The old runtime and the backup are kept; nothing is deleted."
    $summaryDe="Die $vendor-$kind-$($package.Branch)-Runtime in $runtime ($from) durch die neueste Version desselben Branches ersetzen: $to ($($package.Architecture), SHA256 $($package.Sha256)). Schritte: geprueftes ZIP-Backup $($paths.Backup); HTTPS-Download beim Hersteller; Entpacken nach $($paths.Stage); Java-Selbsttest; alte Runtime nach $($paths.Old) umbenennen; installieren; erneut testen. Bei jedem Fehler wird die alte Runtime wiederhergestellt. Alte Runtime und Backup bleiben erhalten; es wird nichts geloescht."
    $warnings=@(
        @{en='ELO compatibility with this runtime is NOT verified; the update can affect ELO support. Confirming accepts this risk.';de='Die ELO-Kompatibilitaet dieser Runtime ist NICHT geprueft; das Update kann den ELO-Support beeintraechtigen. Mit der Bestaetigung wird dieses Risiko akzeptiert.'}
        @{en='The download is limited to the vendor''s official release host and its published SHA256. Installing the vendor package with its installer remains the preferred long-term fix.';de='Der Download ist auf den offiziellen Herstellerhost und die veroeffentlichte SHA256 beschraenkt. Die Installation des Herstellerpakets mit dem Installer bleibt die bevorzugte langfristige Loesung.'})
    if ($services.Count -gt 0) {
        $list=Format-EloServiceList $services
        $warnings=@(@{en="These services use the runtime and will be STOPPED before the replacement and started again afterwards: $list. ELO is unavailable meanwhile. Confirming accepts this.";de="Diese Dienste verwenden die Runtime und werden vor dem Austausch BEENDET und danach wieder gestartet: $list. ELO ist in dieser Zeit nicht verfuegbar. Mit der Bestaetigung wird dies akzeptiert."})+$warnings
    }
    return @{previewId=$preview.Id;summary=@{en=$summaryEn;de=$summaryDe};warnings=$warnings}
}
function Add-EloUpdateReportActions {
    param($Session,[string]$Outcome,$Preview,[int]$RuntimeIndex,[string]$FailureCode)
    $from=$Preview.FromVersion; $to=$Preview.Package.Version
    if ($Outcome -in @('Success','SimulatedSuccess','RolledBack','ManualRecoveryRequired')) {
        $Session.ReportActions+=@{Kind='Backup';Status='Proven';Verified=$true;BackupVerified=$true;RuntimeIndex=$RuntimeIndex;EvidenceCode='BackupManifestMatched';EvidenceVerified=$true;FromVersion=$from;BackupVersion=$from}
        $Session.ReportRecovery=@{Validated=$true;RuntimeIndex=$RuntimeIndex;Archive=$Preview.Paths.Backup;Original=$Preview.Paths.Runtime;Destination=($Preview.Paths.Runtime+'.restore')}
        $Session.BackupsCache=$null
        $Session.LastUpdate=@{Runtime=$Preview.Paths.Runtime;Root=$Preview.Root;Backup=$Preview.Paths.Backup;FromVersion=$from;ToVersion=$to;RuntimeIndex=$RuntimeIndex;Services=$Preview.Services}
    }
    switch ($Outcome) {
        { $_ -in @('Success','SimulatedSuccess') } { $Session.ReportActions+=@{Kind='Update';Status='Proven';Verified=$true;RuntimeIndex=$RuntimeIndex;EvidenceCode='InstalledRuntimeValidated';EvidenceVerified=$true;FromVersion=$from;ToVersion=$to} }
        'RolledBack' {
            $Session.ReportActions+=@{Kind='Update';Status='Failed';RuntimeIndex=$RuntimeIndex;EvidenceCode='ValidationFailed';EvidenceVerified=$true}
            $Session.ReportActions+=@{Kind='Restore';Status='Proven';Verified=$true;RuntimeIndex=$RuntimeIndex;EvidenceCode='OriginalRuntimeRestored';EvidenceVerified=$true;FromVersion=$to;ToVersion=$from}
        }
        'ManualRecoveryRequired' {
            $Session.ReportActions+=@{Kind='Update';Status='Failed';RuntimeIndex=$RuntimeIndex;EvidenceCode='ValidationFailed';EvidenceVerified=$true}
            $Session.ReportActions+=@{Kind='Restore';Status='Failed';RuntimeIndex=$RuntimeIndex;EvidenceCode='RestoreFailed';EvidenceVerified=$true}
        }
        default {
            $code='ValidationFailed'; if ($FailureCode -cmatch '^(download|package_verification|unverified_https|unverified_response|truncated|redirect)') { $code='DownloadFailed' }
            $Session.ReportActions+=@{Kind='Update';Status='Failed';RuntimeIndex=$RuntimeIndex;EvidenceCode=$code;EvidenceVerified=$true}
        }
    }
}
function Invoke-EloRuntimeUpdateAction {
    param($Session,$Body)
    $preview=$Session.Preview; $Session.Preview=$null # consume even on failure
    $context=$Session.UpdateContext; $Session.UpdateContext=$null
    if (-not $preview -or -not $context -or $preview.ActionId -cne 'update-runtime' -or $preview.Id -cne $Body.previewId -or
        $preview.ResultId -cne $Body.resultId -or $Body.actionId -cne 'update-runtime' -or (& $Session.Adapters.Clock) -ge $preview.Expires) { Stop-EloRequest 409 'preview_expired_or_mismatched' }
    if (-not (& $Session.Adapters.Admin)) { Stop-EloRequest 403 'administrator_required' }
    $target=$Session.Targets[$Body.resultId]
    if (-not $target -or $target.Location -cne $preview.JavaPath) { Stop-EloRequest 409 'stale_preview' }
    $index=[int]$Session.ReportIndexes[$Body.resultId]
    $module=$preview.Module
    # The UI confirmation states the unverified-compatibility risk and the services to stop; it authorises all module confirmations.
    $result=Invoke-EloRuntimeUpdate -Context $context -Confirmation $module.Confirmation -BranchConfirmation $module.BranchConfirmation -CompatibilityConfirmation $module.CompatibilityConfirmation
    $failure=ConvertTo-EloUpdateCode $result.Error
    Add-EloUpdateReportActions $Session ([string]$result.Status) $preview $index $failure
    $serviceNote=''; if ($result.ServiceError) { $serviceNote=ConvertTo-EloUpdateCode $result.ServiceError }
    switch ([string]$result.Status) {
        { $_ -in @('Success','SimulatedSuccess') } {
            if ($serviceNote) { return @{ok=$true;warning='services_not_restarted'} }
            return @{ok=$true}
        }
        'RolledBack' { Stop-EloRequestDetail 422 'update_failed_rolled_back' $failure }
        'ManualRecoveryRequired' { $Session.State='error'; $Session.RecoveryRequired=$true; Stop-EloRequestDetail 500 'update_manual_recovery_required' $failure }
        default { Stop-EloRequestDetail 422 'update_rejected_no_change' $failure }
    }
}
function Get-EloRestoreSource {
    # A restore source is either a scanned runtime with a backup made in this session, or a backup
    # discovered on disk (including backups from earlier sessions), selected by server-side id.
    param($Session,[string]$ResultId)
    if ($Session.Backups.ContainsKey($ResultId)) {
        $b=$Session.Backups[$ResultId]
        if (-not (Test-Path -LiteralPath $b.Path)) { Stop-EloRequest 409 'no_backup_for_target' }
        $current=''; $location=$null
        try { $current=[string](& $Session.Adapters.Identity $b.Runtime).Version } catch { $current='' }
        $match=$Session.Targets.GetEnumerator() | Where-Object { [string]$_.Value.Location -ieq (Join-Path $b.Runtime 'bin\java.exe') } | Select-Object -First 1
        if ($match) { $location=[string]$match.Value.Location }
        return @{Runtime=$b.Runtime;Root=$b.Root;Backup=$b.Path;ToVersion=[string]$b.Version;Vendor=[string]$b.Vendor;Risk=[string]$b.Risk;FromVersion=$current;JavaPath=$location;Index=$(if ($match) { [int]$Session.ReportIndexes[$match.Key] } else { 0 });FromDisk=$true}
    }
    $info=Get-EloUpdateTarget $Session $ResultId
    $last=$Session.LastUpdate
    if (-not $last -or [string]$last.Runtime -cne [string]$info.Runtime -or -not (Test-Path -LiteralPath $last.Backup)) { Stop-EloRequest 409 'no_backup_for_target' }
    $rel=Read-EloBackupRelease $last.Backup
    return @{Runtime=$info.Runtime;Root=$info.Root;Backup=$last.Backup;ToVersion=[string]$last.FromVersion;Vendor=[string]$rel.Vendor;Risk=(Get-EloBackupRisk $rel.Vendor ([string]$last.FromVersion));FromVersion=[string]$last.ToVersion;JavaPath=[string]$info.Target.Location;Index=[int]$Session.ReportIndexes[$ResultId];FromDisk=$false}
}
function New-EloRestorePreview {
    param($Session,[string]$ResultId)
    $Session.Preview=$null
    if (-not (& $Session.Adapters.Admin)) { Stop-EloRequest 403 'administrator_required' }
    $source=Get-EloRestoreSource $Session $ResultId
    $services=@(); if (Test-Path -LiteralPath $source.Runtime) { $services=Get-EloUpdateUsers $Session $source.Runtime }
    $now=& $Session.Adapters.Clock
    $preview=@{Id=(New-EloSecret);ResultId=$ResultId;ActionId='restore-backup';Runtime=$source.Runtime;Root=$source.Root;Backup=$source.Backup;Services=$services
        Stamp=$now.ToString('yyyyMMddHHmmss');FromVersion=$source.FromVersion;ToVersion=$source.ToVersion;Vendor=[string]$source.Vendor;Risk=[string]$source.Risk;JavaPath=$source.JavaPath;Index=$source.Index;Expires=$now.AddMinutes(2)}
    $Session.Preview=$preview
    $summaryEn="Restore the runtime ($($preview.ToVersion)) of $($source.Runtime) from the backup ZIP $($source.Backup). Every file is hash-checked before the swap; the current runtime (if any) is renamed to $($source.Runtime).replaced-$($preview.Stamp) and kept; nothing is deleted."
    $summaryDe="Die Runtime ($($preview.ToVersion)) von $($source.Runtime) aus dem Backup-ZIP $($source.Backup) wiederherstellen. Jede Datei wird vor dem Austausch per Hash geprueft; die aktuelle Runtime (falls vorhanden) wird nach $($source.Runtime).replaced-$($preview.Stamp) umbenannt und bleibt erhalten; es wird nichts geloescht."
    $ver=[string]$preview.ToVersion; $vend=[string]$source.Vendor
    $assessment=Get-EloBackupAssessment $vend $ver
    $warnings=@(Get-EloRestoreSecurityWarning ([string]$source.Risk) $assessment.Vulnerability $vend $ver)
    if ($services.Count -gt 0) {
        $list=Format-EloServiceList $services
        $warnings=@(@{en="The restore requires STOPPING the ELO services (Tomcat) that use this runtime: $list. ELO is unavailable while the runtime is swapped; they are started again afterwards. Confirming accepts this.";de="Die Wiederherstellung erfordert das BEENDEN der ELO-Dienste (Tomcat), die diese Runtime verwenden: $list. ELO ist waehrend des Austauschs nicht verfuegbar; die Dienste werden danach wieder gestartet. Mit der Bestaetigung wird dies akzeptiert."})+$warnings
    } else {
        $warnings=@(@{en='No running service or process uses this runtime right now. If the ELO Tomcat services run on it, stop them first (ELO will be unavailable) or the restore is refused.';de='Zurzeit verwendet kein laufender Dienst oder Prozess diese Runtime. Laufen die ELO-Tomcat-Dienste darauf, diese zuerst beenden (ELO ist dann nicht verfuegbar), sonst wird die Wiederherstellung abgelehnt.'})+$warnings
    }
    return @{previewId=$preview.Id;summary=@{en=$summaryEn;de=$summaryDe};warnings=$warnings}
}
function Invoke-EloRestoreAction {
    param($Session,$Body)
    $preview=$Session.Preview; $Session.Preview=$null
    if (-not $preview -or $preview.ActionId -cne 'restore-backup' -or $preview.Id -cne $Body.previewId -or $preview.ResultId -cne $Body.resultId -or
        $Body.actionId -cne 'restore-backup' -or (& $Session.Adapters.Clock) -ge $preview.Expires) { Stop-EloRequest 409 'preview_expired_or_mismatched' }
    if (-not (& $Session.Adapters.Admin)) { Stop-EloRequest 403 'administrator_required' }
    if ($preview.JavaPath) {
        $target=$Session.Targets[$Body.resultId]
        if (-not $Session.Backups.ContainsKey([string]$Body.resultId) -and (-not $target -or $target.Location -cne $preview.JavaPath)) { Stop-EloRequest 409 'stale_preview' }
    }
    $index=[int]$preview.Index
    try {
        $null=& $Session.Adapters.RestoreBackup $preview.Root $preview.Runtime $preview.Backup ($preview.Services.Count -gt 0) $preview.Stamp
        $restored=& $Session.Adapters.Identity $preview.Runtime
        if ([string]$preview.ToVersion -and [string]$preview.ToVersion -cne 'unknown' -and -not (Test-EloSameJavaRelease ([string]$restored.Version) ([string]$preview.ToVersion))) { throw 'restored_version_mismatch' }
    } catch {
        if ($index -gt 0) { $Session.ReportActions+=@{Kind='Restore';Status='Failed';RuntimeIndex=$index;EvidenceCode='RestoreFailed';EvidenceVerified=$true} }
        Stop-EloRequestDetail 422 'restore_failed_no_change' (ConvertTo-EloUpdateCode $_.Exception.Message)
    }
    # The restored runtime is new evidence for the report: its classification (vulnerable or fixed) is recorded
    # even when the restore was done without a scan in this session.
    $classification='Unknown'; $code='Unknown'
    if ([string]$preview.Risk -ceq 'vulnerable') { $classification='PotentiallyVulnerable'; $code='AdvisoryRangeMatch' }
    elseif ([string]$preview.Risk -ceq 'patched') { $classification='Fixed'; $code='AdvisoryFixedVersion' }
    $restoredVendor=[string]$preview.Vendor; if ($restoredVendor -cnotin @('Temurin','Azul Zulu')) { $restoredVendor='Unknown' }
    $Session.ReportJvms+=@{Version=[string]$restored.Version;Verified=$true;ExecutionVerified=$true;Vendor=$restoredVendor;VendorVerified=($restoredVendor -cne 'Unknown')
        Classification=$classification;ClassificationVerified=($classification -cne 'Unknown');EvidenceCode=$code}
    $newIndex=$Session.ReportJvms.Count
    $Session.ReportActions+=@{Kind='Restore';Status='Proven';Verified=$true;RuntimeIndex=$newIndex;EvidenceCode='OriginalRuntimeRestored';EvidenceVerified=$true;FromVersion=$preview.FromVersion;ToVersion=$preview.ToVersion}
    $logAssessment=Get-EloBackupAssessment ([string]$preview.Vendor) ([string]$restored.Version)
    $logValues=Get-EloVulnMessageValues $logAssessment.Vulnerability ([string]$preview.Vendor) ([string]$restored.Version) ([string]$preview.Runtime)
    $logName='logRestoreFixed'; if ($classification -ceq 'PotentiallyVulnerable') { $logName='logRestoreVulnerable' } elseif ($classification -ceq 'Unknown') { $logName='logRestoreUnknown' }
    if ($logAssessment.Vulnerability -and $logAssessment.Vulnerability.messages.$logName) { Write-EloLog $Session (Format-EloVulnText ([string]$logAssessment.Vulnerability.messages.$logName) $logValues) }
    $Session.LastUpdate=$null; $Session.BackupsCache=$null
    return @{ok=$true}
}function Get-EloSessionReportHtml {
    param($Session,[ValidateSet('en','de')][string]$Language)
    # ELO version: only from the installed Indexserver files below the parent of a scanned runtime.
    $eloRoots=@($Session.Targets.Values | ForEach-Object { try { [IO.Path]::GetDirectoryName([IO.Path]::GetDirectoryName([IO.Path]::GetDirectoryName([string]$_.Location))) } catch { $null } } | Where-Object { $_ } | Select-Object -Unique)
    $eloVersion=$null; if ($Session.Adapters.EloVersion -is [scriptblock] -and $eloRoots.Count -gt 0) { try { $eloVersion=& $Session.Adapters.EloVersion $eloRoots } catch { $eloVersion=$null } }
    $eloAdapter={ @{Verified=(-not [string]::IsNullOrWhiteSpace([string]$eloVersion));Version=[string]$eloVersion} }.GetNewClosure()
    $report=New-EloTechnicalReport -EloVersionAdapter $eloAdapter -ResourceCollector $Session.Adapters.Resources -OptionsCollector $Session.Adapters.ReportOptions -JvmEvidence $Session.ReportJvms -Actions $Session.ReportActions -RecoveryEvidence $Session.ReportRecovery
    $html=ConvertTo-EloTechnicalReportHtml $report -Language $Language
    $states=@{idle='Ready';scanning='Scanning';cancelling='Cancelling';completed='Completed';cancelled='Cancelled';error='Failed'}
    $notice='Session scan state: '; $scope='Session observations (including earlier scans); only a completed scan is a complete snapshot. A runtime update is performed only after explicit confirmation. ELO API support and running ELO process mitigation are not verified.'
    if ($Language -eq 'de') {
        $states=@{idle='Bereit';scanning='Scan laeuft';cancelling='Abbruch angefordert';completed='Abgeschlossen';cancelled='Abgebrochen';error='Fehlgeschlagen'}
        $notice='Scanstatus der Sitzung: '; $scope='Sitzungsnachweise (auch fruehere Scans); nur ein abgeschlossener Scan ist eine vollstaendige Momentaufnahme. Ein Runtime-Update erfolgt nur nach ausdruecklicher Bestaetigung. ELO-API-Unterstuetzung und Risikominderung im laufenden ELO-Prozess sind nicht nachgewiesen.'
    }
    $state=$states[$Session.State]; if (-not $state) { $state='Unknown / Unbekannt' }
    # A failed rollback can invalidate earlier machine-option evidence. Do not
    # present a historical success as the current environment's postcondition.
    $recovery=''; if ($Session.RecoveryRequired) { $recovery='Manual recovery required / Manuelle Wiederherstellung erforderlich.' }
    return $html.Replace('<head>','<head><meta name="referrer" content="no-referrer"><meta http-equiv="Content-Security-Policy" content="default-src &#39;none&#39;; base-uri &#39;none&#39;; form-action &#39;none&#39;">').Replace('<body>','<body><p>'+ $notice+$state+'. '+$scope+' '+$recovery+'</p>')
}
function Invoke-EloApi {
    param($Session,$Request)
    Assert-EloBoundary $Session $Request
    if (-not (Test-EloSecret ([string]$Request.Headers['X-Session-Token']) $Session.Token)) { Stop-EloRequest 401 'authentication_required' }
    $get=@('/api/status','/api/results'); $post=@('/api/scan','/api/cancel','/api/preview','/api/action','/api/report')
    if ($Request.Target -cnotin ($get+$post)) { Stop-EloRequest 404 'unknown_route' }
    if (($Request.Target -cin $get -and $Request.Method -cne 'GET') -or ($Request.Target -cin $post -and $Request.Method -cne 'POST')) { Stop-EloRequest 405 'method_rejected' }
    Update-EloScanWorker $Session
    if ($Request.Method -ceq 'GET') {
        if ($Request.Body.Length -ne 0) { Stop-EloRequest 400 'unexpected_body' }
        if ($Request.Target -ceq '/api/status') { return @{state=$Session.State} }
        if ($Session.RecoveryRequired) { Stop-EloRequest 500 'rollback_failed_manual_recovery_required' }
        if ($Session.LastError) { Stop-EloRequest $Session.LastError.Status $Session.LastError.Code }
        return @{results=@($Session.Results);security=(Get-EloSecurityMetadata);vulnerabilities=@(Get-EloVulnerabilityInfo);backups=@(Get-EloBackupList $Session)}
    }
    if ($Request.Headers['Content-Type'] -cnotin @('application/json','application/json; charset=utf-8')) { Stop-EloRequest 415 'json_required' }
    switch -CaseSensitive ($Request.Target) {
        '/api/report' {
            $body=ConvertFrom-EloBody $Request.Body -Required @('language')
            if ($body.language -cnotin @('en','de')) { Stop-EloRequest 400 'invalid_language' }
            return @{html=(Get-EloSessionReportHtml $Session $body.language)}
        }
        '/api/scan' {
            $body=ConvertFrom-EloBody $Request.Body -Optional @('searchPath')
            $path=$null
            if ($body.PSObject.Properties.Name -contains 'searchPath') { $path=Test-EloLocalPath $body.searchPath -RequireDirectory }
            Start-EloScanWorker $Session $path
            $scope='on drives C: to Z:'; if ($path) { $scope="in $path" }
            Write-EloLog $Session "Scan started $scope."
            return @{ok=$true}
        }
        '/api/cancel' {
            $null=ConvertFrom-EloBody $Request.Body
            $Session.Preview=$null
            if ($Session.Worker) { $Session.Worker.Control.Cancel=$true; $Session.State='cancelling'; Write-EloLog $Session 'Scan cancel requested.' }
            return @{ok=$true}
        }
        default {
            $required=@('actionId','resultId'); if ($Request.Target -ceq '/api/action') { $required+= 'previewId' }
            $body=ConvertFrom-EloBody $Request.Body -Required $required
            foreach ($key in $required) { if ($body.$key -cnotmatch '^[A-Za-z0-9_-]{1,128}$') { Stop-EloRequest 400 'invalid_id' } }
            if ($body.actionId -cnotin @('mitigate','update-runtime','restore-backup')) { Stop-EloRequest 400 'invalid_action' }
            if ($Session.RecoveryRequired) { Stop-EloRequest 409 'manual_recovery_required_close_session' }
            $diskRestore=($body.actionId -ceq 'restore-backup' -and $Session.Backups.ContainsKey([string]$body.resultId))
            if ($Session.Worker -or $Session.State -cin @('scanning','cancelling') -or ($Session.State -cne 'completed' -and -not $diskRestore)) { Stop-EloRequest 409 'completed_scan_required' }
            $phase='preview'; if ($Request.Target -ceq '/api/action') { $phase='apply' }
            $subject=''
            if ($diskRestore) { $subject=[string]$Session.Backups[[string]$body.resultId].Path }
            elseif ($Session.Targets.ContainsKey([string]$body.resultId)) { $subject=[string]$Session.Targets[[string]$body.resultId].Location }
            Write-EloLog $Session "$phase '$($body.actionId)' requested for $subject"
            try {
            $preview=($Request.Target -ceq '/api/preview')
            if ($body.actionId -ceq 'update-runtime') { if ($preview) { $result=New-EloRuntimeUpdatePreview $Session $body.resultId } else { $result=Invoke-EloRuntimeUpdateAction $Session $body } }
            elseif ($body.actionId -ceq 'restore-backup') { if ($preview) { $result=New-EloRestorePreview $Session $body.resultId } else { $result=Invoke-EloRestoreAction $Session $body } }
            else { if ($preview) { $result=New-EloMitigationPreview $Session $body.resultId } else { $result=Invoke-EloMitigation $Session $body } }
            Write-EloLog $Session "$phase '$($body.actionId)' OK."
            return $result
            } catch {
                $failure=ConvertTo-EloErrorResponse $_.Exception
                Write-EloLog $Session "$phase '$($body.actionId)' FAILED: $($failure.Body.error) (HTTP $($failure.Status))"
                throw
            }
        }
    }
}
function Read-EloHttpRequest {
    param([IO.Stream]$Stream,[string]$Remote)
    $clock=[Diagnostics.Stopwatch]::StartNew(); $header=New-Object Text.StringBuilder
    while ($true) {
        if ($clock.Elapsed.TotalSeconds -gt 5) { Stop-EloRequest 408 'request_timeout' }
        $b=$Stream.ReadByte()
        if ($b -lt 0) { Stop-EloRequest 400 'incomplete_request' }
        if ($b -gt 127 -or ($b -lt 32 -and $b -notin @(9,10,13))) { Stop-EloRequest 400 'invalid_header' }
        $null=$header.Append([char]$b)
        if ($header.Length -gt 16384) { Stop-EloRequest 431 'headers_too_large' }
        if ($header.Length -ge 4 -and $header.ToString($header.Length-4,4) -ceq "`r`n`r`n") { break }
    }
    $lines=$header.ToString().Split(@("`r`n"),[StringSplitOptions]::None)
    if ($lines[0] -cnotmatch '^(GET|POST|[A-Z]+) (/[^ ]*) HTTP/1\.1$') { Stop-EloRequest 400 'invalid_request_line' }
    $method=$Matches[1]; $target=$Matches[2]; $headers=@{}
    for ($i=1; $i -lt $lines.Length-2; $i++) {
        if ($lines[$i] -notmatch '^([A-Za-z0-9-]+):[ \t]*([^\r\n]*)$') { Stop-EloRequest 400 'invalid_header' }
        $name=$Matches[1]; $value=$Matches[2].Trim()
        if ($headers.ContainsKey($name)) { Stop-EloRequest 400 'duplicate_header' }
        $headers[$name]=$value
    }
    if ($headers.ContainsKey('Transfer-Encoding') -or $headers.ContainsKey('Expect') -or $headers.ContainsKey('Upgrade')) { Stop-EloRequest 400 'unsupported_framing' }
    $length=0
    if ($headers.ContainsKey('Content-Length')) {
        if ($headers['Content-Length'] -cnotmatch '^(0|[1-9][0-9]{0,4})$') { Stop-EloRequest 400 'invalid_length' }
        $length=[int]$headers['Content-Length']
    } elseif ($method -ceq 'POST') { Stop-EloRequest 411 'length_required' }
    if ($length -gt 8192) { Stop-EloRequest 413 'body_too_large' }
    $bytes=New-Object byte[] $length; $offset=0
    while ($offset -lt $length) {
        if ($clock.Elapsed.TotalSeconds -gt 5) { Stop-EloRequest 408 'request_timeout' }
        $count=$Stream.Read($bytes,$offset,$length-$offset)
        if ($count -le 0) { Stop-EloRequest 400 'incomplete_body' }
        $offset+=$count
    }
    try { $utf8=New-Object Text.UTF8Encoding($false,$true); $body=$utf8.GetString($bytes) } catch { Stop-EloRequest 400 'invalid_utf8' }
    return [pscustomobject]@{Method=$method;Target=$target;Headers=$headers;Body=$body;Remote=$Remote}
}
function Write-EloHttpResponse {
    param([IO.Stream]$Stream,[int]$Status,[string]$Content,[string]$ContentType='application/json; charset=utf-8')
    $bytes=[Text.Encoding]::UTF8.GetBytes($Content)
    $headers="HTTP/1.1 $Status Response`r`nConnection: close`r`nContent-Type: $ContentType`r`nContent-Length: $($bytes.Length)`r`nCache-Control: no-store`r`nX-Content-Type-Options: nosniff`r`nReferrer-Policy: no-referrer`r`nX-Frame-Options: DENY`r`nContent-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`r`n`r`n"
    $head=[Text.Encoding]::ASCII.GetBytes($headers)
    $Stream.Write($head,0,$head.Length); $Stream.Write($bytes,0,$bytes.Length); $Stream.Flush()
}
function ConvertTo-EloErrorResponse {
    param([Exception]$Exception)
    $status=500; $code='operation_failed'; $cursor=$Exception
    while ($null -ne $cursor) {
        if ($cursor.Data.Contains('Status')) { $status=[int]$cursor.Data['Status']; $code=$cursor.Message; break }
        if ($cursor -is [UnauthorizedAccessException] -or $cursor -is [Security.SecurityException]) { $status=403; $code='access_denied'; break }
        $cursor=$cursor.InnerException
    }
    $warnings=@()
    switch ($code) {
        'access_denied' { $warnings+=@{en='Access was denied. Check elevation and filesystem/registry permissions; no protection is claimed. Do not bypass access controls.';de='Zugriff verweigert. Administratorrechte und Datei-/Registrierungsberechtigungen pruefen; kein Schutz zugesichert. Zugriffsschutz nicht umgehen.'} }
        'administrator_required' { $warnings+=@{en='Mitigation requires an elevated administrator session. Read-only scans do not require elevation; inaccessible locations can make assessment incomplete.';de='Risikominderung erfordert eine erhoehte Administratorsitzung. Nur-Lese-Scans brauchen keine Erhoehung; unzugaengliche Orte koennen die Bewertung unvollstaendig machen.'} }
        'rollback_failed_manual_recovery_required' { $warnings+=@{en='JAVA_TOOL_OPTIONS may still be changed. Further actions are locked. Restore JAVA_TOOL_OPTIONS with the exact previous value and registry type saved from the preview using an approved Registry Editor procedure; verify manually before closing and starting a new session. Existing JVM protection is not claimed.';de='JAVA_TOOL_OPTIONS ist moeglicherweise noch geaendert. Weitere Aktionen sind gesperrt. JAVA_TOOL_OPTIONS mit exaktem alten Wert und Registrierungstyp aus der Vorschau per freigegebenem Registrierungseditor wiederherstellen und manuell pruefen, bevor eine neue Sitzung gestartet wird. Kein Schutz bestehender JVMs zugesichert.'} }
        'manual_recovery_required_close_session' { $warnings+=@{en='Manual recovery is required before another change. Restore the preview backup and verify it; opening a new session alone does not restore the environment.';de='Vor einer weiteren Aenderung ist manuelle Wiederherstellung erforderlich. Vorschau-Sicherung wiederherstellen und pruefen; eine neue Sitzung allein stellt die Umgebung nicht wieder her.'} }
        'verification_failed_rolled_back' { $warnings+=@{en='Verification failed; the exact previous environment value and type were restored and read back. No protection is claimed.';de='Pruefung fehlgeschlagen; exakter alter Umgebungswert und Typ wurden wiederhergestellt und zurueckgelesen. Kein Schutz zugesichert.'} }
        'scan_incomplete' { $warnings+=@{en='The scan encountered inaccessible/skipped locations or traversal limits. Results are not a complete assessment. Select a narrower accessible local root; review permissions without bypassing access controls.';de='Der Scan traf auf unzugaengliche/uebersprungene Orte oder Suchgrenzen. Keine vollstaendige Bewertung. Engeren zugaenglichen lokalen Suchpfad waehlen und Berechtigungen pruefen, ohne Zugriffsschutz zu umgehen.'} }
        'inaccessible_path' { $warnings+=@{en='The selected local directory is missing or inaccessible. Select an accessible directory and check permissions.';de='Das ausgewaehlte lokale Verzeichnis fehlt oder ist unzugaenglich. Zugaengliches Verzeichnis waehlen und Berechtigungen pruefen.'} }
        'update_unavailable_provenance_compatibility_backup_replacement_rollback_not_verified' { $warnings+=@{en='Automatic runtime update is unavailable: provenance, ELO compatibility, validated backups, reversible replacement and rollback guarantees are not implemented and verified. Nothing was downloaded or replaced.';de='Automatisches Laufzeit-Update nicht verfuegbar: Herkunft, ELO-Kompatibilitaet, validierte Sicherung, reversible Ersetzung und Wiederherstellung sind nicht implementiert und geprueft. Nichts heruntergeladen oder ersetzt.'} }
    }
    $detail=''; if ($cursor -and $cursor.Data.Contains('Detail')) { $detail=' ['+[string]$cursor.Data['Detail']+']' }
    switch ($code) {
        'update_not_needed' { $warnings+=@{en='This runtime is already the newest release of its branch. Nothing to update.';de='Diese Runtime ist bereits die neueste Version ihres Branches. Nichts zu aktualisieren.'} }
        'no_backup_for_target' { $warnings+=@{en='No backup from this session exists for this runtime. Restore manually from a backup ZIP using the commands in the technical report.';de='Fuer diese Runtime existiert in dieser Sitzung kein Backup. Manuell aus einem Backup-ZIP wiederherstellen; Befehle stehen im technischen Bericht.'} }
        'restore_failed_no_change' { $warnings+=@{en="The restore was rejected before the runtime was swapped.$detail The current runtime is unchanged.";de="Die Wiederherstellung wurde abgelehnt, bevor die Runtime getauscht wurde.$detail Die aktuelle Runtime ist unveraendert."} }
        'update_preview_refused' { $warnings+=@{en="The runtime update cannot be offered for this JVM (only Eclipse Temurin or Azul Zulu on Windows, no other process using it, writable, with enough disk space and a published newer release).$detail Nothing was downloaded or changed.";de="Das Runtime-Update kann fuer diese JVM nicht angeboten werden (nur Eclipse Temurin oder Azul Zulu unter Windows, von keinem anderen Prozess verwendet, beschreibbar, genug Speicherplatz und eine veroeffentlichte neuere Version).$detail Nichts wurde heruntergeladen oder geaendert."} }
        'update_rejected_no_change' { $warnings+=@{en="The update was rejected before the runtime was replaced.$detail The original runtime is unchanged.";de="Das Update wurde abgelehnt, bevor die Runtime ersetzt wurde.$detail Die urspruengliche Runtime ist unveraendert."} }
        'update_failed_rolled_back' { $warnings+=@{en="The new runtime failed validation.$detail The original runtime was restored and verified; the failed runtime and the backup ZIP were kept.";de="Die neue Runtime bestand die Pruefung nicht.$detail Die urspruengliche Runtime wurde wiederhergestellt und geprueft; fehlgeschlagene Runtime und Backup-ZIP bleiben erhalten."} }
        'update_manual_recovery_required' { $warnings+=@{en="Automatic restore failed.$detail Further actions are locked. Restore manually from the backup ZIP using the commands in the technical report.";de="Automatische Wiederherstellung fehlgeschlagen.$detail Weitere Aktionen sind gesperrt. Manuell aus dem Backup-ZIP wiederherstellen; Befehle stehen im technischen Bericht."} }
    }
    return @{Status=$status;Body=@{error=$code;warnings=@($warnings)}}
}
function New-EloLoopbackListener {
    param([ValidateRange(0,65535)][int]$Port=0)
    $listener=New-Object Net.Sockets.TcpListener([Net.IPAddress]::Parse('127.0.0.1'),$Port)
    try { $listener.Start(8); return $listener }
    catch { $listener.Stop(); Stop-EloRequest 503 'loopback_bind_failed' }
}
function Invoke-EloSessionLaunch {
    param($Session,[switch]$NoBrowser,[scriptblock]$LaunchHandler,
        [scriptblock]$BrowserLauncher={ param($Uri) Start-Process -FilePath $Uri -ErrorAction Stop | Out-Null })
    $uri=$Session.Origin+'/#token='+$Session.Token
    if ($NoBrowser) {
        if (-not $LaunchHandler) { Stop-EloRequest 422 'no_browser_requires_private_launch_handler' }
        try { & $LaunchHandler $uri *> $null } catch { Stop-EloRequest 503 'private_launch_failed' }
    } else {
        try { & $BrowserLauncher $uri *> $null } catch { Stop-EloRequest 503 'browser_launch_failed' }
    }
}
function Start-EloServer {
    param([Parameter(Mandatory=$true)][string]$UiHtml,[Parameter(Mandatory=$true)][string]$ScanSource,
        [ValidateRange(0,65535)][int]$Port=0,[switch]$OpenBrowser,[switch]$NoBrowser,[scriptblock]$LaunchHandler)
    if ($NoBrowser -and $OpenBrowser) { Stop-EloRequest 422 'conflicting_launch_options' }
    if ($NoBrowser -and -not $LaunchHandler) { Stop-EloRequest 422 'no_browser_requires_private_launch_handler' }
    $listener=New-EloLoopbackListener -Port $Port
    $session=$null
    try {
        $Port=$listener.LocalEndpoint.Port
        $session=New-EloServerSession -Port $Port -UiHtml $UiHtml -ScanSource $ScanSource
        Invoke-EloSessionLaunch $session -NoBrowser:$NoBrowser -LaunchHandler $LaunchHandler
        Write-Output "ELO local server listening on 127.0.0.1:$Port. Close this host to stop."
        while ($true) {
            Update-EloScanWorker $session
            if (-not $listener.Pending()) { Start-Sleep -Milliseconds 40; continue }
            $client=$listener.AcceptTcpClient()
            try {
                $client.ReceiveTimeout=1000; $client.SendTimeout=1000
                $stream=$client.GetStream(); $status=200; $type='application/json; charset=utf-8'
                try {
                    $request=Read-EloHttpRequest $stream $client.Client.RemoteEndPoint.Address.ToString()
                    Assert-EloBoundary $session $request
                    if ($request.Target -ceq '/' -and $request.Method -ceq 'GET' -and $request.Body.Length -eq 0) { $content=$session.UiHtml; $type='text/html; charset=utf-8' }
                    else { $content=Invoke-EloApi $session $request | ConvertTo-Json -Depth 8 -Compress }
                } catch {
                    $failure=ConvertTo-EloErrorResponse $_.Exception
                    $status=$failure.Status; $content=$failure.Body | ConvertTo-Json -Depth 5 -Compress
                    # Helps diagnosing a stale browser tab (old session link); logged once per distinct cause.
                    $rejected="Rejected request: HTTP $status $($failure.Body.error)"
                    if ($status -in @(400,401,403,404,405) -and $session.LastRejected -cne $rejected) { $session.LastRejected=$rejected; Write-EloLog $session ($rejected+'. If this is a browser tab from an earlier run, close it and use the page opened by the current run.') }
                }
                Write-EloHttpResponse $stream $status $content $type
            } catch { # Socket errors are intentionally not logged (request data may contain credentials).
            } finally { $client.Close() }
        }
    } finally {
        $listener.Stop()
        if ($session -and $session.Worker) {
            $session.Worker.Control.Cancel=$true
            try { $session.Worker.PowerShell.Stop() } finally { $session.Worker.PowerShell.Dispose() }
        }
        if ($session) { $session.Preview=$null; $session.Token=$null }
    }
}
::ELO_PATCH_END:SERVER_PS

::ELO_PATCH_BEGIN:UI_HTML
<!doctype html>
<!-- Integration contract (no external assets or shared state):
 Serve this page from the same loopback origin as /api; open /#token=<URL-encoded token>.
 The fragment is removed immediately. Authentication is X-Session-Token only.
 GET status -> {state: idle|scanning|cancelling|completed|cancelled|error,
                progress?: number (0..100), checked?: nonnegative integer}.
 GET results -> {results:[{id,path,runtimeRoot,version,vendor,architecture,status,
                         eloRationale:{en,de},classificationEvidence:{en,de}}],
                 security:{verifiedOn: YYYY-MM-DD|null,
                           advisories:[{id,title:{en,de},url}]}}.
 Limits (UTF-16 code units): <=250 JVMs; id 1..128 [A-Za-z0-9_-]; path/root
 1..1024; version 1..128; vendor 1..256; rationale 1..2048 per language;
 classification evidence 1..4096 per language. architecture: x86|x64|arm64|unknown.
 status: vulnerable|patched|not-affected|inconclusive|mitigated|unsupported|safe.
 Unknown classifications or missing evidence fail closed, never imply safety.
 Every result is one JVM; path is its ELO installation path; runtimeRoot is its
 actual Java root. Evidence must explain association and classification, including
 uncertainty; use explicit unknown text + inconclusive when not determinable.
 security: <=16 advisories, id <=128, title 1..256 per language, URL <=512.
 Nonempty advisories require a real verification date from 2000 through today (UTC).
 Empty advisories require verifiedOn:null. Backend owns actual source verification;
 the UI validates format/official-host allowlist, not the truth of an advisory.
 Allowed URLs: HTTPS, no credentials/port/query/fragment, canonical paths under
 www.oracle.com/security-alerts/ or openjdk.org/groups/vulnerability/advisories/,
 plus these exact parent-verified vendor advisories (no other Adoptium or
 linux.oracle.com URLs):
 https://adoptium.net/news/2026/11/temurin-november-2026-cspu-java4shell/
 https://linux.oracle.com/cve/CVE-2026-114938.html
 All response objects use only documented keys; text is nonblank and forbids control
 characters except tab/newline/CR for readable evidence. JSON bodies <=4 MiB UTF-8;
 never silently truncate JVMs or evidence: report a failure and narrow the scan root
 if limits are exceeded (this frontend has no pagination).
 preview summary 1..4096 per language, <=16 warnings of 1..2048 per language.
 POST scan -> {} checks ready fixed or removable drives C: through Z: at exactly
 X:\java\bin\java.exe and X:\ELO\java\bin\java.exe. An optional {searchPath:
 absolute local Windows directory} adds a manual root after the root checks
 (1..1024, no controls/wildcards/device/UNC/relative paths). This is the ONLY path input. Preserve spaces; treat as plain JSON
 data, never shell/PowerShell text or a command. Backend MUST independently validate
 and canonicalize, enforce local read-only traversal, handle reparse points safely,
 and reject invalid/inaccessible roots. Do not echo the root into activity logs.
 POST cancel -> {}; both respond {ok:true}. Cancel is a request, not completion.
 POST preview -> {actionId: mitigate|update-runtime|restore-backup, resultId}; response
 {previewId, summary:{en,de}, warnings:[{en,de}]}. Preview must be read-only and
 explain exact scope, backup, rollback, compatibility and provenance as applicable.
 POST action -> {actionId, resultId, previewId}; response {ok:true} ONLY on completion.
 All POSTs use application/json. Apart from scan.searchPath, no paths are sent.
 No commands or arbitrary URLs are sent. Preview/action still accept narrow IDs only.
 Server must authenticate every route, enforce loopback/Host/Origin, validate IDs,
 bind single-use expiring previews to the session + target + exact change, revalidate
 targets and reject replay/stale previews. Every success has a JSON object body,
 not HTTP 204. Current server: status returns {state}; progress/checked are optional.
 Every non-2xx response is {error:<stable code>,warnings:[{en,de}]} (exact keys).
 Error JSON is capped at 256 KiB UTF-8; codes are 1..128 lowercase ASCII letters/
 digits/underscores, accepted only from the errorMessages map below; warnings are
 <=16 bilingual nonblank entries, <=2048 code units per language. Validated warning
 text is displayed via textContent with token redaction, NEVER added to logs.
 401 authentication_required is distinct from 403 administrator_required/access_denied
 and boundary rejections. 409 may mean stale preview, ineligible target, ambiguous
 options, busy scan or manual recovery: never infer expiry solely from HTTP status.
 422 verification_failed_rolled_back means the previous environment value AND type
 were restored/read back; probe_failed_no_change means no write occurred. 500
 rollback_failed_manual_recovery_required, update_manual_recovery_required and 409
 manual_recovery_required_close_session latch a visible manual-recovery lock for this
 page lifetime, including across polling success/network errors. Malformed warnings on
 recognized recovery errors are discarded without hiding that lock. Other malformed/
 unknown error bodies discard all server text; fallback is auth for 401, access denied
 for 403, otherwise generic failure. Runtime update (update-runtime) and restore from the
 session backup ZIP (restore-backup) follow the same preview/confirm/apply contract.
 Request errors remain visible through successful background polls until another
 explicit request; poll errors clear on a validated refresh.
 No backend diagnostic text is logged. JSON export retains all documented JVM
 evidence and advisory metadata, lastSuccessfulRefresh (ISO timestamp|null) and
 assessmentComplete (false for active/cancelled/failed scans or stale snapshots),
 and recoveryRequired (a sticky client-side safety lock, not proof of recovery).
 Activity export contains fixed translated events only.
 Wizard: five steps (scan, runtime, action, confirm, report). Steps are purely a
 presentation layer over the same requests; a step is reachable only when its
 prerequisite (results, selection, preview) exists, and the displayed step falls back
 whenever that prerequisite disappears (new scan, changed evidence, expired preview).
-->
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<meta name="color-scheme" content="light dark">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'none'; base-uri 'none'; form-action 'none'">
<title>ELO Patch Tools</title>
<style>
:root{--bg:#f3f5fa;--surface:#fff;--surface-2:#f7f9fd;--text:#18202f;--muted:#586377;--line:#dde3ee;--accent:#2457e6;--accent-ink:#fff;--accent-soft:#e8eefd;--ok:#12733a;--ok-soft:#e3f5ea;--warn:#975a00;--warn-soft:#fdf1da;--bad:#b3261e;--bad-soft:#fde8e6;--shadow:0 1px 2px rgba(20,30,60,.06),0 8px 24px rgba(20,30,60,.06);--radius:14px}
@media (prefers-color-scheme:dark){:root{--bg:#0d1220;--surface:#151c2e;--surface-2:#1a2336;--text:#e7ecf6;--muted:#9aa6bd;--line:#26314a;--accent:#6d93ff;--accent-ink:#0b1226;--accent-soft:#1d2b52;--ok:#5fd18a;--ok-soft:#12301f;--warn:#f0b24a;--warn-soft:#38290e;--bad:#ff8a80;--bad-soft:#3b1815;--shadow:none}}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--text);font:16px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:980px;margin:0 auto;padding:0 16px 48px}
svg.i{width:1.25em;height:1.25em;flex:none;fill:none;stroke:currentColor;stroke-width:1.75;stroke-linecap:round;stroke-linejoin:round;vertical-align:-.2em}
header.top{display:flex;align-items:center;gap:12px;padding:20px 0 8px}
header.top .logo{display:grid;place-items:center;width:40px;height:40px;border-radius:12px;background:var(--accent);color:var(--accent-ink)}
header.top .logo svg{width:22px;height:22px}
h1{font-size:1.25rem;line-height:1.2;margin:0;letter-spacing:-.01em}
.sub{margin:0;color:var(--muted);font-size:.875rem}
.lang{margin-left:auto;display:flex;align-items:center;gap:6px;color:var(--muted);font-size:.875rem}
select{font:inherit;color:var(--text);background:var(--surface);border:1px solid var(--line);border-radius:10px;padding:.4rem .6rem}
.stepper{list-style:none;display:grid;grid-template-columns:repeat(5,1fr);gap:8px;margin:12px 0 18px;padding:0;counter-reset:s}
.stepper li{min-width:0}
.step{width:100%;display:flex;flex-direction:column;align-items:center;gap:6px;padding:10px 4px;border:0;background:transparent;color:var(--muted);font:inherit;font-size:.8125rem;cursor:pointer;border-radius:12px;position:relative}
.step .dot{display:grid;place-items:center;width:38px;height:38px;border-radius:50%;background:var(--surface);border:1.5px solid var(--line);color:var(--muted);transition:background .15s,border-color .15s,color .15s}
.step[data-state=current] .dot{background:var(--accent);border-color:var(--accent);color:var(--accent-ink)}
.step[data-state=current]{color:var(--text);font-weight:600}
.step[data-state=done] .dot{background:var(--ok-soft);border-color:var(--ok);color:var(--ok)}
.step:disabled{cursor:not-allowed;opacity:.55}
.step:focus-visible,.btn:focus-visible,.rt:focus-visible,.card:focus-visible,summary:focus-visible,select:focus-visible,input:focus-visible{outline:3px solid var(--accent);outline-offset:2px}
.step .lbl{white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:100%}
@media (max-width:560px){.step .lbl{display:none}.step[data-state=current] .lbl{display:block}}
.panel{background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);padding:20px;margin:0 0 16px;box-shadow:var(--shadow)}
.panel[hidden]{display:none}
.panel h2{display:flex;align-items:center;gap:10px;font-size:1.125rem;margin:0 0 4px;letter-spacing:-.01em}
.panel h2 .ico{display:grid;place-items:center;width:32px;height:32px;border-radius:10px;background:var(--accent-soft);color:var(--accent)}
.lead{margin:.25rem 0 1rem;color:var(--muted)}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;font:inherit;font-weight:600;padding:.6rem 1rem;border-radius:11px;border:1px solid var(--line);background:var(--surface);color:var(--text);cursor:pointer;transition:background .12s,border-color .12s,transform .05s}
.btn:hover:not(:disabled){background:var(--surface-2);border-color:var(--muted)}
.btn:active:not(:disabled){transform:translateY(1px)}
.btn.primary{background:var(--accent);border-color:var(--accent);color:var(--accent-ink)}
.btn.primary:hover:not(:disabled){filter:brightness(1.08);background:var(--accent)}
.btn.ghost{background:transparent}
.btn:disabled{opacity:.5;cursor:not-allowed}
.btn[hidden],[hidden]{display:none!important}
.row{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin-top:14px}
.row.between{justify-content:space-between}
.banner{margin:0 0 14px;padding:12px 14px;border-radius:12px;border:1px solid var(--line);background:var(--surface);white-space:pre-wrap;overflow-wrap:anywhere;font:inherit;font-size:.9375rem}
.banner:empty{display:none}
#error{border-color:var(--bad);background:var(--bad-soft);color:var(--bad)}
#recoveryNotice{border-color:var(--bad);background:var(--bad-soft);color:var(--bad);font-weight:600}
.busy{display:flex;align-items:center;gap:10px;margin:0 0 14px;padding:12px 14px;border-radius:12px;background:var(--accent-soft);color:var(--text);border:1px solid var(--line)}
.status-line{display:flex;align-items:center;gap:10px;min-height:2rem;margin:.25rem 0}
.spin{width:18px;height:18px;border-radius:50%;border:2.5px solid var(--line);border-top-color:var(--accent);animation:spin .8s linear infinite}
.spin[hidden]{display:none}
@keyframes spin{to{transform:rotate(360deg)}}
@media (prefers-reduced-motion:reduce){.spin{animation:none;border-top-color:var(--accent);border-right-color:var(--accent)}.step .dot{transition:none}}
progress{width:100%;height:8px;border-radius:6px;overflow:hidden;appearance:none;-webkit-appearance:none;border:0;background:var(--line);margin:.25rem 0}
progress::-webkit-progress-bar{background:var(--line)}
progress::-webkit-progress-value{background:var(--accent)}
progress::-moz-progress-bar{background:var(--accent)}
progress:indeterminate{background:linear-gradient(90deg,var(--line) 0,var(--accent) 50%,var(--line) 100%);background-size:200% 100%;animation:slide 1.2s linear infinite}
@keyframes slide{to{background-position:-200% 0}}
.muted{color:var(--muted);font-size:.875rem}
details{border:1px solid var(--line);border-radius:12px;background:var(--surface-2);margin:12px 0}
details>summary{cursor:pointer;padding:10px 14px;font-weight:600;display:flex;align-items:center;gap:8px;list-style:none}
details>summary::-webkit-details-marker{display:none}
details>summary::after{content:"";margin-left:auto;width:8px;height:8px;border-right:2px solid var(--muted);border-bottom:2px solid var(--muted);transform:rotate(45deg);transition:transform .15s}
details[open]>summary::after{transform:rotate(-135deg)}
details>.body{padding:0 14px 14px}
label.field{display:block;font-weight:600;margin:.5rem 0}
input[type=text]{display:block;width:100%;font:inherit;color:var(--text);background:var(--surface);border:1px solid var(--line);border-radius:10px;padding:.55rem .7rem;margin-top:.35rem}
.cards{display:grid;gap:10px;grid-template-columns:repeat(auto-fill,minmax(260px,1fr))}
.rt,.card{text-align:left;font:inherit;color:var(--text);background:var(--surface);border:1.5px solid var(--line);border-radius:13px;padding:14px;cursor:pointer;display:flex;flex-direction:column;gap:6px;transition:border-color .12s,background .12s,box-shadow .12s}
.rt:hover:not(:disabled),.card:hover:not(:disabled){border-color:var(--muted)}
.rt[aria-checked=true]{border-color:var(--accent);background:var(--accent-soft);box-shadow:0 0 0 1px var(--accent) inset}
.rt .t{font-weight:700;display:flex;align-items:center;gap:8px}
.rt .p{font-size:.8125rem;color:var(--muted);overflow-wrap:anywhere}
.badge{display:inline-flex;align-items:center;gap:6px;align-self:flex-start;font-size:.75rem;font-weight:700;padding:.15rem .55rem;border-radius:999px;background:var(--surface-2);border:1px solid var(--line);color:var(--muted)}
.badge::before{content:"";width:8px;height:8px;border-radius:50%;background:currentColor}
.badge[data-status=vulnerable]{color:var(--bad);background:var(--bad-soft);border-color:transparent}
.badge[data-status=patched],.badge[data-status=not-affected],.badge[data-status=safe],.badge[data-status=mitigated]{color:var(--ok);background:var(--ok-soft);border-color:transparent}
.badge[data-status=inconclusive],.badge[data-status=unsupported]{color:var(--warn);background:var(--warn-soft);border-color:transparent}
.card{flex-direction:row;align-items:flex-start;gap:14px}
.card .ico{display:grid;place-items:center;flex:none;width:44px;height:44px;border-radius:12px;background:var(--accent-soft);color:var(--accent)}
.card .ico svg{width:24px;height:24px}
.card .tt{font-weight:700;display:block}
.card .dd{display:block;color:var(--muted);font-size:.875rem;font-weight:400}
.card:disabled{opacity:.5;cursor:not-allowed}
.card.rec{border-color:var(--accent)}
.preview{white-space:pre-wrap;overflow-wrap:anywhere;font:inherit;font-size:.9375rem;background:var(--surface-2);border:1px solid var(--line);border-radius:12px;padding:14px;margin:8px 0}
.confirm{display:flex;gap:10px;align-items:flex-start;margin:14px 0;padding:12px 14px;border:1px solid var(--line);border-radius:12px;background:var(--surface-2)}
.confirm input{margin-top:.25rem;width:18px;height:18px;flex:none}
.done{display:flex;gap:12px;align-items:flex-start;padding:14px;border-radius:12px;background:var(--ok-soft);color:var(--ok);margin-bottom:12px;font-weight:600}
.done:empty,.done[hidden]{display:none}
.table-wrap{overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:.8125rem}
th,td{padding:.45rem .55rem;border:1px solid var(--line);text-align:left;vertical-align:top;white-space:pre-wrap;overflow-wrap:anywhere}
th{background:var(--surface-2)}
pre{white-space:pre-wrap;overflow-wrap:anywhere;font:inherit;font-size:.8125rem;margin:8px 0}
a{color:var(--accent)}
ol.manual{padding-left:1.25rem;margin:.5rem 0}
ol.manual li{margin:.35rem 0}
.sec{margin-top:8px}
.backups{border:1.5px solid var(--accent);border-radius:13px;background:var(--accent-soft);padding:14px;margin:0 0 16px}
.backups h3{display:flex;align-items:center;gap:8px;margin:0 0 4px;font-size:1rem}
.backups .rt{background:var(--surface)}
.badge.act{color:var(--accent);background:var(--accent-soft)}
.backups{padding:0}
.backups>summary{padding:12px 14px;font-weight:700}
.backups>.body{padding:0 14px 14px}
.alert{border:2px solid var(--bad);background:var(--bad-soft);border-radius:13px;padding:14px;margin:10px 0 14px}
.alert h3{display:flex;align-items:center;gap:8px;margin:0 0 6px;color:var(--bad);font-size:1.05rem}
.alert p{margin:.35rem 0}
.alert .fix{font-weight:600}
.alert .vuln+.vuln{border-top:1px solid var(--bad);margin-top:10px;padding-top:10px}
.sev{display:inline-block;font-size:.6875rem;font-weight:800;letter-spacing:.04em;text-transform:uppercase;padding:.1rem .45rem;border-radius:6px;color:#fff;background:var(--bad)}
.sev[data-sev=medium]{background:#c2410c}
.sev[data-sev=low]{background:#a16207}
.rt[data-status=vulnerable]{border-color:var(--bad)}
.cmdbox{margin:16px 0 8px}
.cmdbox h3{display:flex;align-items:center;gap:8px;font-size:1rem;margin:0 0 6px}
pre.cmd{background:#0f172a;color:#e2e8f0;border:1px solid #1e293b;border-radius:12px;padding:14px;font-family:Consolas,"Cascadia Mono",monospace;font-size:.8125rem;overflow-x:auto;white-space:pre-wrap;overflow-wrap:anywhere}
pre.cmd>span{display:block;min-height:1.2em}
pre.cmd .c-note{color:#86efac}
pre.cmd .c-flag{color:#fbbf24}
pre.cmd .c-var{color:#7dd3fc}
pre.cmd .c-str{color:#fca5a5}
</style>
</head>
<body>
<svg width="0" height="0" style="position:absolute" aria-hidden="true" focusable="false">
<symbol id="i-search" viewBox="0 0 24 24"><circle cx="11" cy="11" r="7"/><path d="M20 20l-3.5-3.5"/></symbol>
<symbol id="i-cpu" viewBox="0 0 24 24"><rect x="6" y="6" width="12" height="12" rx="2"/><path d="M9 2v4M15 2v4M9 18v4M15 18v4M2 9h4M2 15h4M18 9h4M18 15h4"/></symbol>
<symbol id="i-update" viewBox="0 0 24 24"><path d="M20 11a8 8 0 1 0-2.3 5.7"/><path d="M20 4v7h-7"/></symbol>
<symbol id="i-shield" viewBox="0 0 24 24"><path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/><path d="M9 12l2 2 4-4"/></symbol>
<symbol id="i-file" viewBox="0 0 24 24"><path d="M7 3h7l5 5v13H7z"/><path d="M14 3v5h5M10 13h6M10 17h6"/></symbol>
<symbol id="i-book" viewBox="0 0 24 24"><path d="M5 4h10a3 3 0 0 1 3 3v13H8a3 3 0 0 1-3-3z"/><path d="M5 17a3 3 0 0 1 3-3h10"/></symbol>
<symbol id="i-check" viewBox="0 0 24 24"><path d="M5 12l4.5 4.5L19 7"/></symbol>
<symbol id="i-play" viewBox="0 0 24 24"><path d="M8 5l11 7-11 7z"/></symbol>
<symbol id="i-stop" viewBox="0 0 24 24"><rect x="6" y="6" width="12" height="12" rx="2"/></symbol>
<symbol id="i-next" viewBox="0 0 24 24"><path d="M5 12h14M13 6l6 6-6 6"/></symbol>
<symbol id="i-back" viewBox="0 0 24 24"><path d="M19 12H5M11 6l-6 6 6 6"/></symbol>
<symbol id="i-download" viewBox="0 0 24 24"><path d="M12 4v11M7 11l5 5 5-5M5 20h14"/></symbol>
<symbol id="i-undo" viewBox="0 0 24 24"><path d="M9 14L4 9l5-5"/><path d="M4 9h10a6 6 0 0 1 0 12h-3"/></symbol>
<symbol id="i-globe" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18"/></symbol>
<symbol id="i-info" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8v.01"/></symbol>
<symbol id="i-list" viewBox="0 0 24 24"><path d="M8 6h12M8 12h12M8 18h12M4 6v.01M4 12v.01M4 18v.01"/></symbol>
</svg>
<div class="wrap">
<header class="top">
<div class="logo"><svg class="i"><use href="#i-cpu"/></svg></div>
<div><h1>ELO Patch Tools</h1><p class="sub" data-i18n="tagline"></p></div>
<label class="lang"><svg class="i"><use href="#i-globe"/></svg><span data-i18n="language"></span> <select id="language"><option value="en">English</option><option value="de">Deutsch</option></select></label>
</header>
<nav aria-label="Steps"><ol class="stepper" id="stepper">
<li><button class="step" id="nav1" type="button" data-state="current"><span class="dot"><svg class="i"><use href="#i-search"/></svg></span><span class="lbl" data-i18n="step1"></span></button></li>
<li><button class="step" id="nav2" type="button" data-state="todo" disabled><span class="dot"><svg class="i"><use href="#i-cpu"/></svg></span><span class="lbl" data-i18n="step2"></span></button></li>
<li><button class="step" id="nav3" type="button" data-state="todo" disabled><span class="dot"><svg class="i"><use href="#i-update"/></svg></span><span class="lbl" data-i18n="step3"></span></button></li>
<li><button class="step" id="nav4" type="button" data-state="todo" disabled><span class="dot"><svg class="i"><use href="#i-shield"/></svg></span><span class="lbl" data-i18n="step4"></span></button></li>
<li><button class="step" id="nav5" type="button" data-state="todo" disabled><span class="dot"><svg class="i"><use href="#i-file"/></svg></span><span class="lbl" data-i18n="step5"></span></button></li>
</ol></nav>
<div id="busy" class="busy" role="status" aria-live="polite" hidden><span class="spin"></span><span data-i18n="working"></span></div>
<pre id="error" class="banner" role="alert"></pre>
<pre id="recoveryNotice" class="banner" role="alert"></pre>

<section class="panel" id="step1" aria-labelledby="h1s">
<h2 id="h1s"><span class="ico"><svg class="i"><use href="#i-search"/></svg></span><span data-i18n="step1Title"></span></h2>
<details id="backupsBox" class="backups" hidden><summary><svg class="i"><use href="#i-undo"/></svg><span id="backupsSummary"></span></summary><div class="body"><p class="muted" data-i18n="backupsText"></p><div class="cards" id="backups"></div></div></details>
<p class="lead" data-i18n="step1Text"></p>
<div class="status-line"><span class="spin" id="spinner" hidden></span><span id="status" role="status" aria-live="polite"></span></div>
<progress id="progress" max="100" aria-label="Progress" hidden></progress><p id="progressText" class="muted"></p>
<p id="scanSummary" class="muted" role="status"></p>
<p id="resultNotice" class="muted" role="status"></p>
<details><summary><svg class="i"><use href="#i-list"/></svg><span data-i18n="advanced"></span></summary><div class="body">
<label class="field"><span data-i18n="searchPath"></span><input id="searchPath" type="text" maxlength="1024" autocomplete="off" spellcheck="false" aria-describedby="searchHelp"></label>
<p id="searchHelp" class="muted" data-i18n="searchHelp"></p>
</div></details>
<div class="row">
<button id="scan" class="btn primary" type="button"><svg class="i"><use href="#i-play"/></svg><span data-i18n="scan"></span></button>
<button id="cancel" class="btn" type="button" disabled><svg class="i"><use href="#i-stop"/></svg><span data-i18n="cancel"></span></button>
<button id="toStep2" class="btn ghost" type="button" hidden><span data-i18n="continue"></span><svg class="i"><use href="#i-next"/></svg></button>
</div>
</section>

<section class="panel" id="step2" aria-labelledby="h2s" hidden>
<h2 id="h2s"><span class="ico"><svg class="i"><use href="#i-cpu"/></svg></span><span data-i18n="step2Title"></span></h2>
<p class="lead" data-i18n="step2Text"></p>
<div id="vulnAlert" class="alert" role="alert" hidden><div id="vulnList"></div></div>
<div class="cards" id="cards" role="radiogroup" aria-labelledby="h2s"></div>
<label class="field" hidden><span data-i18n="results"></span><select id="results"></select></label>
<details><summary><svg class="i"><use href="#i-info"/></svg><span data-i18n="evidence"></span></summary><div class="body">
<pre id="details"></pre>
<div class="table-wrap"><table><caption data-i18n="jvmTable"></caption><thead><tr><th scope="col" data-i18n="path"></th><th scope="col" data-i18n="runtimeRoot"></th><th scope="col" data-i18n="version"></th><th scope="col" data-i18n="vendor"></th><th scope="col" data-i18n="architecture"></th><th scope="col" data-i18n="classification"></th><th scope="col" data-i18n="eloRationale"></th><th scope="col" data-i18n="classificationEvidence"></th></tr></thead><tbody id="jvmRows"></tbody></table></div>
</div></details>
<div class="row between">
<button id="back2" class="btn ghost" type="button"><svg class="i"><use href="#i-back"/></svg><span data-i18n="back"></span></button>
<button id="toStep3" class="btn primary" type="button" disabled><span data-i18n="continue"></span><svg class="i"><use href="#i-next"/></svg></button>
</div>
</section>

<section class="panel" id="step3" aria-labelledby="h3s" hidden>
<h2 id="h3s"><span class="ico"><svg class="i"><use href="#i-update"/></svg></span><span data-i18n="step3Title"></span></h2>
<p class="lead" data-i18n="warning"></p>
<div id="vulnRec" class="alert" role="alert" hidden><div id="vulnRecList"></div></div>
<div class="cards">
<button id="update" class="card rec" type="button" disabled><span class="ico"><svg class="i"><use href="#i-update"/></svg></span><span><span class="tt" data-i18n="update"></span><span class="dd" data-i18n="updateDesc"></span></span></button>
<button id="mitigate" class="card" type="button" disabled><span class="ico"><svg class="i"><use href="#i-shield"/></svg></span><span><span class="tt" data-i18n="mitigate"></span><span class="dd" data-i18n="mitigateDesc"></span></span></button>
</div>
<details><summary><svg class="i"><use href="#i-book"/></svg><span data-i18n="manualHeading"></span></summary><div class="body"><p class="muted" data-i18n="manualIntro"></p><ol id="manual" class="manual"></ol><h3 data-i18n="manualCommandsTitle"></h3><pre id="manualCommands" data-i18n="manualCommands" hidden></pre><pre id="cmdView" class="cmd" aria-label="PowerShell"></pre></div></details>
<div class="cmdbox"><h3><svg class="i"><use href="#i-play"/></svg><span data-i18n="terminalTitle"></span></h3><pre id="terminalCmds" class="cmd" aria-label="PowerShell"></pre></div>
<div class="row"><button id="back3" class="btn ghost" type="button"><svg class="i"><use href="#i-back"/></svg><span data-i18n="back"></span></button></div>
</section>

<section class="panel" id="step4" aria-labelledby="h4s" hidden>
<h2 id="h4s"><span class="ico"><svg class="i"><use href="#i-shield"/></svg></span><span data-i18n="step4Title"></span></h2>
<p class="muted"><span data-i18n="previewKind"></span>: <strong id="previewKind"></strong></p>
<pre id="preview" class="preview"></pre>
<label class="confirm"><input id="confirm" type="checkbox" disabled><span id="confirmation"></span></label>
<div class="row between">
<button id="back4" class="btn ghost" type="button"><svg class="i"><use href="#i-back"/></svg><span data-i18n="back"></span></button>
<button id="apply" class="btn primary" type="button" disabled><svg class="i"><use href="#i-check"/></svg><span data-i18n="apply"></span></button>
</div>
</section>

<section class="panel" id="step5" aria-labelledby="h5s" hidden>
<h2 id="h5s"><span class="ico"><svg class="i"><use href="#i-file"/></svg></span><span data-i18n="step5Title"></span></h2>
<p id="finalNotice" class="done" role="status"></p>
<p class="lead" data-i18n="reportText"></p>
<div class="row">
<button id="exportTechnical" class="btn primary" type="button"><svg class="i"><use href="#i-download"/></svg><span data-i18n="technicalReport"></span></button>
<button id="exportJson" class="btn" type="button"><svg class="i"><use href="#i-download"/></svg><span data-i18n="exportJson"></span></button>
<button id="exportLog" class="btn" type="button"><svg class="i"><use href="#i-download"/></svg><span data-i18n="exportLog"></span></button>
</div>
<div class="row">
<button id="restore" class="btn" type="button" hidden><svg class="i"><use href="#i-undo"/></svg><span data-i18n="restore"></span></button>
<button id="startOver" class="btn ghost" type="button"><svg class="i"><use href="#i-search"/></svg><span data-i18n="startOver"></span></button>
</div>
<p id="restoreHint" class="muted" hidden data-i18n="restoreHint"></p>
<details><summary><svg class="i"><use href="#i-list"/></svg><span data-i18n="exportHeading"></span></summary><div class="body"><pre id="activity" aria-live="polite"></pre></div></details>
</section>

<details class="sec"><summary><svg class="i"><use href="#i-info"/></svg><span data-i18n="securityHeading"></span></summary><div class="body">
<p class="muted" data-i18n="securityHelp"></p><p id="verifiedOn"></p><ul id="advisories"></ul></div></details>
</div>
<script>
'use strict';
(() => {
const messages = {
 en: {
 working:'Working… preparing or applying the change can take a minute (verified download, tests, backup). Please keep this page open.',language:'Language',tagline:'Java runtime check, update and recovery for ELO servers',intro:'Local, read-only discovery. No change is made by scanning or previewing. Keep this session open while work is running.',
 step1:'Scan',step2:'Runtime',step3:'Action',step4:'Confirm',step5:'Report',
 step1Title:'Find Java runtimes',step1Text:'A read-only scan looks for Java in X:\\java\\bin and X:\\<folder>\\java\\bin (for example ELO\\java\\bin) on every drive (C: to Z:). Nothing is changed.',
 step2Title:'Choose a runtime',step2Text:'Select the Java runtime you want to work on.',step3Title:'Choose an action',step4Title:'Review and confirm',step5Title:'Report and next steps',
 continue:'Continue',back:'Back',startOver:'Scan again',advanced:'Advanced: search another folder',evidence:'Technical evidence',
 scanningNow:'Scanning drives',foundN:'Java runtimes found: {n}.',foundNone:'No Java runtime found. Open “Advanced” to search another folder, then scan again.',
 updateDesc:'Installs the newest release of the same Java branch and vendor. Includes a verified backup, a Java self-test and automatic rollback.',
 mitigateDesc:'Adds -XX:-UseBASE64Intrinsics to the machine environment. Quick and temporary; it is not a Java update.',
 doneUpdate:'The runtime was updated and verified. The backup ZIP and the previous runtime were kept. Scan again to confirm the new version.',
 doneMitigation:'The mitigation was applied and verified for newly started JVMs. Running processes stay unprotected until they are restarted.',
 doneRestore:'The previous runtime was restored from the backup ZIP and verified.',
 restore:'Restore previous version',restoreHint:'Reverts this session’s update from the verified backup ZIP; the updated runtime is kept next to it.',
 restoreBackup:'Restore from backup',confirmRestore:'I reviewed the restore preview and authorize replacing the current runtime with the backup.',
 reportText:'Download the technical report for your team. It lists detected JVMs, actions, backup and restore commands.',
 updateNotNeeded:'This runtime is already the newest release of its branch. Nothing to update.',noBackup:'No backup made in this session exists for this runtime.',restoreFailed:'The restore was rejected before the runtime was swapped. The current runtime is unchanged.',
 technicalReport:'Download technical HTML report',scanHeading:'Discovery',scan:'Start read-only scan',cancel:'Cancel scan',results:'Select JVM for preview',none:'No JVMs found',
 actionHeading:'Separate, optional changes',warning:'Pick one change. Updating may affect compatibility and vendor support; the temporary mitigation is not a runtime update. Nothing is applied before you confirm.',
 mitigate:'Temporary mitigation',update:'Update Java runtime',preview:'Change preview',apply:'Apply confirmed change',
 confirmMitigation:'I reviewed the mitigation preview, backup and rollback plan and authorize this change.',confirmUpdate:'I reviewed the update preview, compatibility risks, backup and rollback plan and authorize this runtime update.',
 noPreview:'Select a JVM and preview one change. A new scan, search root, selection or preview clears confirmation.',
 manualHeading:'Manual patch instructions',manualIntro:'These instructions do not execute commands or change the system. Follow ELO and runtime vendor guidance for your exact installation.',
 manual:['Identify the affected ELO service and its actual Java runtime from the scan. Verify the version against vendor advisories; a potential finding is not proof of exploitability.',
 'Plan a maintenance window. Record existing JVM options and environment settings. Back up the service configuration and runtime; verify a rollback procedure before changing anything.',
 'Temporary mitigation: in the affected service’s supported JVM configuration, add -XX:-UseBASE64Intrinsics without replacing existing options or global environment values. Confirm that the runtime supports this flag. This is not a permanent fix.',
 'Separate runtime update: obtain a vendor-approved, compatible patched runtime from a trusted vendor source. Verify integrity, architecture and ELO support. Do not replace a running runtime or use an arbitrary download.',
 'Stop only the affected service during the approved window, apply the chosen change using the vendor procedure, then restart. Check service health and effective JVM options/version. If checks fail, stop and restore the saved configuration/runtime.',
 'Rescan and document the outcome. Keep the backup until validated. Contact ELO support if paths, service ownership or compatibility are uncertain.'],
 manualCommandsTitle:'PowerShell commands (administrator)',manualCommands:'# Run in an ADMINISTRATOR PowerShell. Adjust the paths and service names to your scan result.\n\n# 1) Find the runtime, its version and the services that use it\n& \'C:\\ELO\\java\\bin\\java.exe\' -version\nGet-Content \'C:\\ELO\\java\\release\' | Select-String \'IMPLEMENTOR|JAVA_RUNTIME_VERSION|OS_ARCH\'\nGet-CimInstance Win32_Service | Where-Object { $_.PathName -match \'ELO\' } | Select-Object Name, State, PathName\n[Environment]::GetEnvironmentVariable(\'JAVA_TOOL_OPTIONS\', \'Machine\')\n\n# 2) Back up the runtime (ZIP) before changing anything\nCompress-Archive -LiteralPath \'C:\\ELO\\java\' -DestinationPath \'C:\\ELO\\java-backup.zip\'\n\n# 3) Temporary mitigation (machine-wide): KEEP the old value and append, never overwrite\n$old = [Environment]::GetEnvironmentVariable(\'JAVA_TOOL_OPTIONS\', \'Machine\'); $old\n[Environment]::SetEnvironmentVariable(\'JAVA_TOOL_OPTIONS\', (($old + \' -XX:-UseBASE64Intrinsics\').Trim()), \'Machine\')\n# Undo: [Environment]::SetEnvironmentVariable(\'JAVA_TOOL_OPTIONS\', $old, \'Machine\')   (use $null if it was empty)\n# Services only see the change after they are restarted.\n\n# 4) Update the runtime by hand (download the newest release of the SAME vendor and branch first)\n(Get-FileHash \'C:\\Downloads\\new-java.zip\' -Algorithm SHA256).Hash        # compare with the vendor\'s published SHA256\nStop-Service \'ELO-SRV01-1\' -Force                                        # every service that uses this Java\nRename-Item \'C:\\ELO\\java\' \'java.old\'\nExpand-Archive -LiteralPath \'C:\\Downloads\\new-java.zip\' -DestinationPath \'C:\\ELO\\java-new\'\nMove-Item (Get-ChildItem \'C:\\ELO\\java-new\' -Directory | Select-Object -First 1).FullName \'C:\\ELO\\java\'\n& \'C:\\ELO\\java\\bin\\java.exe\' -version\nStart-Service \'ELO-SRV01-1\'\n\n# 5) If something fails: stop the services, put the old runtime back, start the services\nStop-Service \'ELO-SRV01-1\' -Force\nRename-Item \'C:\\ELO\\java\' \'java.failed\'; Rename-Item \'C:\\ELO\\java.old\' \'java\'\nStart-Service \'ELO-SRV01-1\'\n# Or restore from the ZIP: Expand-Archive \'C:\\ELO\\java-backup.zip\' -DestinationPath \'C:\\ELO\\restore\'; then move the java folder back',
 backupsTitle:'Existing backups',backupsText:'Backups made by this tool were found on this server. Pick one to bring that Java version back; the runtime that is installed now is kept next to it.',severity_high:'High',severity_medium:'Medium',severity_low:'Low',vulnTitle:'Vulnerability found: CVE-2026-114938 (Java4Shell)',vulnText:'{n} runtime(s) are before the fixed release: {list}. The JIT BASE64 intrinsics flaw lets this Java produce wrong results; the vendor fixed it in a newer release.',vulnFixLabel:'Solution:',vulnFix:'update Java to the current release of the same branch (step 3, Update Java runtime). The temporary mitigation only reduces the risk until you update.',terminalTitle:'Run it from the terminal (administrator PowerShell)',terminalCmdsText:'# Update Java to the current release (recommended)\n.\ELO-Patch-Tools.bat --cli --update-runtime --target {n} --confirm-admin --confirm-update\n\n# Temporary mitigation only (adds -XX:-UseBASE64Intrinsics; restart the ELO services afterwards)\n.\ELO-Patch-Tools.bat --cli --mitigate --target {n} --confirm-admin --confirm-mitigation\n\n# Check the result (--target is the position in the scan list, starting at 0)\n.\ELO-Patch-Tools.bat --cli --scan',backupsVuln:'contains a vulnerable Java',
restoreShort:'Restore this backup',backupRisk_vulnerable:'Vulnerable: this version is before the vendor fix for a catalog vulnerability',backupRisk_patched:'Listed as fixed for every catalog vulnerability',backupRisk_unknown:'Security status unknown: treat as potentially vulnerable',backupStop:'Restoring stops the ELO Tomcat services that use this Java (ELO is unavailable meanwhile) and starts them again afterwards.',
 exportHeading:'Activity log',exportJson:'Export JSON results',exportLog:'Export activity log',
 idle:'Ready',scanning:'Scanning',cancelling:'Cancellation requested; waiting for the scanner',completed:'Scan completed',cancelled:'Scan cancelled; results may be incomplete',error:'Operation failed',unknown:'Unknown',
 vulnerable:'Potentially vulnerable',safe:'No vulnerability detected by current rules',mitigated:'Mitigation detected',unsupported:'Unsupported runtime',
 progress:'Progress',indeterminate:'Progress unavailable',path:'Installation path',version:'Runtime version',classification:'Assessment',
 auth:'Missing or rejected session token. Reopen the local session link.',network:'Cannot reach the local service. Check that the BAT is still running.',
 invalid:'The local service returned an invalid response.',failed:'The request failed. Check the local service and retry.',expired:'The preview expired or no longer matches the target. Request a fresh preview.',
 accessDenied:'Access denied. Check elevation and filesystem/registry permissions without bypassing access controls. No protection is claimed.',
 adminNeeded:'Mitigation requires an elevated administrator session. Read-only scanning does not require elevation. This is not a session-token error.',
 boundaryRejected:'The local service rejected the request boundary. Reopen the original local session link; do not bypass origin or host checks.',
 updateRefused:'The runtime update cannot be offered for this JVM. Nothing was downloaded or changed.',updateRejected:'The update was rejected before the runtime was replaced. The original runtime is unchanged.',updateRolledBack:'The new runtime failed validation. The original runtime was restored and verified; the failed runtime and the backup ZIP were kept.',updateManualRecovery:'Automatic restore failed. Manual recovery from the backup ZIP is required (see the technical report).',
 rollbackFailed:'Rollback failed — manual recovery is required.',manualRecovery:'Manual recovery is required before any further change.',
 recoveryGuidance:'CRITICAL: JAVA_TOOL_OPTIONS may still be changed. Further requests that could change state are locked in this page. Restore the exact previous value AND registry type saved from the preview using an approved Registry Editor procedure, with your administrator. Verify manually before closing this session and starting another. Opening a new session alone does not restore the environment. Existing JVM protection is not claimed.',
 rolledBack:'Verification failed. The exact previous environment value and registry type were restored and read back. No protection is claimed.',
 probeFailed:'JVM-option verification failed before any change. No protection is claimed.',
 updateUnavailable:'Automatic runtime update is unavailable: provenance, ELO compatibility, backup, replacement and rollback have not been verified. Nothing was downloaded or replaced. Use the manual instructions and vendor support.',
 incompleteScan:'The scan is incomplete or exceeds evidence limits. Choose a narrower accessible local directory and review permissions without bypassing access controls.',
 inaccessiblePath:'The selected local directory is missing or inaccessible. Check the directory and permissions.',
 scanBusy:'A scan is already running. Wait for completion or request cancellation.',completedScan:'Complete a successful scan before requesting a change.',
 targetIneligible:'The selected JVM is not eligible for this change. Review the scan evidence.',optionsUnsupported:'Existing JVM/environment settings are ambiguous or unsupported. Review them with your administrator before making changes.',
 scanSent:'Scan requested',cancelSent:'Cancellation requested',previewReady:'Preview received',actionSent:'Confirmed action completed',connected:'Session connected',report:'Report exported',log:'Activity log exported',
 units:'items checked',previewKind:'Selected change',mitigation:'Temporary mitigation',runtimeUpdate:'Runtime update',
 searchPath:'Optional local search directory',searchHelp:'On ready fixed or removable drives C: through Z:, the scan checks X:\\java\\bin\\java.exe, X:\\ELO\\java\\bin\\java.exe and X:\\<folder>\\java\\bin\\java.exe (any first-level folder, e.g. X:\\OtherFolder\\java\\bin) at each drive root. Optionally enter an absolute local directory to search after the root checks, e.g. C:\\ELO data. It is read-only search data, never a command. Network/device paths and wildcards are not accepted.',
 invalidPath:'Enter an absolute local Windows directory of at most 1024 characters, without controls, wildcards or relative segments.',
 jvmTable:'Discovered JVMs and evidence',runtimeRoot:'Runtime root',vendor:'Vendor',architecture:'Architecture',eloRationale:'ELO association rationale',classificationEvidence:'Classification evidence',
 patched:'Patched', 'not-affected':'Not affected',inconclusive:'Inconclusive',
 securityHeading:'Security information',securityHelp:'Official advisory links and verification date are supplied and verified by the backend maintainer. This UI checks their format and official host, not their live content or applicability. Links open only on request; no remote assets are loaded. Review evidence and vendor support before acting.',
 resultNotice:'Results may be incomplete or stale during a scan, after cancellation or after an error. They are not a fresh, complete assessment.',
 verifiedDate:'Source verification date (UTC)',noAdvisories:'No verified advisory information supplied. Do not infer that this runtime is safe.'
 },
 de: {
 working:'In Arbeit … Vorbereitung oder Anwendung der Änderung kann eine Minute dauern (geprüfter Download, Tests, Backup). Bitte lassen Sie diese Seite geöffnet.',language:'Sprache',tagline:'Java-Runtime prüfen, aktualisieren und wiederherstellen für ELO-Server',intro:'Lokale, schreibgeschützte Suche. Scan und Vorschau ändern nichts. Lassen Sie diese Sitzung während laufender Vorgänge geöffnet.',
 step1:'Scan',step2:'Runtime',step3:'Aktion',step4:'Bestätigen',step5:'Bericht',
 step1Title:'Java-Runtimes finden',step1Text:'Ein schreibgeschützter Scan sucht Java in X:\\java\\bin und X:\\<Ordner>\\java\\bin (zum Beispiel ELO\\java\\bin) auf allen Laufwerken (C: bis Z:). Es wird nichts geändert.',
 step2Title:'Runtime auswählen',step2Text:'Wählen Sie die Java-Runtime, die Sie bearbeiten möchten.',step3Title:'Aktion wählen',step4Title:'Prüfen und bestätigen',step5Title:'Bericht und nächste Schritte',
 continue:'Weiter',back:'Zurück',startOver:'Erneut scannen',advanced:'Erweitert: anderen Ordner durchsuchen',evidence:'Technische Nachweise',
 scanningNow:'Laufwerke werden durchsucht',foundN:'Gefundene Java-Runtimes: {n}.',foundNone:'Keine Java-Runtime gefunden. Öffnen Sie „Erweitert“, um einen anderen Ordner zu durchsuchen, und scannen Sie erneut.',
 updateDesc:'Installiert die neueste Version desselben Java-Branches und Herstellers. Mit geprüftem Backup, Java-Selbsttest und automatischer Wiederherstellung.',
 mitigateDesc:'Ergänzt -XX:-UseBASE64Intrinsics in der Systemumgebung. Schnell und vorübergehend; kein Java-Update.',
 doneUpdate:'Die Runtime wurde aktualisiert und geprüft. Backup-ZIP und vorherige Runtime blieben erhalten. Scannen Sie erneut, um die neue Version zu bestätigen.',
 doneMitigation:'Die Risikominderung wurde angewendet und für neu gestartete JVMs geprüft. Laufende Prozesse bleiben bis zum Neustart ungeschützt.',
 doneRestore:'Die vorherige Runtime wurde aus dem Backup-ZIP wiederhergestellt und geprüft.',
 restore:'Vorherige Version wiederherstellen',restoreHint:'Macht das Update dieser Sitzung aus dem geprüften Backup-ZIP rückgängig; die aktualisierte Runtime bleibt daneben erhalten.',
 restoreBackup:'Aus Backup wiederherstellen',confirmRestore:'Ich habe die Wiederherstellungsvorschau geprüft und genehmige den Austausch der aktuellen Runtime gegen das Backup.',
 reportText:'Laden Sie den technischen Bericht für Ihr Team herunter. Er listet erkannte JVMs, Aktionen, Backup und Wiederherstellungsbefehle.',
 updateNotNeeded:'Diese Runtime ist bereits die neueste Version ihres Branches. Nichts zu aktualisieren.',noBackup:'Für diese Runtime existiert kein in dieser Sitzung erstelltes Backup.',restoreFailed:'Die Wiederherstellung wurde abgelehnt, bevor die Runtime getauscht wurde. Die aktuelle Runtime ist unverändert.',
 technicalReport:'Technischen HTML-Bericht herunterladen',scanHeading:'Suche',scan:'Schreibgeschützten Scan starten',cancel:'Scan abbrechen',results:'JVM für Vorschau auswählen',none:'Keine JVMs gefunden',
 actionHeading:'Getrennte, optionale Änderungen',warning:'Wählen Sie eine Änderung. Ein Update kann Kompatibilität und Herstellersupport beeinträchtigen; die vorübergehende Risikominderung ist kein Laufzeit-Update. Nichts wird vor Ihrer Bestätigung angewendet.',
 mitigate:'Vorübergehende Risikominderung',update:'Java-Runtime aktualisieren',preview:'Änderungsvorschau',apply:'Bestätigte Änderung anwenden',
 confirmMitigation:'Ich habe die Vorschau zur Risikominderung sowie Sicherung und Wiederherstellung geprüft und genehmige diese Änderung.',confirmUpdate:'Ich habe die Update-Vorschau, Kompatibilitätsrisiken sowie Sicherung und Wiederherstellung geprüft und genehmige dieses Laufzeit-Update.',
 noPreview:'Wählen Sie eine JVM und prüfen Sie eine Änderung. Ein neuer Scan, Suchpfad, eine Auswahl oder eine Vorschau setzt die Bestätigung zurück.',
 manualHeading:'Anleitung für die manuelle Korrektur',manualIntro:'Diese Anleitung führt keine Befehle aus und ändert das System nicht. Beachten Sie die ELO- und Laufzeit-Herstellerhinweise für Ihre konkrete Installation.',
 manual:['Ermitteln Sie den betroffenen ELO-Dienst und seine tatsächliche Java-Laufzeit anhand des Scans. Vergleichen Sie die Version mit Herstellerhinweisen; ein Verdacht ist kein Nachweis der Ausnutzbarkeit.',
 'Planen Sie ein Wartungsfenster. Dokumentieren Sie vorhandene JVM-Optionen und Umgebungswerte. Sichern Sie Dienstkonfiguration und Laufzeit und prüfen Sie vor Änderungen den Wiederherstellungsablauf.',
 'Vorübergehende Risikominderung: Ergänzen Sie -XX:-UseBASE64Intrinsics in der unterstützten JVM-Konfiguration des betroffenen Dienstes, ohne vorhandene Optionen oder globale Umgebungswerte zu ersetzen. Prüfen Sie, ob die Laufzeit diese Option unterstützt. Dies ist keine dauerhafte Korrektur.',
 'Getrenntes Laufzeit-Update: Beziehen Sie eine vom Hersteller freigegebene, kompatible und korrigierte Laufzeit aus einer vertrauenswürdigen Herstellerquelle. Prüfen Sie Integrität, Architektur und ELO-Unterstützung. Ersetzen Sie keine laufende Laufzeit und verwenden Sie keinen beliebigen Download.',
 'Stoppen Sie nur den betroffenen Dienst im genehmigten Wartungsfenster, führen Sie die gewählte Änderung nach Herstellerverfahren aus und starten Sie ihn erneut. Prüfen Sie Dienstzustand und wirksame JVM-Optionen beziehungsweise Version. Bei Fehlern stoppen und gesicherte Konfiguration oder Laufzeit wiederherstellen.',
 'Scannen Sie erneut und dokumentieren Sie das Ergebnis. Bewahren Sie die Sicherung bis zur erfolgreichen Prüfung auf. Bei unklaren Pfaden, Dienstzuordnung oder Kompatibilität wenden Sie sich an den ELO-Support.'],
 manualCommandsTitle:'PowerShell-Befehle (Administrator)',manualCommands:'# In einer ADMINISTRATOR-PowerShell ausfuehren. Pfade und Dienstnamen an das Scan-Ergebnis anpassen.\n\n# 1) Runtime, Version und die Dienste finden, die sie verwenden\n& \'C:\\ELO\\java\\bin\\java.exe\' -version\nGet-Content \'C:\\ELO\\java\\release\' | Select-String \'IMPLEMENTOR|JAVA_RUNTIME_VERSION|OS_ARCH\'\nGet-CimInstance Win32_Service | Where-Object { $_.PathName -match \'ELO\' } | Select-Object Name, State, PathName\n[Environment]::GetEnvironmentVariable(\'JAVA_TOOL_OPTIONS\', \'Machine\')\n\n# 2) Runtime vor jeder Aenderung als ZIP sichern\nCompress-Archive -LiteralPath \'C:\\ELO\\java\' -DestinationPath \'C:\\ELO\\java-backup.zip\'\n\n# 3) Vorlaeufige Risikominderung (systemweit): alten Wert BEHALTEN und anhaengen, nie ueberschreiben\n$old = [Environment]::GetEnvironmentVariable(\'JAVA_TOOL_OPTIONS\', \'Machine\'); $old\n[Environment]::SetEnvironmentVariable(\'JAVA_TOOL_OPTIONS\', (($old + \' -XX:-UseBASE64Intrinsics\').Trim()), \'Machine\')\n# Rueckgaengig: [Environment]::SetEnvironmentVariable(\'JAVA_TOOL_OPTIONS\', $old, \'Machine\')   ($null, falls leer)\n# Dienste sehen die Aenderung erst nach einem Neustart.\n\n# 4) Runtime manuell aktualisieren (zuerst die neueste Version DESSELBEN Herstellers und Branches laden)\n(Get-FileHash \'C:\\Downloads\\new-java.zip\' -Algorithm SHA256).Hash        # mit der veroeffentlichten SHA256 des Herstellers vergleichen\nStop-Service \'ELO-SRV01-1\' -Force                                        # jeden Dienst, der dieses Java verwendet\nRename-Item \'C:\\ELO\\java\' \'java.old\'\nExpand-Archive -LiteralPath \'C:\\Downloads\\new-java.zip\' -DestinationPath \'C:\\ELO\\java-new\'\nMove-Item (Get-ChildItem \'C:\\ELO\\java-new\' -Directory | Select-Object -First 1).FullName \'C:\\ELO\\java\'\n& \'C:\\ELO\\java\\bin\\java.exe\' -version\nStart-Service \'ELO-SRV01-1\'\n\n# 5) Bei Fehlern: Dienste stoppen, alte Runtime zurueckstellen, Dienste starten\nStop-Service \'ELO-SRV01-1\' -Force\nRename-Item \'C:\\ELO\\java\' \'java.failed\'; Rename-Item \'C:\\ELO\\java.old\' \'java\'\nStart-Service \'ELO-SRV01-1\'\n# Oder aus dem ZIP: Expand-Archive \'C:\\ELO\\java-backup.zip\' -DestinationPath \'C:\\ELO\\restore\'; dann den java-Ordner zurueckverschieben',
 backupsTitle:'Vorhandene Backups',backupsText:'Auf diesem Server wurden Backups dieses Werkzeugs gefunden. Wählen Sie eines, um diese Java-Version zurückzuholen; die aktuell installierte Runtime bleibt daneben erhalten.',severity_high:'Hoch',severity_medium:'Mittel',severity_low:'Niedrig',vulnTitle:'Schwachstelle gefunden: CVE-2026-114938 (Java4Shell)',vulnText:'{n} Runtime(s) liegen vor der behobenen Version: {list}. Der Fehler in den JIT-BASE64-Intrinsics kann falsche Ergebnisse liefern; der Hersteller hat ihn in einer neueren Version behoben.',vulnFixLabel:'Loesung:',vulnFix:'Java auf die aktuelle Version desselben Branches aktualisieren (Schritt 3, Java-Runtime aktualisieren). Die vorlaeufige Risikominderung senkt das Risiko nur bis zum Update.',terminalTitle:'Im Terminal ausfuehren (Administrator-PowerShell)',terminalCmdsText:'# Java auf die aktuelle Version aktualisieren (empfohlen)\n.\ELO-Patch-Tools.bat --cli --update-runtime --target {n} --confirm-admin --confirm-update\n\n# Nur vorlaeufige Risikominderung (haengt -XX:-UseBASE64Intrinsics an; danach die ELO-Dienste neu starten)\n.\ELO-Patch-Tools.bat --cli --mitigate --target {n} --confirm-admin --confirm-mitigation\n\n# Ergebnis pruefen (--target ist die Position in der Scan-Liste, ab 0)\n.\ELO-Patch-Tools.bat --cli --scan',backupsVuln:'enthaelt ein verwundbares Java',
restoreShort:'Dieses Backup wiederherstellen',backupRisk_vulnerable:'Verwundbar: diese Version liegt vor dem Herstellerfix einer Katalog-Schwachstelle',backupRisk_patched:'Für alle Katalog-Schwachstellen als behoben aufgeführt',backupRisk_unknown:'Sicherheitsstatus unbekannt: als potenziell verwundbar behandeln',backupStop:'Die Wiederherstellung beendet die ELO-Tomcat-Dienste, die dieses Java verwenden (ELO ist solange nicht verfügbar), und startet sie danach wieder.',
 exportHeading:'Aktivitätsprotokoll',exportJson:'JSON-Ergebnisse exportieren',exportLog:'Aktivitätsprotokoll exportieren',
 idle:'Bereit',scanning:'Scan läuft',cancelling:'Abbruch angefordert; Scanner wird abgewartet',completed:'Scan abgeschlossen',cancelled:'Scan abgebrochen; Ergebnisse möglicherweise unvollständig',error:'Vorgang fehlgeschlagen',unknown:'Unbekannt',
 vulnerable:'Möglicherweise verwundbar',safe:'Nach aktuellen Regeln keine Schwachstelle erkannt',mitigated:'Risikominderung erkannt',unsupported:'Nicht unterstützte Laufzeit',
 progress:'Fortschritt',indeterminate:'Fortschritt nicht verfügbar',path:'Installationspfad',version:'Laufzeitversion',classification:'Bewertung',
 auth:'Sitzungstoken fehlt oder wurde abgelehnt. Öffnen Sie den lokalen Sitzungslink erneut.',network:'Lokaler Dienst nicht erreichbar. Prüfen Sie, ob die BAT-Datei noch läuft.',
 invalid:'Der lokale Dienst hat eine ungültige Antwort geliefert.',failed:'Anfrage fehlgeschlagen. Prüfen Sie den lokalen Dienst und versuchen Sie es erneut.',expired:'Die Vorschau ist abgelaufen oder passt nicht mehr zum Ziel. Fordern Sie eine neue Vorschau an.',
 accessDenied:'Zugriff verweigert. Administratorrechte und Datei-/Registrierungsberechtigungen prüfen, ohne den Zugriffsschutz zu umgehen. Kein Schutz zugesichert.',
 adminNeeded:'Risikominderung erfordert eine erhöhte Administratorsitzung. Schreibgeschützte Scans benötigen keine Erhöhung. Dies ist kein Sitzungstoken-Fehler.',
 boundaryRejected:'Der lokale Dienst hat die Anfragegrenzen abgelehnt. Öffnen Sie den ursprünglichen lokalen Sitzungslink erneut; Herkunfts- und Host-Prüfungen nicht umgehen.',
 updateRefused:'Das Runtime-Update kann für diese JVM nicht angeboten werden. Nichts wurde heruntergeladen oder geändert.',updateRejected:'Das Update wurde abgelehnt, bevor die Runtime ersetzt wurde. Die ursprüngliche Runtime ist unverändert.',updateRolledBack:'Die neue Runtime bestand die Prüfung nicht. Die ursprüngliche Runtime wurde wiederhergestellt und geprüft; fehlgeschlagene Runtime und Backup-ZIP bleiben erhalten.',updateManualRecovery:'Automatische Wiederherstellung fehlgeschlagen. Manuelle Wiederherstellung aus dem Backup-ZIP ist erforderlich (siehe technischer Bericht).',
 rollbackFailed:'Wiederherstellung fehlgeschlagen — manuelle Wiederherstellung erforderlich.',manualRecovery:'Vor weiteren Änderungen ist eine manuelle Wiederherstellung erforderlich.',
 recoveryGuidance:'KRITISCH: JAVA_TOOL_OPTIONS ist möglicherweise noch geändert. Weitere zustandsändernde Anfragen sind auf dieser Seite gesperrt. Stellen Sie mit Ihrem Administrator den exakten alten Wert UND Registrierungstyp aus der Vorschau mit einem freigegebenen Registrierungseditor-Verfahren wieder her. Vor dem Schließen dieser Sitzung und dem Start einer neuen Sitzung manuell prüfen. Eine neue Sitzung allein stellt die Umgebung nicht wieder her. Kein Schutz bestehender JVMs zugesichert.',
 rolledBack:'Prüfung fehlgeschlagen. Der exakte alte Umgebungswert und Registrierungstyp wurden wiederhergestellt und zurückgelesen. Kein Schutz zugesichert.',
 probeFailed:'Prüfung der JVM-Option vor einer Änderung fehlgeschlagen. Kein Schutz zugesichert.',
 updateUnavailable:'Automatisches Laufzeit-Update nicht verfügbar: Herkunft, ELO-Kompatibilität, Sicherung, Ersetzung und Wiederherstellung sind nicht geprüft. Nichts wurde heruntergeladen oder ersetzt. Nutzen Sie die manuelle Anleitung und den Herstellersupport.',
 incompleteScan:'Der Scan ist unvollständig oder überschreitet Nachweisgrenzen. Engeres zugängliches lokales Verzeichnis wählen und Berechtigungen prüfen, ohne den Zugriffsschutz zu umgehen.',
 inaccessiblePath:'Das gewählte lokale Verzeichnis fehlt oder ist unzugänglich. Verzeichnis und Berechtigungen prüfen.',
 scanBusy:'Ein Scan läuft bereits. Abschluss abwarten oder Abbruch anfordern.',completedScan:'Vor einer Änderung einen erfolgreichen Scan abschließen.',
 targetIneligible:'Die gewählte JVM ist für diese Änderung nicht geeignet. Scan-Nachweise prüfen.',optionsUnsupported:'Vorhandene JVM-/Umgebungseinstellungen sind mehrdeutig oder nicht unterstützt. Vor Änderungen mit Ihrem Administrator prüfen.',
 scanSent:'Scan angefordert',cancelSent:'Abbruch angefordert',previewReady:'Vorschau empfangen',actionSent:'Bestätigte Änderung abgeschlossen',connected:'Sitzung verbunden',report:'Bericht exportiert',log:'Aktivitätsprotokoll exportiert',
 units:'Elemente geprüft',previewKind:'Gewählte Änderung',mitigation:'Vorübergehende Risikominderung',runtimeUpdate:'Laufzeit-Update',
 searchPath:'Optionales lokales Suchverzeichnis',searchHelp:'Auf bereiten festen oder Wechsellaufwerken C: bis Z: prüft der Scan X:\\java\\bin\\java.exe, X:\\ELO\\java\\bin\\java.exe und X:\\<Ordner>\\java\\bin\\java.exe (jeder Ordner der ersten Ebene, z. B. X:\\AndererOrdner\\java\\bin) im Laufwerksstamm. Optional ein absolutes lokales Verzeichnis eingeben, das nach den Stammprüfungen durchsucht wird, z. B. C:\\ELO data. Die Eingabe ist nur ein schreibgeschützter Suchpfad, niemals ein Befehl. Netzwerk- und Gerätepfade sowie Platzhalter sind nicht zulässig.',
 invalidPath:'Geben Sie ein absolutes lokales Windows-Verzeichnis mit höchstens 1024 Zeichen ohne Steuerzeichen, Platzhalter oder relative Segmente ein.',
 jvmTable:'Gefundene JVMs und Nachweise',runtimeRoot:'Laufzeit-Stammverzeichnis',vendor:'Hersteller',architecture:'Architektur',eloRationale:'Begründung der ELO-Zuordnung',classificationEvidence:'Nachweis der Einstufung',
 patched:'Gepatcht','not-affected':'Nicht betroffen',inconclusive:'Nicht eindeutig',
 securityHeading:'Sicherheitsinformationen',securityHelp:'Offizielle Sicherheitshinweise und Prüfdatum werden vom Backend-Verantwortlichen bereitgestellt und geprüft. Diese Oberfläche prüft Format und offizielle Domain, nicht den aktuellen Inhalt oder die Anwendbarkeit. Links öffnen sich nur auf Anforderung; externe Ressourcen werden nicht geladen. Prüfen Sie Nachweise und Herstellersupport vor Änderungen.',
 resultNotice:'Während eines Scans, nach einem Abbruch oder Fehler können Ergebnisse unvollständig oder veraltet sein. Sie sind keine aktuelle, vollständige Bewertung.',
 verifiedDate:'Prüfdatum der Quellen (UTC)',noAdvisories:'Keine geprüften Sicherheitshinweise bereitgestellt. Daraus darf keine Unbedenklichkeit der Laufzeit abgeleitet werden.'
 }
};
const $ = id => document.getElementById(id);
// The link carries the token once (fragment). It is kept only for this tab (sessionStorage) so that a page
// refresh keeps working; a new local session link replaces it. Never sent anywhere except as X-Session-Token.
let token = new URLSearchParams(location.hash.slice(1)).get('token') || '';
history.replaceState(null, '', location.pathname + location.search);
try {
 if (/^[A-Za-z0-9_-]{16,256}$/.test(token)) sessionStorage.setItem('eloSessionToken',token);
 else { const saved = sessionStorage.getItem('eloSessionToken') || ''; token = /^[A-Za-z0-9_-]{16,256}$/.test(saved) ? saved : ''; }
} catch (_) { /* storage unavailable: the link must be reopened after a refresh */ }
const forgetToken = () => { try { sessionStorage.removeItem('eloSessionToken'); } catch (_) { } };
let language = 'en', state = 'idle', rows = [], preview = null, pending = false, polling = false, lastError = '';
let vulns = [], backups = [], backupsKey = '', progress = null, checked = null, lastSuccessfulRefresh = null, security = {verifiedOn:null,advisories:[]};
let lastWarnings = [], errorFromPoll = false, recoveryRequired = false, recoveryWarnings = [];
let step = 1, awaitingScan = false, scanStartedAt = null, finalKind = '', canRestore = false, cardsKey = '';
const events = [], states = ['idle','scanning','cancelling','completed','cancelled','error'];
const t = key => messages[language][key] || messages[language].unknown;
const safeText = value => typeof value === 'string' ? (token ? value.split(token).join('[redacted]') : value).slice(0,16000) : '';
const validId = value => typeof value === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(value);
const record = value => value && typeof value === 'object' && !Array.isArray(value);
const keys = (value, required, optional = []) => record(value) && required.every(key => Object.hasOwn(value,key)) && Object.keys(value).every(key => required.includes(key) || optional.includes(key));
const text = (value,max) => typeof value === 'string' && value.trim().length >= 1 && value.length <= max && !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(value);
const bilingual = (value,max) => keys(value,['en','de']) && text(value.en,max) && text(value.de,max);
const classifications = ['vulnerable','patched','not-affected','inconclusive','mitigated','unsupported','safe'];
const rowFields = ['id','path','runtimeRoot','version','vendor','architecture','status','eloRationale','classificationEvidence'];
const validBackup = item => keys(item,['id','path','runtime','version','vendor','risk','created','size']) && validId(item.id) && text(item.path,1024) && text(item.runtime,1024) && text(item.version,128) && text(item.vendor,32) && ['vulnerable','patched','unknown'].includes(item.risk) && text(item.created,32) && Number.isSafeInteger(item.size) && item.size >= 0;
const severities = ['high','medium','low'];
const validVuln = item => keys(item,['id','alias','severity','title','problem','solution','actions']) && /^[A-Za-z0-9._-]{3,64}$/.test(item.id) && typeof item.alias === 'string' && item.alias.length <= 64 && severities.includes(item.severity) && bilingual(item.title,2048) && bilingual(item.problem,2048) && bilingual(item.solution,2048) && Array.isArray(item.actions) && item.actions.length <= 16 && item.actions.every(action => typeof action === 'string' && action.length <= 32);
const validFinding = item => keys(item,['id','severity','status']) && /^[A-Za-z0-9._-]{3,64}$/.test(item.id) && severities.includes(item.severity) && ['vulnerable','patched','inconclusive'].includes(item.status);
const validRow = row => keys(row,rowFields,['findings']) && (row.findings === undefined || (Array.isArray(row.findings) && row.findings.length <= 32 && row.findings.every(validFinding))) && validId(row.id) && text(row.path,1024) && text(row.runtimeRoot,1024) && text(row.version,128) && text(row.vendor,256) && ['x86','x64','arm64','unknown'].includes(row.architecture) && classifications.includes(row.status) && bilingual(row.eloRationale,2048) && bilingual(row.classificationEvidence,4096);
function validSearchPath(value) {
 return value.length <= 1024 && /^[A-Za-z]:\\/.test(value) && !/[\u0000-\u001f\u007f"<>|?*\/]/.test(value) && !value.slice(2).includes(':') && !value.split('\\').slice(1).some(part => /[. ]$/.test(part) || /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(part));
}
function officialUrl(value) {
 // Advisory links come from the catalog (vulndb.json): any plain https URL, no credentials, port, query or fragment.
 if (!text(value,512) || (token && value.includes(token))) return false;
 try {
 const url = new URL(value);
 return url.href === value && url.protocol === 'https:' && !url.username && !url.password && !url.port && !url.search && !url.hash && /^[a-z0-9.-]+$/.test(url.hostname) && /^\/[A-Za-z0-9._~\/-]*$/.test(url.pathname);
 } catch (_) { return false; }
}function validSecurity(value) {
 if (!keys(value,['verifiedOn','advisories']) || !Array.isArray(value.advisories) || value.advisories.length > 16) return false;
 if (!value.advisories.length) return value.verifiedOn === null;
 const date = value.verifiedOn;
 return typeof date === 'string' && /^20\d{2}-\d{2}-\d{2}$/.test(date) && Number.isFinite(Date.parse(date)) && new Date(date).toISOString().slice(0,10) === date && date <= new Date().toISOString().slice(0,10) &&
 value.advisories.every(item => keys(item,['id','title','url']) && validId(item.id) && bilingual(item.title,256) && officialUrl(item.url)) && new Set(value.advisories.map(item => item.id)).size === value.advisories.length;
}
const localized = value => safeText(value[language]);
const running = () => state === 'scanning' || state === 'cancelling';
function log(key) { events.push({time:new Date().toISOString(),key}); if(events.length > 500) events.shift(); renderLog(); }
function renderLog() { $('activity').textContent = events.map(e => e.time+' '+t(e.key)).join('\n'); }
function clearPreview() { preview = null; $('confirm').checked = false; }
// Exact known server codes only. Never use an arbitrary server string as a message key.
const errorMessages = Object.fromEntries(Object.entries({
 auth:['authentication_required'],accessDenied:['access_denied'],adminNeeded:['administrator_required'],
 boundaryRejected:['loopback_only','host_rejected','origin_rejected','cross_site','origin_required'],
 expired:['preview_expired_or_mismatched','stale_preview'],
 updateRefused:['update_preview_refused'],updateRejected:['update_rejected_no_change'],updateRolledBack:['update_failed_rolled_back'],updateManualRecovery:['update_manual_recovery_required'],
 updateNotNeeded:['update_not_needed'],noBackup:['no_backup_for_target'],restoreFailed:['restore_failed_no_change'],
 rollbackFailed:['rollback_failed_manual_recovery_required'],manualRecovery:['manual_recovery_required_close_session'],
 rolledBack:['verification_failed_rolled_back'],probeFailed:['probe_failed_no_change'],
 updateUnavailable:['update_unavailable_provenance_compatibility_backup_replacement_rollback_not_verified'],
 incompleteScan:['scan_incomplete','narrow_scan_root','evidence_out_of_bounds'],inaccessiblePath:['inaccessible_path'],
 invalidPath:['invalid_path','nonlocal_path','reparse_path'],scanBusy:['scan_busy'],completedScan:['completed_scan_required'],
 targetIneligible:['target_not_eligible','invalid_java_target'],
 optionsUnsupported:['unsupported_environment_type','unsupported_options','ambiguous_option_quoting','malformed_option_quoting','ambiguous_intrinsics_option','ambiguous_jvm_options','ambiguous_environment_expansion'],
 failed:['operation_failed','scan_failed','unknown_route','method_rejected','unexpected_body','json_required','invalid_id','invalid_action','invalid_json','invalid_parameters','missing_parameter','request_timeout','incomplete_request','invalid_header','headers_too_large','invalid_request_line','duplicate_header','unsupported_framing','invalid_length','length_required','body_too_large','incomplete_body','invalid_utf8']
}).flatMap(([key,codes]) => codes.map(code => [code,key])));
const recoveryCodes = ['rollback_failed_manual_recovery_required','manual_recovery_required_close_session','update_manual_recovery_required'];
class ApiFailure extends Error {
 constructor(key,warnings = [],recovery = false) { super(key); this.key = key; this.warnings = warnings; this.recovery = recovery; }
}
function fail(error, fromPoll = false) {
 lastError = error instanceof ApiFailure ? error.key : typeof error === 'string' && Object.hasOwn(messages.en,error) ? error : 'invalid';
 lastWarnings = error instanceof ApiFailure ? error.warnings : []; errorFromPoll = fromPoll;
 if (error instanceof ApiFailure && error.recovery) {
 recoveryRequired = true; recoveryWarnings = error.warnings; lastWarnings = []; state = 'error';
 }
 render();
}
async function readJson(response,limit) {
 try {
 const reader = response.body.getReader(), decoder = new TextDecoder('utf-8',{fatal:true});
 let size = 0, json = '';
 try {
 while (true) {
 const chunk = await reader.read(); if (chunk.done) break;
 size += chunk.value.byteLength;
 if (size > limit) { await reader.cancel(); throw 0; }
 json += decoder.decode(chunk.value,{stream:true});
 }
 json += decoder.decode();
 } finally { reader.releaseLock(); }
 const data = JSON.parse(json); if (!record(data)) throw 0; return data;
 } catch (_) { throw 'invalid'; }
}
async function api(path, body) {
 if (!token) throw 'auth';
 let response;
 try { response = await fetch('/api/'+path, {method:body === undefined ? 'GET' : 'POST',headers:{'X-Session-Token':token,...(body === undefined ? {} : {'Content-Type':'application/json'})},...(body === undefined ? {} : {body:JSON.stringify(body)}),credentials:'omit',cache:'no-store',redirect:'error',referrerPolicy:'no-referrer'}); }
 catch (_) { throw 'network'; }
 if (response.ok) return readJson(response,4*1024*1024);
 if (response.status === 401) forgetToken();
 const fallback = response.status === 401 ? 'auth' : response.status === 403 ? 'accessDenied' : 'failed';
 let data;
 try { data = await readJson(response,256*1024); } catch (_) { throw new ApiFailure(fallback); }
 if (!keys(data,['error','warnings']) || typeof data.error !== 'string' || !/^[a-z0-9_]{1,128}$/.test(data.error) || !Object.hasOwn(errorMessages,data.error)) throw new ApiFailure(fallback);
 const recovery = recoveryCodes.includes(data.error);
 if (!Array.isArray(data.warnings) || data.warnings.length > 16 || data.warnings.some(warning => !bilingual(warning,2048))) throw new ApiFailure(recovery ? errorMessages[data.error] : 'invalid',[],recovery);
 throw new ApiFailure(errorMessages[data.error],data.warnings,recovery);
}
async function acknowledge(path, body) { const data = await api(path,body); if (!keys(data,['ok']) || data.ok !== true) throw 'failed'; }
function selected() { return rows.find(row => row.id === $('results').value); }
// ---- wizard (presentation only): a step is reachable when its prerequisite exists.
const reachable = n => n === 1 || ((n === 2 || n === 5) && rows.length > 0) || (n === 3 && !!selected()) || (n === 4 && !!preview);
function goto(n) { if (reachable(n)) { step = n; render(); } }
function fixStep() { while (step > 1 && !reachable(step)) step = step === 5 ? 1 : step - 1; }
const previewKinds = {'mitigate':'mitigation','update-runtime':'runtimeUpdate','restore-backup':'restoreBackup'};
function toggle(id, hidden) { if (hidden) $(id).setAttribute('hidden',''); else $(id).removeAttribute('hidden'); }
function renderCards() {
 const key = JSON.stringify(rows.map(row => [row.id,row.status]))+'|'+$('results').value+'|'+language;
 if (key === cardsKey) return;
 cardsKey = key; $('cards').replaceChildren();
 rows.forEach(row => {
 const card = document.createElement('button'), title = document.createElement('span'), path = document.createElement('span'), badge = document.createElement('span');
 card.className = 'rt'; card.dataset.status = row.status; card.setAttribute('type','button'); card.setAttribute('role','radio'); card.setAttribute('aria-checked',String(row.id === $('results').value));
 title.className = 't'; title.textContent = safeText(row.vendor)+' '+safeText(row.version)+(row.architecture === 'unknown' ? '' : ' · '+row.architecture);
 path.className = 'p'; path.textContent = safeText(row.runtimeRoot);
 badge.className = 'badge'; badge.setAttribute('data-status',row.status); badge.textContent = t(row.status);
 card.append(title); card.append(path); card.append(badge);
 card.onclick = () => { if (pending || running()) return; $('results').value = row.id; clearPreview(); render(); };
 $('cards').append(card);
 });
}
function highlightInto(el, source) {
 el.replaceChildren();
 source.split('\n').forEach(line => {
 const row = document.createElement('span');
 if (/^\s*#/.test(line)) { row.className = 'c-note'; row.textContent = line; }
 else if (line === '') { row.textContent = ' '; }
 else line.split(/(--[a-z-]+|\$[A-Za-z]+|'[^']*')/).forEach(part => {
 if (!part) return;
 const piece = document.createElement('span');
 if (part.startsWith('--')) piece.className = 'c-flag'; else if (part[0] === '$') piece.className = 'c-var'; else if (part[0] === "'") piece.className = 'c-str';
 piece.textContent = part; row.append(piece);
 });
 el.append(row);
 });
}
let cmdKey = '';
const fill = (template, values) => template.replace(/\{(n|list)\}/g,(_, key) => values[key]);
function adviceBlock(vuln, affected, solutionOnly) {
 const box = document.createElement('div'), head = document.createElement('h3'), sev = document.createElement('span'), title = document.createElement('span'), problem = document.createElement('p'), fix = document.createElement('p'), label = document.createElement('strong'), solution = document.createElement('span');
 box.className = 'vuln'; fix.className = 'fix';
 sev.className = 'sev'; sev.dataset.sev = vuln.severity; sev.textContent = t('severity_'+vuln.severity);
 title.textContent = localized(vuln.title);
 const list = affected.slice(0,5).map(item => safeText(item.vendor)+' '+safeText(item.version)+' ('+safeText(item.runtimeRoot)+')').join('; ');
 problem.textContent = fill(localized(vuln.problem),{n:String(affected.length),list});
 label.textContent = t('vulnFixLabel')+' '; solution.textContent = localized(vuln.solution);
 fix.append(label); fix.append(solution);
 if (!solutionOnly) { head.append(sev); head.append(title); box.append(head); box.append(problem); }
 box.append(fix);
 return box;
}
function renderAdvice(row) {
 const affects = id => item => (item.findings || []).some(f => f.id === id && f.status === 'vulnerable');
 const blocks = [], recs = [];
 vulns.forEach(vuln => {
 const affected = rows.filter(affects(vuln.id));
 if (affected.length) blocks.push(adviceBlock(vuln,affected,false));
 if (row && affects(vuln.id)(row)) recs.push(adviceBlock(vuln,[row],true));
 });
 // Rows without catalog findings (older results) still get the generic alert.
 const legacy = rows.filter(item => item.status === 'vulnerable' && !(item.findings || []).length);
 if (legacy.length && !vulns.length) {
 const box = document.createElement('div'), head = document.createElement('h3'), problem = document.createElement('p'), fix = document.createElement('p'), label = document.createElement('strong'), solution = document.createElement('span');
 box.className = 'vuln'; fix.className = 'fix'; head.textContent = t('vulnTitle');
 problem.textContent = fill(t('vulnText'),{n:String(legacy.length),list:legacy.slice(0,5).map(item => safeText(item.vendor)+' '+safeText(item.version)+' ('+safeText(item.runtimeRoot)+')').join('; ')});
 label.textContent = t('vulnFixLabel')+' '; solution.textContent = t('vulnFix'); fix.append(label); fix.append(solution);
 box.append(head); box.append(problem); box.append(fix); blocks.push(box);
 if (row && row.status === 'vulnerable') { const rec = document.createElement('div'), p2 = document.createElement('p'), l2 = document.createElement('strong'), s2 = document.createElement('span'); l2.textContent = t('vulnFixLabel')+' '; s2.textContent = t('vulnFix'); p2.append(l2); p2.append(s2); rec.append(p2); recs.push(rec); }
 }
 $('vulnList').replaceChildren(); blocks.forEach(block => $('vulnList').append(block));
 $('vulnRecList').replaceChildren(); recs.forEach(block => $('vulnRecList').append(block));
 toggle('vulnAlert',blocks.length === 0); toggle('vulnRec',recs.length === 0);const n = Math.max(0,rows.findIndex(item => row && item.id === row.id));
 const key = language+'|'+n; if (key === cmdKey) return; cmdKey = key;
 highlightInto($('terminalCmds'),t('terminalCmdsText').replace(/\{n\}/g,() => String(n)));
 highlightInto($('cmdView'),t('manualCommands'));
}
function renderBackups() {
 const key = JSON.stringify(backups.map(item => [item.id,item.risk]))+'|'+language+'|'+(pending || running() || recoveryRequired);
 toggle('backupsBox',backups.length === 0);
 $('backupsSummary').textContent = t('backupsTitle')+' ('+backups.length+')'+(backups.some(item => item.risk !== 'patched') ? ' · '+t('backupsVuln') : '');
 if (key === backupsKey) return;
 backupsKey = key; $('backups').replaceChildren();
 backups.forEach(item => {
 const card = document.createElement('button'), title = document.createElement('span'), path = document.createElement('span'), meta = document.createElement('span'), act = document.createElement('span'), risk = document.createElement('span'), note = document.createElement('span');
 card.className = 'rt'; card.setAttribute('type','button'); card.disabled = pending || running() || recoveryRequired;
 risk.className = 'badge'; risk.dataset.status = item.risk === 'unknown' ? 'inconclusive' : item.risk; risk.textContent = t('backupRisk_'+item.risk);
 note.className = 'p'; note.textContent = t('backupStop');
 title.className = 't'; title.textContent = safeText(item.runtime)+' — '+safeText(item.version);
 path.className = 'p'; path.textContent = safeText(item.path);
 meta.className = 'p'; meta.textContent = safeText(item.created)+' UTC · '+Math.max(1,Math.round(item.size/1048576))+' MB';
 act.className = 'badge act'; act.textContent = t('restoreShort');
 card.append(title); card.append(risk); card.append(path); card.append(meta); card.append(note); card.append(act);
 card.onclick = () => getPreview('restore-backup',item.id);
 $('backups').append(card);
 });
}
function render() {
 document.documentElement.lang = language;
 document.querySelectorAll('[data-i18n]').forEach(el => { el.textContent = t(el.dataset.i18n); });
 $('error').textContent = lastError ? [t(lastError),...lastWarnings.map(localized)].join('\n') : '';
 $('recoveryNotice').textContent = recoveryRequired ? [t('recoveryGuidance'),...recoveryWarnings.map(localized)].join('\n') : '';
 $('status').textContent = t(recoveryRequired ? 'error' : state);
 $('resultNotice').textContent = lastError || recoveryRequired || running() || state === 'cancelled' || state === 'error' ? t('resultNotice') : '';
 // Honest progress: a moving bar only while the scanner runs; a summary once it is done.
 const elapsed = scanStartedAt === null ? '' : ' · '+Math.max(0,Math.round((Date.now()-scanStartedAt)/1000))+' s';
 toggle('progress',!running()); toggle('spinner',!running()); toggle('busy',!pending);
 $('progress').setAttribute('aria-label',t('progress'));
 if (progress === null) $('progress').removeAttribute('value'); else $('progress').value = progress;
 $('progressText').textContent = running() ? (progress === null ? t('scanningNow') : t('progress')+': '+progress+'%')+elapsed+(checked === null ? '' : ' — '+checked+' '+t('units')) : '';
 $('scanSummary').textContent = !running() && state === 'completed' && !lastError ? (rows.length ? t('foundN').replace('{n}',String(rows.length)) : t('foundNone')) : '';
 const old = $('results').value;
 $('results').replaceChildren();
 if (!rows.length) { const option = document.createElement('option'); option.textContent = t('none'); option.value = ''; $('results').append(option); }
 rows.forEach(row => { const option = document.createElement('option'); option.value = row.id; option.textContent = safeText(row.runtimeRoot)+' — '+safeText(row.version)+' — '+safeText(row.vendor)+' — '+t(row.status); $('results').append(option); });
 if (rows.some(row => row.id === old)) $('results').value = old;
 const row = selected();
 const cells = item => [safeText(item.path),safeText(item.runtimeRoot),safeText(item.version),safeText(item.vendor),item.architecture === 'unknown' ? t('unknown') : item.architecture,t(item.status),localized(item.eloRationale),localized(item.classificationEvidence)];
 $('jvmRows').replaceChildren();
 rows.forEach(item => { const tr = document.createElement('tr'); cells(item).forEach(value => { const td = document.createElement('td'); td.textContent = value; tr.append(td); }); $('jvmRows').append(tr); });
 const labels = ['path','runtimeRoot','version','vendor','architecture','classification','eloRationale','classificationEvidence'];
 $('details').textContent = row ? cells(row).map((value,index) => t(labels[index])+': '+value).join('\n') : '';
 renderCards(); renderBackups(); renderAdvice(row);
 $('verifiedOn').textContent = security.verifiedOn ? t('verifiedDate')+': '+security.verifiedOn : t('noAdvisories');
 $('advisories').replaceChildren();
 security.advisories.forEach(item => {
 const li = document.createElement('li'), link = document.createElement('a');
 link.textContent = localized(item.title); link.href = item.url; link.target = '_blank'; link.rel = 'noopener noreferrer'; link.referrerPolicy = 'no-referrer';
 li.append(link); $('advisories').append(li);
 });
 $('searchPath').disabled = pending || running() || recoveryRequired;
 $('scan').disabled = pending || running() || !token || recoveryRequired;
 $('cancel').disabled = pending || state !== 'scanning' || !token || recoveryRequired;
 $('results').disabled = pending || running();
 $('mitigate').disabled = $('update').disabled = pending || running() || !row || !token || recoveryRequired || (!!lastError && errorFromPoll);
 $('preview').textContent = preview ? localized(preview.summary)+(preview.warnings.length ? '\n\n'+preview.warnings.map(w => '• '+localized(w)).join('\n') : '') : t('noPreview');
 $('previewKind').textContent = preview ? t(previewKinds[preview.actionId]) : '';
 $('confirmation').textContent = t(preview && preview.actionId === 'update-runtime' ? 'confirmUpdate' : preview && preview.actionId === 'restore-backup' ? 'confirmRestore' : 'confirmMitigation');
 $('confirm').disabled = pending || !preview || running() || recoveryRequired;
 $('apply').disabled = pending || !preview || !$('confirm').checked || running() || recoveryRequired;
 $('manual').replaceChildren(); messages[language].manual.forEach(text => { const li = document.createElement('li'); li.textContent = text; $('manual').append(li); });
 renderLog();
 // wizard chrome
 fixStep();
 for (let n = 1; n <= 5; n++) {
 toggle('step'+n, step !== n);
 const nav = $('nav'+n);
 nav.setAttribute('data-state', step === n ? 'current' : n < step ? 'done' : 'todo');
 if (step === n) nav.setAttribute('aria-current','step'); else nav.removeAttribute('aria-current');
 nav.disabled = pending || !reachable(n) || (running() && n !== 1) || recoveryRequired && n !== 5;
 }
 toggle('toStep2', !(rows.length > 0 && !running()));
 $('toStep3').disabled = pending || running() || !row;
 $('back2').disabled = $('back3').disabled = $('back4').disabled = pending;
 $('startOver').disabled = pending || running() || !token;
 toggle('restore', !canRestore); toggle('restoreHint', !canRestore);
 $('restore').disabled = pending || running() || !row || !token || recoveryRequired || !canRestore;
 const done = {'mitigate':'doneMitigation','update-runtime':'doneUpdate','restore-backup':'doneRestore'}[finalKind];
 $('finalNotice').textContent = done && !lastError ? t(done) : '';
}
async function refresh() {
 if (polling || pending || !token) return;
 polling = true;
 try {
 const status = await api('status');
 if (!keys(status,['state'],['progress','checked']) || !states.includes(status.state) || (status.progress !== undefined && (!Number.isFinite(status.progress) || status.progress < 0 || status.progress > 100)) || (status.checked !== undefined && (!Number.isSafeInteger(status.checked) || status.checked < 0))) throw 'invalid';
 const result = await api('results');
 if (!keys(result,['results','security'],['backups','vulnerabilities']) || (result.vulnerabilities !== undefined && (!Array.isArray(result.vulnerabilities) || result.vulnerabilities.length > 32 || result.vulnerabilities.some(item => !validVuln(item)))) || (result.backups !== undefined && (!Array.isArray(result.backups) || result.backups.length > 50 || result.backups.some(item => !validBackup(item)) || new Set(result.backups.map(item => item.id)).size !== result.backups.length)) || !Array.isArray(result.results) || result.results.length > 250 || result.results.some(row => !validRow(row)) || new Set(result.results.map(row => row.id)).size !== result.results.length || !validSecurity(result.security)) throw 'invalid';
 const nextRows = result.results;
 if (state !== status.state || JSON.stringify(rows) !== JSON.stringify(nextRows) || JSON.stringify(security) !== JSON.stringify(result.security)) clearPreview();
 if (status.state === 'scanning' && scanStartedAt === null) scanStartedAt = Date.now();
 state = status.state; rows = nextRows; security = result.security; backups = result.backups || []; vulns = result.vulnerabilities || [];
 if (state !== 'scanning' && state !== 'cancelling') scanStartedAt = null;
 // A finished scan moves the wizard on by itself; anything else releases the wait.
 if (awaitingScan && state === 'completed') { awaitingScan = false; if (rows.length) step = 2; }
 if (awaitingScan && (state === 'cancelled' || state === 'error')) awaitingScan = false;
 progress = Number.isFinite(status.progress) ? Math.max(0,Math.min(100,status.progress)) : null;
 checked = Number.isSafeInteger(status.checked) && status.checked >= 0 ? status.checked : null;
 lastSuccessfulRefresh = new Date().toISOString();
 if (errorFromPoll) { lastError = recoveryRequired ? 'manualRecovery' : ''; lastWarnings = []; errorFromPoll = false; }
 render();
 } catch (error) { clearPreview(); fail(error,true); }
 finally { polling = false; }
}
async function perform(work, allowRecovery = false) {
 // A click during a background refresh waits for it instead of being silently ignored.
 for (let i = 0; polling && i < 200; i++) await new Promise(resolve => setTimeout(resolve,25));
 if (pending || polling || (recoveryRequired && !allowRecovery)) return;
 pending = true; lastError = ''; lastWarnings = []; errorFromPoll = false; render();
 try { await work(); } catch (error) { clearPreview(); fail(error); }
 finally { pending = false; render(); }
}
$('language').onchange = () => { language = $('language').value === 'de' ? 'de' : 'en'; render(); };
$('results').onchange = () => { clearPreview(); render(); };
$('confirm').onchange = render;
$('searchPath').oninput = () => { clearPreview(); render(); };
$('scan').onclick = () => {
 const searchPath = $('searchPath').value;
 if (searchPath !== '' && !validSearchPath(searchPath)) { clearPreview(); fail('invalidPath'); return; }
 return perform(async () => { clearPreview(); await acknowledge('scan',searchPath === '' ? {} : {searchPath}); state = 'scanning'; rows = []; lastSuccessfulRefresh = null; progress = null; checked = null; canRestore = false; finalKind = ''; awaitingScan = true; scanStartedAt = Date.now(); step = 1; log('scanSent'); });
};
$('cancel').onclick = () => perform(async () => { clearPreview(); await acknowledge('cancel',{}); state = 'cancelling'; log('cancelSent'); });
async function getPreview(actionId, explicitId) {
 const row = selected(); const resultId = explicitId || (row && row.id);
 if (!resultId || running() || recoveryRequired || (lastError && errorFromPoll)) return;
 await perform(async () => {
 clearPreview(); const data = await api('preview',{actionId,resultId});
 if (!keys(data,['previewId','summary','warnings']) || !validId(data.previewId) || !bilingual(data.summary,4096) || !Array.isArray(data.warnings) || data.warnings.length > 16 || data.warnings.some(w => !bilingual(w,2048))) throw 'invalid';
 preview = {previewId:data.previewId,actionId,resultId,summary:data.summary,warnings:data.warnings}; step = 4; log('previewReady');
 });
}
$('mitigate').onclick = () => getPreview('mitigate');
$('update').onclick = () => getPreview('update-runtime');
$('restore').onclick = () => getPreview('restore-backup');
$('apply').onclick = () => {
 if (!preview || !$('confirm').checked || running() || lastError || recoveryRequired) return;
 const request = {actionId:preview.actionId,resultId:preview.resultId,previewId:preview.previewId};
 return perform(async () => {
 clearPreview(); await acknowledge('action',request); log('actionSent');
 finalKind = request.actionId; canRestore = request.actionId === 'update-runtime'; step = 5;
 });
};
for (let n = 1; n <= 5; n++) $('nav'+n).onclick = () => goto(n);
$('toStep2').onclick = () => goto(2);
$('toStep3').onclick = () => goto(3);
$('back2').onclick = () => goto(1);
$('back3').onclick = () => goto(2);
$('back4').onclick = () => { clearPreview(); goto(3); };
$('startOver').onclick = () => { clearPreview(); finalKind = ''; step = 1; render(); };
// The authenticated backend creates the sanitized report; no UI rows, paths,
// raw diagnostics or client action claims are submitted as evidence.
async function exportTechnicalReport() {
 const data = await api('report',{language});
 if (!keys(data,['html']) || typeof data.html !== 'string' || !data.html.startsWith('<!doctype html>')) throw 'invalid';
 download('elo-technical-'+language+'.html',data.html,'text/html;charset=utf-8');
 log('report');
}
function download(filename, content, type) {
 const url = URL.createObjectURL(new Blob([content],{type}));
 const link = document.createElement('a'); link.href = url; link.download = filename; link.click();
 setTimeout(() => URL.revokeObjectURL(url),1000);
}
$('exportTechnical').onclick = () => perform(exportTechnicalReport,true);
$('exportJson').onclick = () => { download('elo-results.json',JSON.stringify({state,results:rows,security,lastSuccessfulRefresh,recoveryRequired,assessmentComplete:state === 'completed' && !lastError && !pending && !recoveryRequired && lastSuccessfulRefresh !== null}, (key,value) => typeof value === 'string' ? safeText(value) : value,2),'application/json'); log('report'); };
$('exportLog').onclick = () => { download('elo-activity.txt',events.map(e => e.time+' '+t(e.key)).join('\n'),'text/plain;charset=utf-8'); log('log'); };
render();
if (token) { log('connected'); void refresh(); setInterval(() => { void refresh(); },2000); } else fail('auth');
})();
</script>
</body>
</html>
::ELO_PATCH_END:UI_HTML

::ELO_PATCH_BEGIN:REPORT_PS
# PowerShell 5.1, embeddable: dot-sourcing defines functions only; no IO on load.
# API: New-EloTechnicalReport -> sanitized evidence DTO;
# ConvertTo-EloTechnicalReportHtml -Report <DTO> -Language en|de -> HTML string.
# No file writes, network, Java execution, credential inputs, or ELO calls.
# ResourceCollector: trusted scriptblock returning ServerName, WindowsVersion,
# WindowsBuild, TotalRamBytes, Disks[{Name,TotalBytes,FreeBytes}]. Default is
# read-only CIM. Inject in tests; never accept scriptblocks from an HTTP client.
# JvmEvidence: trusted backend observations [{Version,Verified(bool),
# ExecutionVerified(bool)}]. ExecutionVerified requires an observed version probe
# or equivalent runtime evidence; detection alone never proves execution.
# Actions: trusted backend [{Kind: Update|Mitigation|Backup|Restore,
# Status: NotPerformed|Unknown|Failed|Proven, Verified(bool), FromVersion,
# ToVersion, BackupVersion, BackupVerified(bool)}]. Verified means independently
# checked postcondition, NOT user intent or process exit alone. BackupVerified
# requires archive/content validation. Versions describe evidence, not promises.
# JVM Classification: PotentiallyVulnerable|NotAffected|Fixed|Unknown, with
# ClassificationVerified(bool) and EvidenceCode AdvisoryRangeMatch|
# AdvisoryExcludesVersion|AdvisoryFixedVersion. No version ranges are inferred here.
# Actions require RuntimeIndex (1-based position in JvmEvidence), EvidenceVerified
# (bool), and EvidenceCode: EffectiveJvmFlagObserved (effective running JVM flag),
# InstalledRuntimeValidated (installed manifest + version probe),
# BackupManifestMatched (archive compared with original), OriginalRuntimeRestored
# (restored manifest + version probe), or DownloadFailed|ValidationFailed|
# RestoreFailed|OperationCancelled. Free-text explanations are never accepted.
# Proven requires the kind-specific positive code, boolean evidence proof and a
# valid JVM association; legacy success flags alone now downgrade to Unknown.
# Caller must map scanner/update results explicitly; their schemas are not assumed.
# EloVersionAdapter: optional trusted scriptblock -> {Verified(bool),Version}.
# Only use after independently validating an installation-specific official API
# contract. This module supplies NO live adapter and never accepts credentials.
# Only allowlisted fields are retained. Do not pass raw logs, paths, identities,
# URLs or secrets. Identifiers themselves must be safe backend observations.
# HTML renderer re-normalizes its input; raw diagnostics are never serialized.
# S10: verified Temurin enables same-provider download/install guidance.
# Verified Azul Zulu identifies the provider without asserting a fixed release;
# other or unverified vendors stay Unknown.
# Mitigation EvidenceCode additionally accepts MachineOptionSet (machine option
# read back), NewlyLaunchedJvmFlagVerified (effective flag in a new JVM probe),
# RunningEloJvmFlagVerified (effective flag in the identified current ELO JVM).
# These are independent scopes: no scope implies another. Verified means only
# the named postcondition, never a permanent fix or a runtime installation.
# Legacy EffectiveJvmFlagObserved has unspecified scope, NOT proof about ELO.
# No process IDs, command lines or environment dumps are retained.

function ConvertTo-EloReportEscapedText {
    param([AllowNull()][object]$Value)
    ([string]$Value).Replace('&','&amp;').Replace('<','&lt;').Replace('>','&gt;').Replace('"','&quot;').Replace("'",'&#39;')
}
function Get-EloReportVersion {
    param($Value)
    if ($Value -is [string] -and $Value.Length -le 64 -and $Value -cmatch '^\d{1,8}(?:[._+\-]\d{1,8}){0,7}(?:-ea|-LTS)?$') { return $Value }
    return $null
}
function Test-EloReportProof {
    param($Value)
    return ($Value -is [bool] -and $Value)
}
function Get-EloReportBytes {
    param($Value)
    # Reject strings, NaN, negative, fractional, and implausibly large values.
    if ($Value -isnot [ValueType]) { return $null }
    try {
        $n = [decimal]$Value
        if ($n -ge 0 -and $n -le 1152921504606846976 -and [decimal]::Truncate($n) -eq $n) { return $n }
    } catch { }
    return $null
}
function Get-EloReportWindowsResources {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $computer = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    $disks = @(Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction Stop | ForEach-Object {
        @{Name=$_.DeviceID;TotalBytes=$_.Size;FreeBytes=$_.FreeSpace}
    })
    @{ServerName=$computer.Name;WindowsVersion=$os.Version;WindowsBuild=$os.BuildNumber;TotalRamBytes=$computer.TotalPhysicalMemory;Disks=$disks}
}
# Collectors and recovery evidence are trusted backend-only inputs, never HTTP input.
# Recovery paths require a validated archive matched to the original runtime, and
# an independently selected isolated destination. No filesystem access occurs here.
function Get-EloMitigationOptionForReport {
    $v=Get-EloActiveVulnerabilities | Where-Object { Get-EloVulnAction $_ 'jvm-option' } | Select-Object -First 1
    if (-not $v) { return '' }
    return [string](Get-EloVulnAction $v 'jvm-option').option
}
function Get-EloReportOptionState {
    param($Value)
    if ($null -eq $Value -or $Value -ceq '') { return 'Absent' }
    if ($Value -isnot [string]) { return 'Unknown' }
    # The mitigation option and the flag it controls come from the catalog (vulndb.json).
    $option=[string](Get-EloMitigationOptionForReport)
    $flag=[regex]::Escape([string]((Get-EloVulnAction (Get-EloActiveVulnerabilities | Where-Object { Get-EloVulnAction $_ 'jvm-option' } | Select-Object -First 1) 'jvm-option').conflictPattern))
    $minus=[regex]::IsMatch($Value, '(?<!\S)'+[regex]::Escape($option)+'(?!\S)')
    $plus=[regex]::IsMatch($Value, '(?<!\S)-XX:\+'+$flag+'(?!\S)')
    if ($plus) { return 'Conflict' }
    if ($minus) { return 'Present' }
    return 'Absent'
}
function Test-EloReportRecoveryPath {
    param($Path)
    return ($Path -is [string] -and $Path.Length -le 1024 -and $Path -cmatch '^[A-Za-z]:\\[^\x00-\x1f\x7f"<>|?*/:]+$' -and $Path -notmatch '(^|\\)\.{1,2}(\\|$)' -and $Path -notmatch '[\r\n]')
}
function Get-EloInstalledIndexserverVersion {
    # Read-only: the installed ELO Indexserver announces its build in
    # <ELO root>\servers\<instance>\webapps\ix-<repository>\version.txt (first line that starts with
    # a 25.00.010.476816-style number). No credentials, no network, no service call. Bounded:
    # at most 20 instances and 20 webapps per root, files of at most 8 MiB read as a stream until the first version line. Returns the highest or $null.
    param([string[]]$EloRoots)
    $best=$null; $bestParts=$null
    foreach ($root in @($EloRoots | Where-Object { $_ } | Select-Object -Unique -First 8)) {
        try {
            $servers=Join-Path $root 'servers'
            if (-not [IO.Directory]::Exists($servers)) { continue }
            foreach ($instance in @([IO.Directory]::GetDirectories($servers) | Select-Object -First 20)) {
                $webapps=Join-Path $instance 'webapps'
                if (-not [IO.Directory]::Exists($webapps)) { continue }
                foreach ($app in @([IO.Directory]::GetDirectories($webapps,'ix-*') | Select-Object -First 20)) {
                    $file=Join-Path $app 'version.txt'
                    $info=New-Object IO.FileInfo($file)
                    if (-not $info.Exists -or $info.Length -gt 8388608 -or ($info.Attributes -band [IO.FileAttributes]::ReparsePoint)) { continue }
                    foreach ($line in [IO.File]::ReadLines($file)) {
                        if ($line -cmatch '^(\d{2}\.\d{2}\.\d{3}\.\d{1,9})(\s|$)') {
                            $parts=@($Matches[1].Split('.') | ForEach-Object { [int64]$_ })
                            $newer=($null -eq $best)
                            if (-not $newer) { for ($i=0; $i -lt 4; $i++) { if ($parts[$i] -ne $bestParts[$i]) { $newer=($parts[$i] -gt $bestParts[$i]); break } } }
                            if ($newer) { $best=$Matches[1]; $bestParts=$parts }
                            break
                        }
                    }
                }
            }
        } catch { }
    }
    return $best
}
function New-EloTechnicalReport {
    param(
        [scriptblock]$ResourceCollector = { Get-EloReportWindowsResources },
        [object[]]$JvmEvidence = @(),
        [object[]]$Actions = @(),
        [scriptblock]$EloVersionAdapter,
        [scriptblock]$OptionsCollector = { @{Machine=[Environment]::GetEnvironmentVariable('JAVA_TOOL_OPTIONS','Machine');User=[Environment]::GetEnvironmentVariable('JAVA_TOOL_OPTIONS','User');Process=[Environment]::GetEnvironmentVariable('JAVA_TOOL_OPTIONS','Process')} },
        $RecoveryEvidence
    )
    $system = @{Status='Unknown';ServerName=$null;WindowsVersion=$null;WindowsBuild=$null;TotalRamBytes=$null;Disks=@()}
    try {
        $raw = & $ResourceCollector
        if ($null -ne $raw) {
            if ($raw.ServerName -is [string] -and $raw.ServerName -cmatch '^[A-Za-z0-9][A-Za-z0-9.-]{0,62}$') { $system.ServerName=$raw.ServerName }
            $system.WindowsVersion=Get-EloReportVersion $raw.WindowsVersion
            if ([string]$raw.WindowsBuild -cmatch '^\d{1,10}$') { $system.WindowsBuild=[string]$raw.WindowsBuild }
            $system.TotalRamBytes=Get-EloReportBytes $raw.TotalRamBytes
            foreach ($disk in @($raw.Disks)) {
                $total=Get-EloReportBytes $disk.TotalBytes; $free=Get-EloReportBytes $disk.FreeBytes
                if ($disk.Name -cmatch '^[A-Z]:$' -and $null -ne $total -and $null -ne $free -and $free -le $total) {
                    $system.Disks+=@{Name=$disk.Name;TotalBytes=$total;FreeBytes=$free}
                }
            }
            if ($null -ne $system.ServerName -and $null -ne $system.WindowsVersion -and $null -ne $system.WindowsBuild -and $null -ne $system.TotalRamBytes -and $system.Disks.Count -gt 0) { $system.Status='Proven' }
        }
    } catch { $system.Status='Failed' }
    $jvms=@()
    foreach ($jvm in $JvmEvidence) {
        $version=$null
        if (Test-EloReportProof $jvm.Verified) { $version=Get-EloReportVersion $jvm.Version }
        $state='Unknown'; if ($null -ne $version) { $state='Proven' }
        $execution='Unknown'
        if ($state -eq 'Proven' -and (Test-EloReportProof $jvm.ExecutionVerified)) { $execution='Proven' }
        $classification='Unknown'; $evidence='Unknown'
        $classCodes=@{PotentiallyVulnerable='AdvisoryRangeMatch';NotAffected='AdvisoryExcludesVersion';Fixed='AdvisoryFixedVersion'}
        if ($jvm.Vendor -cne 'Azul Zulu' -and $state -eq 'Proven' -and (Test-EloReportProof $jvm.ClassificationVerified) -and $jvm.Classification -is [string] -and $classCodes.ContainsKey($jvm.Classification) -and $jvm.EvidenceCode -ceq $classCodes[$jvm.Classification]) {
            $classification=$jvm.Classification; $evidence=$jvm.EvidenceCode
        }
        $vendor='Unknown'
        if (@('Temurin','Azul Zulu') -ccontains $jvm.Vendor -and (Test-EloReportProof $jvm.VendorVerified)) { $vendor=$jvm.Vendor }
        $jvms+=@{RuntimeIndex=($jvms.Count+1);Status=$state;Version=$version;ExecutionStatus=$execution;Classification=$classification;ClassificationVerified=($classification -ne 'Unknown');EvidenceCode=$evidence;Vendor=$vendor;VendorVerified=($vendor -cne 'Unknown')}
    }
    $normalized=@()
    foreach ($kind in @('Update','Mitigation','Backup','Restore')) {
        $entries=@($Actions | Where-Object { $_.Kind -ceq $kind })
        if ($entries.Count -eq 0) { $entries=@(@{Status='NotPerformed'}) }
        foreach ($entry in $entries) {
            $state='Unknown'
            if (@('NotPerformed','Unknown','Failed','Proven') -ccontains $entry.Status) { $state=$entry.Status }
            if ($state -eq 'Proven' -and -not (Test-EloReportProof $entry.Verified)) { $state='Unknown' }
            if ($state -eq 'Proven' -and $kind -eq 'Backup' -and -not (Test-EloReportProof $entry.BackupVerified)) { $state='Unknown' }
            $index=$null
            if (($entry.RuntimeIndex -is [int] -or $entry.RuntimeIndex -is [long]) -and $entry.RuntimeIndex -ge 1 -and $entry.RuntimeIndex -le $jvms.Count) { $index=[int]$entry.RuntimeIndex }
            $proofCodes=@{Mitigation='EffectiveJvmFlagObserved';Update='InstalledRuntimeValidated';Backup='BackupManifestMatched';Restore='OriginalRuntimeRestored'}
            $evidence='Unknown'
            $mitigationCodes=@('EffectiveJvmFlagObserved','MachineOptionSet','NewlyLaunchedJvmFlagVerified','RunningEloJvmFlagVerified')
            $codes=@('InstalledRuntimeValidated','BackupManifestMatched','OriginalRuntimeRestored','DownloadFailed','ValidationFailed','RestoreFailed','OperationCancelled') + $mitigationCodes
            if ((Test-EloReportProof $entry.EvidenceVerified) -and $codes -ccontains $entry.EvidenceCode) { $evidence=$entry.EvidenceCode }
            $matchingProof=($evidence -ceq $proofCodes[$kind])
            if ($kind -eq 'Mitigation') { $matchingProof=($mitigationCodes -ccontains $evidence) }
            if ($state -eq 'Proven' -and ($null -eq $index -or -not $matchingProof)) { $state='Unknown' }
            # Never attach positive postcondition evidence to a non-proven outcome.
            if ($state -ne 'Proven' -and ($proofCodes.Values -ccontains $evidence -or $mitigationCodes -ccontains $evidence)) { $evidence='Unknown' }
            $action=@{RuntimeIndex=$index;Kind=$kind;Status=$state;Verified=($state -eq 'Proven');EvidenceCode=$evidence;EvidenceVerified=($evidence -ne 'Unknown');BackupVerified=($state -eq 'Proven' -and $kind -eq 'Backup');FromVersion=$null;ToVersion=$null;BackupVersion=$null}
            if ($state -eq 'Proven') {
                $action.FromVersion=Get-EloReportVersion $entry.FromVersion
                if ($kind -eq 'Update' -or $kind -eq 'Restore') { $action.ToVersion=Get-EloReportVersion $entry.ToVersion }
                if ($kind -eq 'Backup') { $action.BackupVersion=Get-EloReportVersion $entry.BackupVersion }
            }
            $normalized+=$action
        }
    }
    $elo=@{Status='Unknown';Version=$null;MissingContract='Official installation-specific endpoint, authentication method, version operation and response schema are not verified. Java Client IXConnectionIF getVersion/getImplVersion does not establish a universal REST contract.'}
    if ($null -ne $EloVersionAdapter) {
        try {
            $value=& $EloVersionAdapter
            if (Test-EloReportProof $value.Verified) {
                $elo.Version=Get-EloReportVersion $value.Version
                if ($null -ne $elo.Version) { $elo.Status='Proven';$elo.MissingContract=$null }
            }
        } catch { $elo.Status='Failed' }
    }
    $options=@{Machine='Unknown';User='Unknown';Process='Unknown'}
    foreach ($scope in @('Machine','User','Process')) {
        try { $rawOptions=& $OptionsCollector $scope; if ($null -ne $rawOptions) { $options[$scope]=Get-EloReportOptionState $rawOptions[$scope] } } catch { }
    }
    $recovery=@{Available=$false;Archive=$null;Original=$null;Destination=$null}
    $failedUpdates=@($normalized | Where-Object { $_.Kind -eq 'Update' -and $_.Status -eq 'Failed' -and $null -ne $_.RuntimeIndex })
    $backups=@($normalized | Where-Object { $_.Kind -eq 'Backup' -and $_.Status -eq 'Proven' -and $_.RuntimeIndex -eq $RecoveryEvidence.RuntimeIndex })
    if ((Test-EloReportProof $RecoveryEvidence.Validated) -and $backups.Count -gt 0 -and (Test-EloReportRecoveryPath $RecoveryEvidence.Archive) -and (Test-EloReportRecoveryPath $RecoveryEvidence.Original) -and (Test-EloReportRecoveryPath $RecoveryEvidence.Destination) -and $RecoveryEvidence.Archive -match '(?i)\.zip$' -and $RecoveryEvidence.Destination -ine $RecoveryEvidence.Original -and -not $RecoveryEvidence.Destination.StartsWith($RecoveryEvidence.Original.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase) -and -not $RecoveryEvidence.Original.StartsWith($RecoveryEvidence.Destination.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)) {
        $recovery=@{Available=$true;Validated=$true;RuntimeIndex=$RecoveryEvidence.RuntimeIndex;Archive=$RecoveryEvidence.Archive;Original=$RecoveryEvidence.Original;Destination=$RecoveryEvidence.Destination}
    }
    @{System=$system;Jvms=$jvms;Actions=$normalized;Elo=$elo;Options=$options;Recovery=$recovery}
}
function ConvertTo-EloTechnicalReportHtml {
    param([Parameter(Mandatory=$true)]$Report, [ValidateSet('en','de')][string]$Language='en')
    # Normalize again: renderer never reflects arbitrary DTO fields or messages.
    $r=New-EloTechnicalReport -OptionsCollector { $null } -ResourceCollector { $Report.System }.GetNewClosure() -JvmEvidence @($Report.Jvms | ForEach-Object { @{Version=$_.Version;Verified=($_.Status -ceq 'Proven');ExecutionVerified=($_.ExecutionStatus -ceq 'Proven');Classification=$_.Classification;ClassificationVerified=$_.ClassificationVerified;EvidenceCode=$_.EvidenceCode;Vendor=$_.Vendor;VendorVerified=$_.VendorVerified} }) -Actions $Report.Actions -EloVersionAdapter { @{Version=$Report.Elo.Version;Verified=($Report.Elo.Status -ceq 'Proven')} }.GetNewClosure()
    # DTO contains only bounded states; never re-read environment during rendering.
    foreach ($scope in @('Machine','User','Process')) { if (@('Present','Absent','Conflict','Unknown') -ccontains $Report.Options[$scope]) { $r.Options[$scope]=$Report.Options[$scope] } }
    if ($Report.System.Status -ceq 'Failed') { $r.System.Status='Failed' }
    if ($Report.Elo.Status -ceq 'Failed') { $r.Elo.Status='Failed' }
    $t=@{Title='Technical report';Server='Server';Windows='Windows version / build';Ram='Total RAM';Disk='Disk: total / free';Jvm='Detected JVM versions';Execution='Execution evidence';Elo='ELO version (installed Indexserver files)';Unknown='Unknown / unavailable';Failed='Failed';NotPerformed='Not performed';Proven='Verified';Update='Runtime update';Mitigation='Temporary mitigation';Backup='Backup';Restore='Restore';From='Previous version';To='Verified resulting version';BackupVersion='Verified backup JVM version';Sources='Official information sources';Notice='States reflect supplied verified evidence only. Compatibility, vulnerability and successful remediation are not inferred. No credentials or raw diagnostics are included.';Missing='Missing official installation-specific endpoint, authentication method, version operation and response schema. Java Client IXConnectionIF getVersion/getImplVersion is not a universal REST API contract.'}
    if ($Language -eq 'de') {
        $t=@{Title='Technischer Bericht';Server='Server';Windows='Windows-Version / Build';Ram='Gesamter RAM';Disk='Datentraeger: gesamt / frei';Jvm='Erkannte JVM-Versionen';Execution='Ausfuehrungsnachweis';Elo='ELO-Version (installierte Indexserver-Dateien)';Unknown='Unbekannt / nicht verfuegbar';Failed='Fehlgeschlagen';NotPerformed='Nicht ausgefuehrt';Proven='Nachgewiesen';Update='Runtime-Aktualisierung';Mitigation='Vorlaeufige Risikominderung';Backup='Sicherung';Restore='Wiederherstellung';From='Vorherige Version';To='Nachgewiesene Ergebnisversion';BackupVersion='Nachgewiesene JVM-Version der Sicherung';Sources='Offizielle Informationsquellen';Notice='Statusangaben beruhen nur auf uebergebenen Nachweisen. Kompatibilitaet, Verwundbarkeit und erfolgreiche Behebung werden nicht abgeleitet. Keine Zugangsdaten oder Rohdiagnosen enthalten.';Missing='Offizieller installationsspezifischer Endpunkt, Authentifizierungsmethode, Versionsoperation und Antwortschema fehlen. Java Client IXConnectionIF getVersion/getImplVersion ist kein universeller REST-API-Vertrag.'}
    }
    $facts=@{Classification='Vulnerability classification';Evidence='Evidence / method';Association='Runtime association';PotentiallyVulnerable='Potentially vulnerable';NotAffected='Not affected by the matched advisory';Fixed='Fixed version according to matched advisory';AdvisoryRangeMatch='Matched advisory affected-version range';AdvisoryExcludesVersion='Advisory excludes observed version';AdvisoryFixedVersion='Observed version matches advisory fixed release';EffectiveJvmFlagObserved='Effective JVM flag verified';InstalledRuntimeValidated='Installed runtime manifest and version probe verified';BackupManifestMatched='Backup contents matched original manifest';OriginalRuntimeRestored='Original runtime restored and verified';DownloadFailed='Download failed';ValidationFailed='Postcondition validation failed';RestoreFailed='Restoration failed; manual recovery required';OperationCancelled='Operation cancelled';Checked='Source verification date';Fetched='Fetched by parent';Supplied='User-supplied text; site access returned HTTP 403; not independently fetched';Changes='Advisories may change. Source access does not prove applicability or successful remediation.'}
    if ($Language -eq 'de') {
        $facts=@{Classification='Verwundbarkeitsklassifizierung';Evidence='Nachweis / Methode';Association='Runtime-Zuordnung';PotentiallyVulnerable='Potenziell verwundbar';NotAffected='Laut zugeordnetem Hinweis nicht betroffen';Fixed='Korrigierte Version laut zugeordnetem Hinweis';AdvisoryRangeMatch='Betroffene Versionsspanne des Hinweises stimmt ueberein';AdvisoryExcludesVersion='Hinweis schliesst erkannte Version aus';AdvisoryFixedVersion='Erkannte Version entspricht korrigierter Ausgabe laut Hinweis';EffectiveJvmFlagObserved='Wirksames JVM-Flag nachgewiesen';InstalledRuntimeValidated='Installiertes Runtime-Manifest und Versionsprobe nachgewiesen';BackupManifestMatched='Sicherungsinhalt stimmt mit urspruenglichem Manifest ueberein';OriginalRuntimeRestored='Urspruengliche Runtime wiederhergestellt und geprueft';DownloadFailed='Download fehlgeschlagen';ValidationFailed='Pruefung der Nachbedingung fehlgeschlagen';RestoreFailed='Wiederherstellung fehlgeschlagen; manuelle Wiederherstellung erforderlich';OperationCancelled='Vorgang abgebrochen';Checked='Pruefdatum der Quellen';Fetched='Vom uebergeordneten Agenten abgerufen';Supplied='Vom Benutzer bereitgestellter Text; Seitenzugriff HTTP 403; nicht unabhaengig abgerufen';Changes='Hinweise koennen sich aendern. Quellenzugriff beweist weder Anwendbarkeit noch erfolgreiche Behebung.'}
    }
    foreach ($key in $facts.Keys) { $t[$key]=$facts[$key] }
    $guidance=@{Vendor='Verified JVM vendor';Recommendation='Recommended next step';Temporary='Flag-only temporary mitigation; does not install a Java runtime and is not a permanent fix. A machine option does not prove that a newly launched JVM or the current ELO process uses the flag.';Upgrade='Prefer installing a newer vendor-fixed Java release after ELO compatibility confirmation. No particular fixed version or successful installation is inferred.';VendorUnknown='JVM vendor unknown; consult your JVM vendor and ELO for the appropriate fixed release and official download/install instructions. Temurin is not assumed to be a same-provider replacement.';Download='Official Temurin downloads';Install='Official Temurin installation instructions';MachineOptionSet='Machine option set';NewlyLaunchedJvmFlagVerified='Newly launched JVM flag';RunningEloJvmFlagVerified='Current running ELO process flag';EffectiveJvmFlagObserved='JVM flag observed; scope unspecified, current ELO process not verified'}
    if ($Language -eq 'de') {
        $guidance=@{Vendor='Nachgewiesener JVM-Anbieter';Recommendation='Empfohlener naechster Schritt';Temporary='Nur vorlaeufige Flag-Risikominderung; installiert keine Java-Runtime und ist keine dauerhafte Behebung. Eine Maschinenoption beweist nicht, dass eine neu gestartete JVM oder der aktuelle ELO-Prozess das Flag verwendet.';Upgrade='Vorzugsweise eine neuere, vom Anbieter korrigierte Java-Version nach ELO-Kompatibilitaetsbestaetigung installieren. Keine bestimmte korrigierte Version oder erfolgreiche Installation wird abgeleitet.';VendorUnknown='JVM-Anbieter unbekannt; JVM-Anbieter und ELO konsultieren, um die passende korrigierte Version und offizielle Download-/Installationsanleitungen zu erhalten. Temurin wird nicht als Ersatz desselben Anbieters angenommen.';Download='Offizielle Temurin-Downloads';Install='Offizielle Temurin-Installationsanleitung';MachineOptionSet='Maschinenoption gesetzt';NewlyLaunchedJvmFlagVerified='Flag einer neu gestarteten JVM';RunningEloJvmFlagVerified='Flag des aktuell laufenden ELO-Prozesses';EffectiveJvmFlagObserved='JVM-Flag beobachtet; Umfang unbekannt, aktueller ELO-Prozess nicht nachgewiesen'}
    }
    foreach ($key in $guidance.Keys) { $t[$key]=$guidance[$key] }
    $lines=New-Object 'System.Collections.Generic.List[string]'
    $lines.Add('<!doctype html><html lang="'+$Language+'"><head><meta charset="utf-8"><title>'+$t.Title+'</title></head><body><h1>'+$t.Title+'</h1>')
    $lines.Add('<p>'+$t.Notice+'</p><dl>')
    $rows=@(@($t.Server,$r.System.ServerName),@($t.Windows,($r.System.WindowsVersion+' / '+$r.System.WindowsBuild)))
    foreach ($row in $rows) {
        $v=$row[1]; if ([string]::IsNullOrWhiteSpace(($v -replace '[ /]',''))) { $v=$t.Unknown }
        $lines.Add('<dt>'+$row[0]+'</dt><dd>'+(ConvertTo-EloReportEscapedText $v)+'</dd>')
    }
    $ram=$t.Unknown
    if ($null -ne $r.System.TotalRamBytes) { $ram=([double]$r.System.TotalRamBytes / 1GB).ToString('F2',[Globalization.CultureInfo]::InvariantCulture)+' GiB' }
    $lines.Add('<dt>'+$t.Ram+'</dt><dd>'+$ram+' ('+$t[$r.System.Status]+')</dd>')
    if ($r.System.Disks.Count -eq 0) { $lines.Add('<dt>'+$t.Disk+'</dt><dd>'+$t.Unknown+'</dd>') }
    foreach ($d in $r.System.Disks) {
        $space=([double]$d.TotalBytes/1GB).ToString('F2',[Globalization.CultureInfo]::InvariantCulture)+' GiB / '+([double]$d.FreeBytes/1GB).ToString('F2',[Globalization.CultureInfo]::InvariantCulture)+' GiB'
        $lines.Add('<dt>'+$t.Disk+'</dt><dd>'+(ConvertTo-EloReportEscapedText $d.Name)+' '+$space+'</dd>')
    }
    $lines.Add('<dt>'+$t.Elo+'</dt><dd>'+$t[$r.Elo.Status]+' '+(ConvertTo-EloReportEscapedText $r.Elo.Version)+'</dd>')
    $lines.Add('</dl>')
    if ($r.Elo.Status -ne 'Proven') { $lines.Add('<p>'+$t.Missing+'</p>') }
    $lines.Add('<h2>'+$t.Jvm+'</h2><ul>')
    if ($r.Jvms.Count -eq 0) { $lines.Add('<li>'+$t.Unknown+'</li>') }
    foreach ($j in $r.Jvms) { $lines.Add('<li>JVM #'+$j.RuntimeIndex+': '+$t[$j.Status]+' '+(ConvertTo-EloReportEscapedText $j.Version)+'; '+$t.Execution+': '+$t[$j.ExecutionStatus]+'; '+$t.Classification+': '+(ConvertTo-EloReportEscapedText $t[$j.Classification])+'; '+$t.Evidence+': '+(ConvertTo-EloReportEscapedText $t[$j.EvidenceCode])+'</li>') }
    $lines.Add('</ul><h2>'+$t.Recommendation+'</h2><p>'+$t.Temporary+'</p><p>'+$t.Upgrade+'</p><ul>')
    if ($r.Jvms.Count -eq 0) { $lines.Add('<li>'+$t.VendorUnknown+'</li>') }
    foreach ($j in $r.Jvms) {
        $advice=$t.VendorUnknown
        if ($j.Vendor -eq 'Temurin') {
            $advice=$t.Vendor+': Temurin; <a href="https://adoptium.net/temurin/releases">'+$t.Download+'</a>; <a href="https://adoptium.net/installation/">'+$t.Install+'</a>'
        } elseif ($j.Vendor -ceq 'Azul Zulu') {
            $advice=$t.Vendor+': Azul Zulu; <a href="https://www.azul.com/downloads/?os=windows&amp;package=jdk">'+$t.Download+'</a>; <a href="https://docs.azul.com/core/install/windows">'+$t.Install+'</a>. '+$t.Upgrade
        }
        $lines.Add('<li>JVM #'+$j.RuntimeIndex+': '+$advice+'</li>')
    }
    $lines.Add('</ul><h2>'+$t.Update+' / '+$t.Mitigation+' / '+$t.Backup+' / '+$t.Restore+'</h2><ul>')
    foreach ($a in $r.Actions) {
        $association=$t.Unknown
        if ($null -ne $a.RuntimeIndex) { $association='JVM #'+$a.RuntimeIndex }
        $detail='; '+$t.Association+': '+$association+'; '+$t.Evidence+': '+(ConvertTo-EloReportEscapedText $t[$a.EvidenceCode])
        foreach ($key in @('FromVersion','ToVersion','BackupVersion')) {
            if ($a[$key]) {
                $label=$t.BackupVersion; if ($key -eq 'FromVersion') { $label=$t.From }; if ($key -eq 'ToVersion') { $label=$t.To }
                $detail+='; '+$label+': '+(ConvertTo-EloReportEscapedText $a[$key])
            }
        }
        if ($a.Kind -eq 'Mitigation') {
            foreach ($scope in @('MachineOptionSet','NewlyLaunchedJvmFlagVerified','RunningEloJvmFlagVerified')) {
                $scopeState='Unknown'
                if ($a.Status -eq 'Proven' -and $a.EvidenceCode -ceq $scope) { $scopeState='Proven' }
                $detail+='; '+$t[$scope]+': '+$t[$scopeState]
            }
            if ($a.Status -eq 'Proven') { $detail+='; '+(Get-EloMitigationOptionForReport) }
        }
        $lines.Add('<li>'+$t[$a.Kind]+': '+$t[$a.Status]+$detail+'</li>')
    }
    $lines.Add('</ul><h2>JAVA_TOOL_OPTIONS</h2><ul>')
    $optionLabels=@{Present='Flag present';Absent='Flag absent';Conflict='Conflicting enabling flag present';Unknown='Unknown / unavailable'}
    if ($Language -eq 'de') { $optionLabels=@{Present='Flag vorhanden';Absent='Flag nicht vorhanden';Conflict='Konfligierendes aktivierendes Flag vorhanden';Unknown='Unbekannt / nicht verfuegbar'} }
    foreach ($scope in @('Machine','User','Process')) { $lines.Add('<li>'+$scope+': '+$optionLabels[$r.Options[$scope]]+'</li>') }
    if ($Language -eq 'de') { $lines.Add('</ul><p>Umgebungswerte beweisen keinen Schutz bestehender ELO-Prozesse.</p>') } else { $lines.Add('</ul><p>Environment values do not prove protection of existing ELO processes.</p>') }
    if (@($r.Actions | Where-Object { $_.Kind -eq 'Update' -and $_.Status -eq 'Failed' }).Count -gt 0 -or @($r.Actions | Where-Object { $_.Kind -eq 'Backup' -and $_.Status -eq 'Proven' }).Count -gt 0) {
        if ($Language -eq 'de') { $lines.Add('<h2>Manuelle Wiederherstellung</h2><p>Falls die Aktualisierung fehlschlaegt oder die alte Java-Version wieder benoetigt wird: ELO-Dienste und Java-Prozesse beenden, neue Runtime entfernen und die gesicherte Version aus dem Backup-ZIP zurueckspielen. Backup-ZIP und alte Runtime werden von diesem Werkzeug nie geloescht.</p>') }
        else { $lines.Add('<h2>Manual recovery</h2><p>If the update fails, or the previous Java version is needed again: stop the ELO services and Java processes, remove the new runtime and restore the saved version from the backup ZIP. This tool never deletes the backup ZIP or the old runtime.</p>') }
        # Revalidate the trusted evidence against the normalized actions before rendering.
        $rr=New-EloTechnicalReport -ResourceCollector { $null } -OptionsCollector { $null } -JvmEvidence @($Report.Jvms | ForEach-Object { @{Version=$_.Version;Verified=($_.Status -ceq 'Proven')} }) -Actions $Report.Actions -RecoveryEvidence $Report.Recovery
        if ($rr.Recovery.Available) {
            $rec=$rr.Recovery
            $q={ param($s) "'"+$s.Replace("'","''")+"'" }
            $cmd=@('# PowerShell (run as administrator)',
                'Remove-Item -LiteralPath '+(& $q $rec.Original)+' -Recurse -Force',
                'Expand-Archive -LiteralPath '+(& $q $rec.Archive)+' -DestinationPath '+(& $q $rec.Destination),
                'Move-Item -LiteralPath '+(& $q ($rec.Destination.TrimEnd('\')+'\tree'))+' -Destination '+(& $q $rec.Original),
                '',
                'REM cmd.exe (run as administrator)',
                'rmdir /s /q "'+$rec.Original+'"',
                'mkdir "'+$rec.Destination+'"',
                'tar -xf "'+$rec.Archive+'" -C "'+$rec.Destination+'"',
                'move "'+$rec.Destination.TrimEnd('\')+'\tree" "'+$rec.Original+'"') -join "`r`n"
            $lines.Add('<p>Original: '+(ConvertTo-EloReportEscapedText $rec.Original)+'</p><p>ZIP: '+(ConvertTo-EloReportEscapedText $rec.Archive)+'</p><pre>'+(ConvertTo-EloReportEscapedText $cmd)+'</pre>')
        } else { $lines.Add('<p>'+$t.Unknown+'</p>') }
    }
    $lines.Add('<h2>'+$t.Sources+'</h2><ul>')
    $lines.Add('<li>'+$t.Checked+': 2026-11-23. '+$t.Changes+'</li>')
    $sources=@()
    foreach ($v in (Get-EloActiveVulnerabilities)) { foreach ($adv in @($v.advisories)) { $label=[string]$adv.reportLabel; if (-not $label) { $label=[string]$adv.id }; $prov='Supplied'; if ([string]$adv.provenance -ceq 'Fetched') { $prov='Fetched' }; $sources+=,@($label,[string]$adv.url,$prov) } }
    foreach ($source in $sources) {
        $lines.Add('<li><a href="'+$source[1]+'">'+$source[0]+'</a> - '+$t[$source[2]]+'</li>')
    }
    $lines.Add('</ul></body></html>')
    return ($lines -join "`r`n")
}
::ELO_PATCH_END:REPORT_PS

::ELO_PATCH_BEGIN:UPDATE_PS
# Embeddable Windows PowerShell 5.1 module: dot-sourcing defines functions ONLY.
# Loading defines functions only. Windows adapters are opt-in; no service control
# or deletion. Production is unavailable: executable release/host/archive policy
# allowlist is EMPTY; API metadata alone is not approval. Live filesystem and
# quiescence proof is missing. Compatibility is not
# guaranteed: explicit risk acceptance is required. Adapters are trusted code.
#
# Backend seam (not wired into server.ps1): dot-source this packaged resource;
# New-EloUpdateContext; New-EloUpdatePreview; Invoke-EloRuntimeUpdate.
# For future production wiring: $adapters=New-EloWindowsUpdateAdapters
# -ApprovedRoot <explicitly selected local parent> -Runtime <selected runtime>;
# $context=New-EloUpdateContext -Adapters $adapters (NO -Simulation). This still
# rejects production; do not bypass the gate by using -Simulation with real IO.
# Pass each preview token to Invoke-EloRuntimeUpdate only AFTER the corresponding
# explicit user approval: -Confirmation, -BranchConfirmation (if requested), and
# -CompatibilityConfirmation (if requested). No route changes are made here.
# Keep Context server-side, serialize only preview/result, and obtain a fresh
# explicit confirmation through the authenticated backend. Never accept adapters,
# evidence, package metadata, or paths directly from an HTTP client.
#
# Adapter contract (all methods must throw on failure; predicates return bool):
# Clock -> UTC DateTime; Admin -> bool; Inspect(runtime) -> exact vendor, branch,
# architecture and whole-tree fingerprint (including ACLs; reject reparse points).
# Evidence(detected,package) -> Official, Compatibility, PublishedHash booleans:
# independently authenticate official HTTPS metadata and published SHA256, exact
# vendor/branch/architecture/version. Compatibility=false requires risk approval.
# Preflight(paths) -> SafePaths, Quiescent, Permissions, Space booleans: local
# disjoint paths on one volume; stage/old/download/ZIP must not exist; no ancestor
# reparse points; exclusive lock held through transaction, stopped runtime, full
# tree readable and writable, conservative space for ZIP+stage+old+recovery.
# Backup(paths) writes ZIP before mutation; VerifyBackup(paths,detected) reopens
# ZIP and compares every entry/hash/ACL manifest against the original tree.
# Download(package,paths) HTTPS only, no insecure redirects; VerifyPackage checks
# exact bytes against the independently authenticated published SHA256.
# Stage rejects ZIP traversal, links, duplicate entries and decompression bombs;
# extracts only into isolated staging and verifies full copy manifest.
# Probe(stage,package) runs ONLY staged bin\java.exe -version, bounded time/output,
# sanitized environment; checks exact detected vendor/version/architecture.
# Preserve(paths) same-volume rename runtime -> old, never overwrite old.
# Replace(paths) same-volume rename staged runtime -> runtime, never delete old.
# ValidateInstalled(paths,package) full manifest + bounded java -version probe.
# Restore(paths) must tolerate partially successful renames, preserve failed new
# tree, restore old (or verified ZIP), including ACLs, never delete recovery data.
# VerifyRestored(paths,detected) exact original manifest and java -version.
# Tests exercise mocks and memory-only helpers, NOT live integration proof.

# A Java 5-compatible console class, assembled in memory, with no libraries beyond
# the Java standard runtime. It exercises integer division and prints a marker.
# This is an inert payload: it is not written or executed by this module. In
# particular, it is NOT proof of ELO compatibility or of a safe replacement.
function Get-EloJavaSelfTestClass {
    $bytes=New-Object 'System.Collections.Generic.List[byte]'
    $add={ param([byte[]]$Data) $bytes.AddRange($Data) }
    $utf={ param([string]$Text)
        $encoded=[Text.Encoding]::ASCII.GetBytes($Text)
        $bytes.Add(1); $bytes.Add([byte]($encoded.Length -shr 8)); $bytes.Add([byte]($encoded.Length -band 255)); $bytes.AddRange($encoded)
    }
    & $add ([byte[]](0xca,0xfe,0xba,0xbe,0,0,0,49,0,22))
    & $utf 'EloJavaSelfTest'; & $add ([byte[]](7,0,1))
    & $utf 'java/lang/Object'; & $add ([byte[]](7,0,3))
    & $utf 'main'; & $utf '([Ljava/lang/String;)V'; & $utf 'Code'
    & $utf 'java/lang/System'; & $add ([byte[]](7,0,8))
    & $utf 'out'; & $utf 'Ljava/io/PrintStream;'
    & $add ([byte[]](12,0,10,0,11,9,0,9,0,12))
    & $utf 'java/io/PrintStream'; & $add ([byte[]](7,0,14))
    & $utf 'println'; & $utf '(Ljava/lang/String;)V'
    & $add ([byte[]](12,0,16,0,17,10,0,15,0,18))
    & $utf 'ELO_JAVA_SELF_TEST_OK'; & $add ([byte[]](8,0,20))
    # public class; public static main; 1/1, pop, println(marker), return.
    & $add ([byte[]](0,33,0,2,0,4,0,0,0,0,0,1,0,9,0,5,0,6,0,1,0,7,
        0,0,0,25,0,2,0,1,0,0,0,13,4,4,108,87,178,0,13,18,21,182,0,19,177,
        0,0,0,0,0,0))
    return ,$bytes.ToArray()
}
function Test-EloJavaSelfTestResult {
    param([int]$ExitCode,[string]$StandardOutput,[string]$StandardError)
    return ($ExitCode -eq 0 -and $StandardError -ceq '' -and
        ($StandardOutput -ceq "ELO_JAVA_SELF_TEST_OK`n" -or $StandardOutput -ceq "ELO_JAVA_SELF_TEST_OK`r`n"))
}

# Mockable orchestration only: adapters are trusted, nonblocking code. Start must
# create the unique directory exclusively, write the supplied class there and run
# only JavaPath with an isolated classpath and sanitized environment. Poll returns
# bounded incremental output; Stop terminates/reaps and retains session artifacts.
# No real adapter is provided: this function is not production safety proof.
function Invoke-EloJavaSelfTest {
    param([Parameter(Mandatory=$true)][string]$JavaPath,
        [Parameter(Mandatory=$true)][string]$SessionRoot,
        [Parameter(Mandatory=$true)][hashtable]$Adapter,
        [int]$TimeoutMilliseconds=10000,[int]$MaximumOutputCharacters=16384)
    if ($JavaPath -notmatch '^[A-Za-z]:\\[^\r\n"*?]+\\java\.exe$' -or $JavaPath -match '(^|\\)\.\.?($|\\)') { throw 'absolute_java_path_required' }
    if ($SessionRoot -notmatch '^[A-Za-z]:\\[^\r\n"*?]+$' -or $SessionRoot -match '(^|\\)\.\.?($|\\)') { throw 'absolute_session_root_required' }
    if ($TimeoutMilliseconds -lt 1 -or $TimeoutMilliseconds -gt 60000 -or $MaximumOutputCharacters -lt 1 -or $MaximumOutputCharacters -gt 65536) { throw 'invalid_self_test_limits' }
    foreach ($name in @('Clock','Start','Poll','Stop')) { if ($Adapter[$name] -isnot [scriptblock]) { throw "missing_self_test_adapter:$name" } }
    $request=@{JavaPath=$JavaPath;SessionPath=($SessionRoot.TrimEnd('\')+'\'+[guid]::NewGuid().ToString('N'));ClassBytes=(Get-EloJavaSelfTestClass)}
    $handle=$null; $started=$false; $output=New-Object Text.StringBuilder; $errorOutput=New-Object Text.StringBuilder
    try {
        $begin=& $Adapter.Clock
        $handle=& $Adapter.Start $request; $started=$true
        # Iteration cap also fails closed if a defective clock does not advance.
        for ($i=0; $i -lt 10000; $i++) {
            $now=& $Adapter.Clock
            if ($now -lt $begin -or ($now-$begin) -ge $TimeoutMilliseconds) { return @{Success=$false;Reason='timeout';SessionPath=$request.SessionPath} }
            $part=& $Adapter.Poll $handle
            $now=& $Adapter.Clock
            if ($now -lt $begin -or ($now-$begin) -ge $TimeoutMilliseconds) { return @{Success=$false;Reason='timeout';SessionPath=$request.SessionPath} }
            $chunkOut=[string]$part.Stdout; $chunkError=[string]$part.Stderr
            if (($output.Length+$errorOutput.Length+$chunkOut.Length+$chunkError.Length) -gt $MaximumOutputCharacters) { return @{Success=$false;Reason='output_limit';SessionPath=$request.SessionPath} }
            $null=$output.Append($chunkOut); $null=$errorOutput.Append($chunkError)
            if ($part.Done -isnot [bool]) { throw 'invalid_self_test_poll' }
            if ($part.Done) {
                $valid=($part.ExitCode -is [int] -and (Test-EloJavaSelfTestResult $part.ExitCode $output.ToString() $errorOutput.ToString()))
                return @{Success=[bool]$valid;Reason=$(if ($valid) { 'success' } else { 'invalid_result' });SessionPath=$request.SessionPath}
            }
        }
        return @{Success=$false;Reason='poll_limit';SessionPath=$request.SessionPath}
    } finally { if ($started) { $null=& $Adapter.Stop $handle } }
}

function Get-EloUpdateGaps {
    @('Supported: Eclipse Temurin and Azul Zulu, Windows x86/x64/ARM64, JDK or JRE of the same branch; the newest GA release is resolved from the vendor API at preview time. Other vendors are refused.',
      'Backups and restores cover content, owner, group and DACL; SACL (auditing) entries are not captured.',
      'Quiescence is checked fail-closed (no process or service with the runtime loaded, exclusive open of java binaries); services are stopped only with explicit confirmation and restarted afterwards. ELO compatibility is never assumed.')
}
function New-EloUpdateContext {
    param([hashtable]$Adapters=@{}, [switch]$Simulation, [switch]$Production)
    # Context is trusted backend state, not a wire representation. Production is
    # honoured only for the module's own Windows adapters (explicit marker), never
    # for caller-supplied scriptblocks, and never together with -Simulation.
    if ($Production -and ($Simulation -or $Adapters['EloWindowsAdapters'] -ne $true)) { throw 'production_requires_windows_adapters' }
    return @{ Adapters=$Adapters; Simulation=[bool]$Simulation; Production=[bool]$Production; Preview=$null; Busy=$false; RecoveryRequired=$false }
}
function Invoke-EloUpdateAdapter {
    param($Context,[string]$Name,[object[]]$Arguments=@())
    if (-not $Context.Adapters.ContainsKey($Name) -or $Context.Adapters[$Name] -isnot [scriptblock]) { throw "missing_adapter:$Name" }
    & $Context.Adapters[$Name] @Arguments
}
function Assert-EloUpdateTrue {
    param($Value,[string]$Code)
    if ($Value -isnot [bool] -or -not $Value) { throw $Code }
}
function Assert-EloUpdateMode {
    param($Context)
    if (-not $Context.Simulation -and -not $Context.Production) { throw ('production_update_disabled: ' + ((Get-EloUpdateGaps) -join ' ')) }
    if ($Context.Busy -or $Context.RecoveryRequired) { throw 'busy_or_manual_recovery_required' }
    Assert-EloUpdateTrue (Invoke-EloUpdateAdapter $Context Admin) 'administrator_required'
}
function Assert-EloUpdatePaths {
    param($Paths)
    $canonical=@()
    foreach ($key in @('Runtime','Old','Stage','Backup','Download')) {
        $path=[string]$Paths[$key]
        if ($path -cnotmatch '^[A-Za-z]:\\' -or $path -match '[\x00-\x1f\x7f"<>|?*/]' -or $path.Substring(2).Contains(':')) { throw 'unsafe_path' }
        foreach ($part in $path.Substring(3).Split('\')) {
            if ([string]::IsNullOrWhiteSpace($part) -or $part -match '[. ]$' -or $part -match '^(?i:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)') { throw 'unsafe_path' }
        }
        $full=[IO.Path]::GetFullPath($path)
        foreach ($prior in $canonical) {
            if ($full.Equals($prior,[StringComparison]::OrdinalIgnoreCase) -or
                $full.StartsWith($prior+'\',[StringComparison]::OrdinalIgnoreCase) -or
                $prior.StartsWith($full+'\',[StringComparison]::OrdinalIgnoreCase)) { throw 'overlapping_paths' }
        }
        if ($canonical.Count -gt 0 -and $full.Substring(0,2) -ine $canonical[0].Substring(0,2)) { throw 'same_volume_required' }
        $canonical+= $full
    }
    if ([string]$Paths.Backup -notmatch '(?i)\.zip$') { throw 'backup_zip_required' }
}
function Assert-EloUpdatePreflight {
    param($Context,$Paths)
    $checks=Invoke-EloUpdateAdapter $Context Preflight @($Paths)
    foreach ($key in @('SafePaths','Quiescent','Permissions','Space')) { Assert-EloUpdateTrue $checks[$key] "preflight_failed:$key" }
}
function Assert-EloUpdateEvidence {
    param($Context,$Detected,$Package)
    foreach ($key in @('Vendor','Branch','Architecture','Fingerprint')) {
        if ([string]::IsNullOrWhiteSpace([string]$Detected[$key]) -or $Detected[$key] -eq 'unknown') { throw "unknown_detected_identity:$key" }
    }
    foreach ($key in @('Vendor','Branch','Architecture')) {
        if ([string]$Detected[$key] -cne [string]$Package[$key]) { throw "package_identity_mismatch:$key" }
    }
    if ($Detected.ImageType -and $Package.ImageType -and [string]$Detected.ImageType -cne [string]$Package.ImageType) { throw 'package_identity_mismatch:ImageType' }
    if ($Package.Architecture -cnotin @('x86','x64','ARM64') -or [string]$Package.Branch -notmatch '^\d+$' -or
        [string]::IsNullOrWhiteSpace($Package.Version) -or $Package.Sha256 -cnotmatch '^[a-fA-F0-9]{64}$') { throw 'incomplete_package_identity' }
    $uri=$null
    if (-not [Uri]::TryCreate([string]$Package.Uri,[UriKind]::Absolute,[ref]$uri) -or $uri.Scheme -cne 'https' -or
        $uri.UserInfo -or $uri.Fragment -or -not $uri.IsDefaultPort) { throw 'official_https_required' }
    $evidence=Invoke-EloUpdateAdapter $Context Evidence @($Detected,$Package)
    foreach ($key in @('Official','PublishedHash')) { Assert-EloUpdateTrue $evidence[$key] "unverified_evidence:$key" }
    return ($evidence.Compatibility -is [bool] -and $evidence.Compatibility)
}
function New-EloUpdatePreview {
    param([Parameter(Mandatory=$true)]$Context,[Parameter(Mandatory=$true)][hashtable]$Paths,
        [Parameter(Mandatory=$true)][hashtable]$Package)
    # A new preview invalidates even an older valid confirmation.
    $Context.Preview=$null
    Assert-EloUpdateMode $Context
    Assert-EloUpdatePaths $Paths
    $pathsCopy=@{}; foreach ($key in @('Runtime','Old','Stage','Backup','Download')) { $pathsCopy[$key]=[string]$Paths[$key] }
    $packageCopy=@{}; foreach ($key in @('Vendor','Branch','Architecture','ImageType','Version','Uri','Sha256','Size')) { $packageCopy[$key]=[string]$Package[$key] }
    $detected=Invoke-EloUpdateAdapter $Context Inspect @($pathsCopy.Runtime)
    $compatible=Assert-EloUpdateEvidence $Context $detected $packageCopy
    Assert-EloUpdatePreflight $Context $pathsCopy
    $now=Invoke-EloUpdateAdapter $Context Clock
    if ($now -isnot [datetime]) { throw 'invalid_clock' }
    $branchChange=([string]$detected.Branch -cne $packageCopy.Branch)
    $confirmation=[guid]::NewGuid().ToString('N')
    $branchConfirmation=''; if ($branchChange) { $branchConfirmation=[guid]::NewGuid().ToString('N') }
    $identity=@{}; foreach ($key in @('Vendor','Branch','Architecture','Fingerprint')) { $identity[$key]=[string]$detected[$key] }; $identity.ImageType=[string]$detected.ImageType
    $compatibilityConfirmation=''; if (-not $compatible) { $compatibilityConfirmation=[guid]::NewGuid().ToString('N') }
    $Context.Preview=@{ Paths=$pathsCopy; Package=$packageCopy; Detected=$identity; Created=$now; Confirmation=$confirmation; BranchConfirmation=$branchConfirmation; CompatibilityConfirmation=$compatibilityConfirmation }
    return @{ Simulation=$Context.Simulation; Confirmation=$confirmation; BranchConfirmation=$branchConfirmation; CompatibilityConfirmation=$compatibilityConfirmation; Expires=$now.AddMinutes(5);
        Warning=$(if (-not $compatible) { 'ELO compatibility not confirmed. Updating can break ELO or invalidate vendor support. Explicit risk acceptance required. No services restarted; ZIP and old runtime retained.' } else { 'Explicit update approval required; branch changes need separate approval. No services restarted; ZIP and old runtime retained.' }) }
}
function Invoke-EloRuntimeUpdate {
    param([Parameter(Mandatory=$true)]$Context,[string]$Confirmation,[string]$BranchConfirmation,[string]$CompatibilityConfirmation)
    $preview=$Context.Preview
    $Context.Preview=$null # single-use even for rejected/stale requests
    $mutationAttempted=$false
    $locked=$false
    $resumeNeeded=$false; $quiesceState=$null
    $resume={
        # Restart whatever Quiesce stopped; exactly once, success or failure.
        if (-not $resumeNeeded) { return @{Restarted=$false;Error=$null} }
        try { $null=Invoke-EloUpdateAdapter $Context Resume @($preview.Paths,$quiesceState); return @{Restarted=$true;Error=$null} }
        catch { return @{Restarted=$false;Error=$_.Exception.Message} }
    }
    $hasQuiesce=($Context.Adapters.ContainsKey('Quiesce') -and $Context.Adapters.ContainsKey('Resume'))
    try {
        Assert-EloUpdateMode $Context
        if (-not $preview -or [string]::IsNullOrWhiteSpace($Confirmation) -or $Confirmation -cne $preview.Confirmation) { throw 'fresh_explicit_confirmation_required' }
        $now=Invoke-EloUpdateAdapter $Context Clock
        if ($now -isnot [datetime] -or $now -lt $preview.Created -or $now -ge $preview.Created.AddMinutes(5)) { throw 'confirmation_expired' }
        if ($preview.BranchConfirmation -and $BranchConfirmation -cne $preview.BranchConfirmation) { throw 'second_branch_confirmation_required' }
        if ($preview.CompatibilityConfirmation -and $CompatibilityConfirmation -cne $preview.CompatibilityConfirmation) { throw 'compatibility_confirmation_required' }
        $Context.Busy=$true; $locked=$true
        $paths=$preview.Paths; $package=$preview.Package
        $current=Invoke-EloUpdateAdapter $Context Inspect @($paths.Runtime)
        foreach ($key in @('Vendor','Branch','Architecture','Fingerprint')) { if ([string]$current[$key] -cne $preview.Detected[$key]) { throw 'target_changed' } }
        $compatibleNow=Assert-EloUpdateEvidence $Context $current $package
        if (-not $compatibleNow -and -not $preview.CompatibilityConfirmation) { throw 'compatibility_changed_new_preview_required' }
        Assert-EloUpdatePreflight $Context $paths
        $null=Invoke-EloUpdateAdapter $Context Backup @($paths)
        Assert-EloUpdateTrue (Invoke-EloUpdateAdapter $Context VerifyBackup @($paths,$current)) 'backup_verification_failed'
        $null=Invoke-EloUpdateAdapter $Context Download @($package,$paths)
        Assert-EloUpdateTrue (Invoke-EloUpdateAdapter $Context VerifyPackage @($package,$paths)) 'package_verification_failed'
        $null=Invoke-EloUpdateAdapter $Context Stage @($package,$paths)
        Assert-EloUpdateTrue (Invoke-EloUpdateAdapter $Context Probe @($paths.Stage,$package)) 'staged_java_version_failed'
        if ($hasQuiesce) { $resumeNeeded=$true; $quiesceState=Invoke-EloUpdateAdapter $Context Quiesce @($paths) }
        # Recheck the original after potentially slow backup/download/probe (and service stop).
        $latest=Invoke-EloUpdateAdapter $Context Inspect @($paths.Runtime)
        foreach ($key in @('Vendor','Branch','Architecture','Fingerprint')) { if ([string]$latest[$key] -cne $preview.Detected[$key]) { throw 'target_changed' } }
        # A failed rename may have partially succeeded. Always attempt restoration.
        $mutationAttempted=$true
        $null=Invoke-EloUpdateAdapter $Context Preserve @($paths)
        $null=Invoke-EloUpdateAdapter $Context Replace @($paths)
        Assert-EloUpdateTrue (Invoke-EloUpdateAdapter $Context ValidateInstalled @($paths,$package)) 'installed_validation_failed'
        $restart=& $resume; $resumeNeeded=$false
        return @{ Status=$(if ($Context.Simulation) { 'SimulatedSuccess' } else { 'Success' }); Backup=$paths.Backup; Old=$paths.Old; RecoveryRequired=$false; ServicesRestarted=$restart.Restarted; ServiceError=$restart.Error }
    } catch {
        $failure=$_.Exception.Message
        $restoreFailure=$null
        $status='Rejected'
        if ($mutationAttempted) {
            try {
                $null=Invoke-EloUpdateAdapter $Context Restore @($preview.Paths)
                Assert-EloUpdateTrue (Invoke-EloUpdateAdapter $Context VerifyRestored @($preview.Paths,$preview.Detected)) 'restore_verification_failed'
                $status='RolledBack'
            } catch { $restoreFailure=$_.Exception.Message; $Context.RecoveryRequired=$true; $status='ManualRecoveryRequired' }
        }
        $restart=& $resume; $resumeNeeded=$false
        return @{ Status=$status; Error=$failure; RestoreError=$restoreFailure; RecoveryRequired=$Context.RecoveryRequired;
            Backup=$(if ($preview) { $preview.Paths.Backup }); Old=$(if ($preview) { $preview.Paths.Old }); ServicesRestarted=$restart.Restarted; ServiceError=$restart.Error }
    } finally { if ($locked) { $Context.Busy=$false } }
}

# Release records are resolved from the vendor's official API by catalog.ps1 (latest GA of
# the same vendor/branch/architecture/image type) and re-validated here against a strict
# per-vendor policy (HTTPS host allowlist, URL shape, size bounds, SHA256 from the vendor
# API). The policy is code, never HTTP input; nothing is downloaded before validation.
function Get-EloPinnedRelease {
    param($Package)
    $copy=@{}
    foreach ($key in @('Vendor','Branch','Architecture','ImageType','Version','Uri','Sha256','Size')) { $copy[$key]=$Package[$key] }
    try { return Assert-EloReleaseRecord $copy } catch { throw ('no_independently_verified_release:'+$_.Exception.Message) }
}
function Get-EloStreamHash {
    param([IO.Stream]$Stream)
    $sha=[Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($Stream))).Replace('-','').ToLowerInvariant() }
    finally { $sha.Dispose() }
}
function ConvertFrom-EloPublishedChecksum {
    param([string]$Text)
    # One SHA256 token, optionally followed by a filename on the same line.
    if ($Text.Length -gt 4096 -or $Text -notmatch '\A\s*([a-fA-F0-9]{64})(?:[ \t]+[^\r\n]+)?\s*\z') { throw 'invalid_published_checksum' }
    return $Matches[1].ToLowerInvariant()
}
function Assert-EloHttpsHost {
    param([string]$Address,[string[]]$AllowedHosts)
    $uri=$null
    if (-not [Uri]::TryCreate($Address,[UriKind]::Absolute,[ref]$uri) -or $uri.Scheme -cne 'https' -or
        -not $uri.IsDefaultPort -or $uri.UserInfo -or $uri.Fragment -or $uri.HostNameType -ne [UriHostNameType]::Dns -or
        $AllowedHosts -cnotcontains $uri.DnsSafeHost.ToLowerInvariant()) { throw 'unverified_https_host' }
    return $uri
}
# Vendor APIs may report a rounded size (Azul rounds to the nearest 1000 bytes): the size is only a
# sanity bound (64 KiB tolerance, hard cap at MaxArchiveBytes); the pinned SHA256 is the integrity proof.
function Invoke-EloPinnedDownload {
    param($Package,[string]$Destination)
    $record=Get-EloPinnedRelease $Package # ALWAYS before network or file creation
    $uri=Assert-EloHttpsHost $record.Uri $record.AllowedHosts
    $AllowedFinal=@($record.AllowedHosts)
    $final=$null
    # .NET Framework has no per-request TLS setting: TLS 1.2 is enabled process-wide
    # for the duration of this download only and the previous value is restored.
    $previousProtocol=[Net.ServicePointManager]::SecurityProtocol
    [Net.ServicePointManager]::SecurityProtocol=$previousProtocol -bor [Net.SecurityProtocolType]::Tls12
    try {
    for ($hop=0; $hop -le 5; $hop++) {
        $request=[Net.HttpWebRequest]::Create($uri)
        # The system proxy is honoured (servers are often behind one); redirects stay manual.
        $request.AllowAutoRedirect=$false; $request.UseDefaultCredentials=$false
        $request.Timeout=30000; $request.ReadWriteTimeout=30000
        $response=$null
        try {
            $response=$request.GetResponse()
            $code=[int]$response.StatusCode
            if ($code -in @(301,302,303,307,308)) {
                if ($hop -eq 5 -or -not $response.Headers['Location']) { throw 'redirect_limit_or_missing_location' }
                $next=New-Object Uri($uri,$response.Headers['Location'])
                $uri=Assert-EloHttpsHost $next.AbsoluteUri $record.AllowedHosts
                continue
            }
            if ($code -ne 200 -or [Math]::Abs([long]$response.ContentLength-[long]$record.Size) -gt 65536 -or $response.ContentLength -gt $record.MaxArchiveBytes -or
                $response.ResponseUri.Scheme -cne 'https' -or $AllowedFinal -cnotcontains $response.ResponseUri.DnsSafeHost.ToLowerInvariant()) { throw 'unverified_response_or_length' }
            $input=$response.GetResponseStream(); $output=$null
            try {
                $output=New-Object IO.FileStream($Destination,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
                $buffer=New-Object byte[] 65536; [long]$total=0
                $watch=[Diagnostics.Stopwatch]::StartNew()
                while (($count=$input.Read($buffer,0,$buffer.Length)) -gt 0) {
                    if ($watch.ElapsedMilliseconds -gt 120000) { throw 'download_time_limit' }
                    $total+=$count
                    if ($total -gt $record.MaxArchiveBytes) { throw 'download_size_limit' }
                    $output.Write($buffer,0,$count)
                }
                if ($total -ne $response.ContentLength) { throw 'truncated_download' }
                $output.Flush($true); $final=$uri.AbsoluteUri
            } finally { if ($output) { $output.Dispose() }; $input.Dispose() }
            break
        } finally { if ($response) { $response.Dispose() }; $request.Abort() }
    }
    } finally { [Net.ServicePointManager]::SecurityProtocol=$previousProtocol }
    if (-not $final -or (Get-FileHash -LiteralPath $Destination -Algorithm SHA256 -ErrorAction Stop).Hash -ine $record.Sha256) { throw 'download_checksum_mismatch' }
    # The hash must have been independently pinned from the published checksum.
    # No inference from a .zip suffix or content-type is used as format evidence.
}
function Get-EloArchiveRoot {
    # The single top-level directory every entry must live under (vendor layouts differ).
    param($Entries)
    $root=$null
    foreach ($entry in $Entries) {
        $name=[string]$entry.FullName
        $slash=$name.IndexOf('/')
        if ($slash -lt 1) { throw 'unsafe_archive_entry' }
        $top=$name.Substring(0,$slash)
        if ($null -eq $root) { $root=$top } elseif ($top -cne $root) { throw 'unsafe_archive_entry' }
    }
    if ($null -eq $root) { throw 'unverified_archive_root' }
    return $root
}
function Assert-EloArchiveEntries {
    param($Entries,[string]$ArchiveRoot,[long]$MaximumBytes=1073741824,[int]$MaximumEntries=50000)
    if ($ArchiveRoot -notmatch '^[A-Za-z0-9_-][A-Za-z0-9_.+-]*$' -or $ArchiveRoot -match '[. ]$') { throw 'unverified_archive_root' }
    $names=@{}; [long]$total=0
    foreach ($entry in $Entries) {
        $name=[string]$entry.FullName
        if ($names.Count -ge $MaximumEntries -or $name.Length -gt 240 -or $name.Contains('\') -or
            -not $name.StartsWith($ArchiveRoot+'/',[StringComparison]::Ordinal) -or
            $name -match '[\x00-\x1f\x7f:<>|?*]' -or $name.StartsWith('/')) { throw 'unsafe_archive_entry' }
        $relative=$name.Substring($ArchiveRoot.Length+1)
        if ($relative) {
            foreach ($part in $relative.TrimEnd('/').Split('/')) {
                if ([string]::IsNullOrWhiteSpace($part) -or $part -match '[. ]$' -or $part -match '^(?i:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)') { throw 'unsafe_archive_entry' }
            }
        }
        $key=$name.TrimEnd('/')
        if ($names.ContainsKey($key)) { throw 'duplicate_archive_entry' }
        $names[$key]=$name.EndsWith('/')
        # Unix file type bits (ZIP external attributes): allow regular or dir,
        # never symlinks/devices. DOS reparse bit rejected independently.
        $type=(([long]$entry.ExternalAttributes -shr 16) -band 61440)
        if ($type -notin @(0,32768,16384) -or ($entry.ExternalAttributes -band 1024)) { throw 'archive_link_or_device' }
        if ($entry.Length -lt 0 -or $entry.Length -gt $MaximumBytes -or ($name.EndsWith('/') -and $entry.Length -ne 0)) { throw 'archive_size_limit' }
        $total+=[long]$entry.Length
        if ($total -gt $MaximumBytes) { throw 'archive_size_limit' }
    }
    foreach ($key in @($names.Keys)) {
        $parts=$key.Split('/'); $prefix=$parts[0]
        for ($i=1;$i -lt $parts.Length;$i++) {
            if ($names.ContainsKey($prefix) -and -not $names[$prefix]) { throw 'archive_file_directory_collision' }
            $prefix+='/'+$parts[$i]
        }
    }
    if (-not $names.ContainsKey($ArchiveRoot+'/bin/java.exe') -or $names[$ArchiveRoot+'/bin/java.exe']) { throw 'archive_java_missing' }
    return $total
}
function Initialize-EloZip {
    Add-Type -AssemblyName System.IO.Compression -ErrorAction Stop
}
function Assert-EloWindowsBoundary {
    param([string]$Root,[string]$Path,[switch]$MustExist)
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'windows_only' }
    $full=[IO.Path]::GetFullPath($Path); $base=[IO.Path]::GetFullPath($Root).TrimEnd('\')
    if ($base.Length -lt 2 -or -not $full.StartsWith($base+'\',[StringComparison]::OrdinalIgnoreCase)) { throw 'outside_approved_boundary' }
    $drive=New-Object IO.DriveInfo($full.Substring(0,3))
    if (-not $drive.IsReady -or $drive.DriveType -ne [IO.DriveType]::Fixed -or $drive.DriveFormat -cne 'NTFS') { throw 'local_ntfs_required' }
    $probe=$full
    while ($probe) {
        if (Test-Path -LiteralPath $probe) {
            $item=Get-Item -LiteralPath $probe -Force -ErrorAction Stop
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'reparse_boundary' }
        } elseif ($MustExist -and $probe -eq $full) { throw 'path_missing' }
        $parent=[IO.Path]::GetDirectoryName($probe)
        if ($parent -eq $probe) { break }; $probe=$parent
    }
    return $full
}
function Get-EloRuntimeManifest {
    param([string]$Root,[string]$Path)
    $full=Assert-EloWindowsBoundary $Root $Path -MustExist
    # Directory mtimes are excluded: harmless probes (for example the writability test) change them.
    $items=New-Object 'System.Collections.Generic.List[object]'
    $queue=New-Object 'System.Collections.Generic.Queue[string]'; $queue.Enqueue($full)
    [long]$bytes=0
    while ($queue.Count) {
        $current=$queue.Dequeue()
        $item=Get-Item -LiteralPath $current -Force -ErrorAction Stop
        if ($item.Attributes -band ([IO.FileAttributes]::ReparsePoint -bor [IO.FileAttributes]::Encrypted)) { throw 'unsupported_file_attributes' }
        $relative=$current.Substring($full.Length).TrimStart('\').Replace('\','/')
        if ($relative.Length -gt 200 -or $current.Length -gt 240) { throw 'manifest_path_limit' }
        if ($relative) {
            foreach ($part in $relative.Split('/')) {
                if ($part -match '[\x00-\x1f\x7f:<>|?*]' -or $part -match '[. ]$' -or $part -match '^(?i:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)') { throw 'unsupported_runtime_filename' }
            }
        }
        $acl=Get-Acl -LiteralPath $current -ErrorAction Stop
        # Owner/group/DACL only. SACL proof is an unresolved production blocker;
        # this must not be advertised as a complete Windows security backup.
        $sddl=$acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]'Access,Owner,Group')
        $hash=''; [long]$length=0
        if ($item.PSIsContainer) {
            foreach ($child in @(Get-ChildItem -LiteralPath $current -Force -ErrorAction Stop | Sort-Object Name)) { $queue.Enqueue($child.FullName) }
        } else {
            $streams=@(Get-Item -LiteralPath $current -Stream * -ErrorAction Stop)
            if (@($streams | Where-Object { $_.Stream -ne ':$DATA' }).Count) { throw 'alternate_streams_not_supported' }
            $length=$item.Length; $bytes+=$length
            $hash=(Get-FileHash -LiteralPath $current -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
        }
        $items.Add([pscustomobject][ordered]@{Name=$relative;Directory=[bool]$item.PSIsContainer;Length=$length;Hash=$hash;Sddl=$sddl;Attributes=[int]$item.Attributes;Ticks=$(if ($item.PSIsContainer) { 0 } else { $item.LastWriteTimeUtc.Ticks })})
        if ($items.Count -gt 50000 -or $bytes -gt 8GB) { throw 'runtime_manifest_limit' }
    }
    $entries=@($items.ToArray() | Sort-Object Name)
    $json=ConvertTo-Json -InputObject $entries -Depth 4 -Compress
    $memory=New-Object IO.MemoryStream(,[Text.Encoding]::UTF8.GetBytes($json))
    try { $fingerprint=Get-EloStreamHash $memory } finally { $memory.Dispose() }
    return @{Entries=$entries;Json=$json;Fingerprint=$fingerprint;Bytes=$bytes}
}
function Write-EloVerifiedBackup {
    param([string]$Root,$Paths,$Manifest)
    Initialize-EloZip
    $null=Assert-EloWindowsBoundary $Root $Paths.Backup
    $file=New-Object IO.FileStream($Paths.Backup,[IO.FileMode]::CreateNew,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    $zip=$null
    try {
        $zip=New-Object IO.Compression.ZipArchive($file,[IO.Compression.ZipArchiveMode]::Create,$true)
        $entry=$zip.CreateEntry('manifest.json'); $stream=$entry.Open()
        try { $bytes=[Text.Encoding]::UTF8.GetBytes($Manifest.Json); $stream.Write($bytes,0,$bytes.Length) } finally { $stream.Dispose() }
        foreach ($item in $Manifest.Entries) {
            if ($item.Directory) { continue }
            $entry=$zip.CreateEntry('tree/'+$item.Name,[IO.Compression.CompressionLevel]::Optimal)
            $output=$entry.Open(); $input=$null
            try {
                $path=Join-Path $Paths.Runtime $item.Name.Replace('/','\')
                $null=Assert-EloWindowsBoundary $Root $path -MustExist
                $input=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
                $input.CopyTo($output)
            } finally { if ($input) { $input.Dispose() }; $output.Dispose() }
        }
        $zip.Dispose(); $zip=$null; $file.Flush($true)
    } finally { if ($zip) { $zip.Dispose() }; $file.Dispose() }
}
function Test-EloBackupArchive {
    param($Zip,$Manifest)
    $expected=@{}; foreach ($item in $Manifest.Entries) { if (-not $item.Directory) { $expected['tree/'+$item.Name]=$item } }
    if ($Zip.Entries.Count -ne $expected.Count+1) { return $false }
    $seen=@{}
    foreach ($entry in $Zip.Entries) {
        if ($seen.ContainsKey($entry.FullName)) { return $false }; $seen[$entry.FullName]=$true
        $stream=$entry.Open()
        try {
            if ($entry.FullName -ceq 'manifest.json') {
                $bytes=[Text.Encoding]::UTF8.GetBytes($Manifest.Json)
                if ($entry.Length -ne $bytes.Length) { return $false }
                $reader=New-Object IO.StreamReader($stream,[Text.Encoding]::UTF8,$false)
                try { if ($reader.ReadToEnd() -cne $Manifest.Json) { return $false } } finally { $reader.Dispose() }
            } else {
                if (-not $expected.ContainsKey($entry.FullName) -or $entry.Length -ne $expected[$entry.FullName].Length -or
                    (Get-EloStreamHash $stream) -cne $expected[$entry.FullName].Hash) { return $false }
            }
        } finally { $stream.Dispose() }
    }
    return $seen.ContainsKey('manifest.json')
}
function Expand-EloPinnedArchive {
    param([string]$Root,$Package,$Paths)
    $record=Get-EloPinnedRelease $Package
    Initialize-EloZip
    $null=Assert-EloWindowsBoundary $Root $Paths.Stage
    if (Test-Path -LiteralPath $Paths.Stage) { throw 'staging_already_exists' }
    if ((Get-FileHash -LiteralPath $Paths.Download -Algorithm SHA256 -ErrorAction Stop).Hash -ine $record.Sha256) { throw 'archive_checksum_mismatch' }
    $input=[IO.File]::OpenRead($Paths.Download); $zip=$null
    try {
        $zip=New-Object IO.Compression.ZipArchive($input,[IO.Compression.ZipArchiveMode]::Read,$true)
        $archiveRoot=Get-EloArchiveRoot $zip.Entries
        $null=Assert-EloArchiveEntries $zip.Entries $archiveRoot $record.MaxExpandedBytes
        $null=[IO.Directory]::CreateDirectory($Paths.Stage)
        foreach ($entry in $zip.Entries) {
            $relative=$entry.FullName.Substring($archiveRoot.Length+1)
            if (-not $relative) { continue }
            $destination=Join-Path $Paths.Stage $relative.Replace('/','\').TrimEnd('\')
            $null=Assert-EloWindowsBoundary $Root $destination
            if ($entry.FullName.EndsWith('/')) { $null=[IO.Directory]::CreateDirectory($destination); continue }
            $null=[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($destination))
            $source=$entry.Open(); $output=$null
            try {
                $output=New-Object IO.FileStream($destination,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
                $buffer=New-Object byte[] 65536; [long]$copied=0
                while (($count=$source.Read($buffer,0,$buffer.Length)) -gt 0) {
                    $copied+=$count; if ($copied -gt $entry.Length) { throw 'expanded_entry_size_mismatch' }
                    $output.Write($buffer,0,$count)
                }
                if ($copied -ne $entry.Length) { throw 'expanded_entry_size_mismatch' }; $output.Flush($true)
            } finally { if ($output) { $output.Dispose() }; $source.Dispose() }
            $source=$entry.Open(); $copy=[IO.File]::OpenRead($destination)
            try { if ((Get-EloStreamHash $source) -cne (Get-EloStreamHash $copy)) { throw 'staging_copy_hash_mismatch' } }
            finally { $source.Dispose(); $copy.Dispose() }
        }
    } finally { if ($zip) { $zip.Dispose() }; $input.Dispose() }
}
function Get-EloRuntimeIdentity {
    # Vendor, branch, architecture, image type and version of an installed runtime,
    # read from its release file and the java.exe PE header. Read-only.
    param([string]$Path)
    $release=Join-Path $Path 'release'; $java=Join-Path $Path 'bin\java.exe'
    if ((Get-Item -LiteralPath $release -ErrorAction Stop).Length -gt 65536) { throw 'release_size_limit' }
    $values=@{}
    foreach ($line in [IO.File]::ReadAllLines($release)) {
        if ($line -cmatch '^(IMPLEMENTOR|IMPLEMENTOR_VERSION|JAVA_VERSION|JAVA_RUNTIME_VERSION|OS_ARCH|OS_NAME)="([^"\x00-\x1f]*)"$') {
            if ($values.ContainsKey($Matches[1])) { throw 'duplicate_release_key' }; $values[$Matches[1]]=$Matches[2]
        }
    }
    $vendor=''
    if ($values.IMPLEMENTOR -ceq 'Eclipse Adoptium') { $vendor='Eclipse Adoptium' }
    elseif ($values.IMPLEMENTOR -ceq 'Azul Systems, Inc.' -and [string]$values.IMPLEMENTOR_VERSION -cmatch '^Zulu') { $vendor='Azul Zulu' }
    if (-not $vendor -or $values.OS_NAME -cne 'Windows') { throw 'unrecognized_runtime_identity' }
    # Older builds omit JAVA_RUNTIME_VERSION.
    $source=$values.JAVA_RUNTIME_VERSION; if (-not $source) { $source=$values.JAVA_VERSION }
    if (-not $source) { throw 'unrecognized_runtime_identity' }
    try { $version=ConvertTo-EloJavaVersion $source } catch { throw 'unrecognized_runtime_identity' }
    $stream=[IO.File]::OpenRead($java); $reader=New-Object IO.BinaryReader($stream)
    try {
        if ($reader.ReadUInt16() -ne 23117) { throw 'java_not_pe' }
        $stream.Position=60; $offset=$reader.ReadInt32()
        if ($offset -lt 64 -or $offset -gt $stream.Length-6) { throw 'invalid_pe_offset' }
        $stream.Position=$offset; if ($reader.ReadUInt32() -ne 17744) { throw 'invalid_pe_signature' }
        $machine=$reader.ReadUInt16()
    } finally { $reader.Dispose(); $stream.Dispose() }
    $arch=@{34404='x64';332='x86';43620='ARM64'}[[int]$machine]
    if (-not $arch) { throw 'unsupported_or_inconsistent_architecture' }
    $image='jre'; if (Test-Path -LiteralPath (Join-Path $Path 'bin\javac.exe')) { $image='jdk' }
    return @{Vendor=$vendor;Branch=$version.Branch;Architecture=$arch;ImageType=$image;Version=$version.Text}
}
function Test-EloSameJavaRelease {
    # Same numeric release; build numbers only count when both sides report one.
    param([string]$Left,[string]$Right)
    $a=ConvertTo-EloJavaVersion $Left; $b=ConvertTo-EloJavaVersion $Right
    if ($a.Build -eq 0 -or $b.Build -eq 0) { $a.Build=0; $b.Build=0 }
    return ((Compare-EloJavaVersion $a $b) -eq 0)
}function Invoke-EloBoundedJavaVersion {
    param([string]$Path,$Package)
    $identity=Get-EloRuntimeIdentity $Path
    foreach ($key in @('Vendor','Branch','Architecture')) { if ($identity[$key] -cne $Package[$key]) { throw 'java_identity_mismatch' } }
    if (-not (Test-EloSameJavaRelease $identity.Version ([string]$Package.Version))) { throw 'java_identity_mismatch' }
    $process=New-Object Diagnostics.Process; $started=$false
    try {
        $info=New-Object Diagnostics.ProcessStartInfo
        $info.FileName=Join-Path $Path 'bin\java.exe'; $info.Arguments='-version'; $info.WorkingDirectory=$Path
        $info.UseShellExecute=$false; $info.CreateNoWindow=$true; $info.RedirectStandardOutput=$true; $info.RedirectStandardError=$true
        foreach ($name in @('JAVA_TOOL_OPTIONS','_JAVA_OPTIONS','JDK_JAVA_OPTIONS','CLASSPATH')) { $info.EnvironmentVariables.Remove($name) }
        $process.StartInfo=$info
        $started=$process.Start(); if (-not $started) { throw 'java_start_failed' }
        $watch=[Diagnostics.Stopwatch]::StartNew(); $text=New-Object Text.StringBuilder
        # Separate single-character buffers/tasks bound memory and drain both pipes.
        $outBuffer=New-Object char[] 1; $errBuffer=New-Object char[] 1
        $outTask=$process.StandardOutput.ReadAsync($outBuffer,0,1); $errTask=$process.StandardError.ReadAsync($errBuffer,0,1)
        $outDone=$false; $errDone=$false
        while (-not ($outDone -and $errDone)) {
            if ($watch.ElapsedMilliseconds -gt 10000 -or $text.Length -gt 16384) { throw 'java_probe_limit' }
            if (-not $outDone -and $outTask.IsCompleted) {
                if ($outTask.Result -eq 0) { $outDone=$true } else { $null=$text.Append($outBuffer[0]); $outTask=$process.StandardOutput.ReadAsync($outBuffer,0,1) }
            }
            if (-not $errDone -and $errTask.IsCompleted) {
                if ($errTask.Result -eq 0) { $errDone=$true } else { $null=$text.Append($errBuffer[0]); $errTask=$process.StandardError.ReadAsync($errBuffer,0,1) }
            }
            [Threading.Thread]::Sleep(5)
        }
        if (-not $process.WaitForExit(1000) -or $process.ExitCode -ne 0 -or -not ($text.ToString() -cmatch 'version "([^"]+)"') -or -not (Test-EloSameJavaRelease $Matches[1] ([string]$Package.Version))) { throw 'java_version_probe_failed' }
        return $true
    } finally {
        try { if ($started -and -not $process.HasExited) { $process.Kill(); $null=$process.WaitForExit(2000) } }
        finally { $process.Dispose() }
    }
}
function Get-EloRuntimeUsers {
    # Running services and other processes that have the runtime loaded: their image
    # or any loaded module lives below the runtime directory. Read-only; protected
    # processes whose modules cannot be listed are skipped (and cannot be proven idle).
    param([string]$Path)
    $prefix=[IO.Path]::GetFullPath($Path).TrimEnd('\')+'\'
    $services=@{}
    foreach ($service in @(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop)) {
        if ([int]$service.ProcessId -gt 0 -and [string]$service.State -ceq 'Running') { $services[[int]$service.ProcessId]=$service }
    }
    $found=@{Services=@();Processes=@()}
    $all=@(Get-CimInstance -ClassName Win32_Process -ErrorAction Stop)
    $parents=@{}; foreach ($process in $all) { $parents[[int]$process.ProcessId]=[int]$process.ParentProcessId }
    $seenServices=@{}
    foreach ($process in $all) {
        $id=[int]$process.ProcessId
        if ($id -le 4 -or $id -eq $PID) { continue }
        $uses=$false
        $image=[string]$process.ExecutablePath
        if ($image -and $image.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)) { $uses=$true }
        if (-not $uses) {
            $handle=$null
            try {
                $handle=[Diagnostics.Process]::GetProcessById($id)
                foreach ($module in $handle.Modules) {
                    if ($module.FileName.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)) { $uses=$true; break }
                }
            } catch { } finally { if ($handle) { $handle.Dispose() } }
        }
        if (-not $uses) { continue }
        # A process belongs to the nearest ancestor that is a running service (children die with it).
        $owner=$null; $cursor=$id
        for ($depth=0; $depth -lt 8 -and $null -eq $owner -and $parents.ContainsKey($cursor); $depth++) {
            if ($services.ContainsKey($cursor)) { $owner=$services[$cursor] } else { $cursor=$parents[$cursor] }
        }
        if ($null -eq $owner -and $services.ContainsKey($cursor)) { $owner=$services[$cursor] }
        if ($owner) {
            if (-not $seenServices.ContainsKey([string]$owner.Name)) { $seenServices[[string]$owner.Name]=$true; $found.Services+=@(@{Name=[string]$owner.Name;DisplayName=[string]$owner.DisplayName;ProcessId=[int]$owner.ProcessId}) }
        } else { $found.Processes+=@(@{Id=$id;Name=[string]$process.Name}) }
    }
    return $found
}
function Test-EloRuntimeQuiescent {
    # Strict: nothing uses the runtime and its java binaries can be opened exclusively.
    param([string]$Path)
    $users=Get-EloRuntimeUsers $Path
    if ($users.Services.Count -gt 0 -or $users.Processes.Count -gt 0) { return $false }
    foreach ($name in @('bin\java.exe','bin\javaw.exe')) {
        $file=Join-Path $Path $name
        if (-not (Test-Path -LiteralPath $file)) { continue }
        try { $stream=[IO.File]::Open($file,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None); $stream.Dispose() } catch { return $false }
    }
    return $true
}function Test-EloDirectoryWritable {
    param([string]$Path)
    $probe=Join-Path $Path ('.elo-write-probe-'+[guid]::NewGuid().ToString('N'))
    try {
        $stream=New-Object IO.FileStream($probe,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None,16,[IO.FileOptions]::DeleteOnClose)
        $stream.Dispose(); return $true
    } catch { return $false }
}
# Real adapter for Invoke-EloJavaSelfTest: runs only JavaPath, with a sanitized
# environment, an isolated classpath and non-blocking, size-bounded output reads.
function New-EloJavaSelfTestAdapter {
    $watch=[Diagnostics.Stopwatch]::StartNew()
    return @{
        Clock={ [long]$watch.ElapsedMilliseconds }.GetNewClosure()
        Start={ param($Request)
            $null=[IO.Directory]::CreateDirectory($Request.SessionPath)
            [IO.File]::WriteAllBytes((Join-Path $Request.SessionPath 'EloJavaSelfTest.class'),[byte[]]$Request.ClassBytes)
            $info=New-Object Diagnostics.ProcessStartInfo
            $info.FileName=$Request.JavaPath; $info.Arguments='-cp "'+$Request.SessionPath+'" EloJavaSelfTest'
            $info.WorkingDirectory=$Request.SessionPath; $info.UseShellExecute=$false; $info.CreateNoWindow=$true
            $info.RedirectStandardOutput=$true; $info.RedirectStandardError=$true
            foreach ($name in @('JAVA_TOOL_OPTIONS','_JAVA_OPTIONS','JDK_JAVA_OPTIONS','CLASSPATH')) { $info.EnvironmentVariables.Remove($name) }
            $process=New-Object Diagnostics.Process; $process.StartInfo=$info
            if (-not $process.Start()) { throw 'java_start_failed' }
            $handle=@{Process=$process;OutBuffer=(New-Object char[] 4096);ErrBuffer=(New-Object char[] 4096);OutDone=$false;ErrDone=$false}
            $handle.OutTask=$process.StandardOutput.ReadAsync($handle.OutBuffer,0,4096)
            $handle.ErrTask=$process.StandardError.ReadAsync($handle.ErrBuffer,0,4096)
            $handle
        }
        Poll={ param($Handle)
            $out=''; $err=''
            if (-not $Handle.OutDone -and $Handle.OutTask.IsCompleted) {
                $n=$Handle.OutTask.Result
                if ($n -eq 0) { $Handle.OutDone=$true } else { $out=New-Object string($Handle.OutBuffer,0,$n); $Handle.OutTask=$Handle.Process.StandardOutput.ReadAsync($Handle.OutBuffer,0,4096) }
            }
            if (-not $Handle.ErrDone -and $Handle.ErrTask.IsCompleted) {
                $n=$Handle.ErrTask.Result
                if ($n -eq 0) { $Handle.ErrDone=$true } else { $err=New-Object string($Handle.ErrBuffer,0,$n); $Handle.ErrTask=$Handle.Process.StandardError.ReadAsync($Handle.ErrBuffer,0,4096) }
            }
            $done=($Handle.OutDone -and $Handle.ErrDone -and $Handle.Process.WaitForExit(0))
            if (-not $done) { [Threading.Thread]::Sleep(5) }
            @{Stdout=$out;Stderr=$err;Done=[bool]$done;ExitCode=$(if ($done) { [int]$Handle.Process.ExitCode } else { $null })}
        }
        Stop={ param($Handle)
            try { if (-not $Handle.Process.HasExited) { $Handle.Process.Kill(); $null=$Handle.Process.WaitForExit(2000) } } finally { $Handle.Process.Dispose() }
            $true
        }
    }
}
function Invoke-EloJavaProbe {
    param([string]$Path,$Package)
    $null=Invoke-EloBoundedJavaVersion $Path $Package
    $sessions=Join-Path ([IO.Path]::GetTempPath().TrimEnd('\')) 'elo-patch-selftest'
    $null=[IO.Directory]::CreateDirectory($sessions)
    $result=Invoke-EloJavaSelfTest -JavaPath (Join-Path $Path 'bin\java.exe') -SessionRoot $sessions -Adapter (New-EloJavaSelfTestAdapter)
    # Session artifacts are retained by design (nothing is deleted by this module).
    if (-not $result.Success) { throw ('java_self_test_failed:'+$result.Reason) }
    return $true
}
function ConvertFrom-EloManifestJson {
    param([string]$Json)
    $parsed=ConvertFrom-Json $Json
    return @($parsed | ForEach-Object { $_ })
}
function Invoke-EloBackupRestore {
    # Restores a runtime from a backup ZIP written by this module: every file is hashed
    # while it is extracted into a sibling directory, compared with the manifest, and only
    # then swapped in. The current runtime is renamed (kept), never deleted. ACLs are
    # re-applied from the manifest (owner when permitted, otherwise DACL only).
    param([Parameter(Mandatory=$true)][string]$Root,[Parameter(Mandatory=$true)][string]$Runtime,
        [Parameter(Mandatory=$true)][string]$Backup,[scriptblock]$Quiesce,[scriptblock]$Resume,[string]$Stamp)
    Initialize-EloZip
    $null=Assert-EloWindowsBoundary $Root $Runtime
    $null=Assert-EloWindowsBoundary $Root $Backup -MustExist
    if ($Backup -notmatch '(?i)\.zip$') { throw 'backup_zip_required' }
    if (-not $Stamp) { $Stamp=[DateTime]::UtcNow.ToString('yyyyMMddHHmmss') }
    $stage=$Runtime+'.restore-'+$Stamp; $replaced=$Runtime+'.replaced-'+$Stamp
    foreach ($path in @($stage,$replaced)) {
        $null=Assert-EloWindowsBoundary $Root $path
        if (Test-Path -LiteralPath $path) { throw 'recovery_or_staging_path_exists' }
    }
    $input=[IO.File]::OpenRead($Backup); $zip=$null; $quiesced=$false; $aclExact=$true
    try {
        $zip=New-Object IO.Compression.ZipArchive($input,[IO.Compression.ZipArchiveMode]::Read,$true)
        $manifestEntry=$zip.GetEntry('manifest.json')
        if (-not $manifestEntry -or $manifestEntry.Length -gt 64MB) { throw 'backup_manifest_invalid' }
        $reader=New-Object IO.StreamReader($manifestEntry.Open(),[Text.Encoding]::UTF8,$false)
        try { $manifest=ConvertFrom-EloManifestJson $reader.ReadToEnd() } finally { $reader.Dispose() }
        $expected=@{}
        foreach ($item in $manifest) {
            $name=[string]$item.Name
            if ($name) {
                if ($name.Length -gt 200 -or $name.StartsWith('/') -or $name.Contains('\')) { throw 'backup_manifest_invalid' }
                foreach ($part in $name.Split('/')) {
                    if ([string]::IsNullOrWhiteSpace($part) -or $part -eq '.' -or $part -eq '..' -or $part -match '[\x00-\x1f\x7f:<>|?*]' -or $part -match '[. ]$' -or $part -match '^(?i:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)') { throw 'backup_manifest_invalid' }
                }
            }
            if (-not [bool]$item.Directory -and [string]$item.Hash -cnotmatch '^[a-f0-9]{64}$') { throw 'backup_manifest_invalid' }
            $expected[$name]=$item
        }
        if (-not $expected.ContainsKey('') -or -not [bool]$expected[''].Directory) { throw 'backup_manifest_invalid' }
        $null=[IO.Directory]::CreateDirectory($stage)
        $sorted=@($manifest | Where-Object { [string]$_.Name } | Sort-Object { ([string]$_.Name).Length })
        foreach ($item in $sorted) {
            $target=Join-Path $stage ([string]$item.Name).Replace('/','\')
            $null=Assert-EloWindowsBoundary $Root $target
            if ([bool]$item.Directory) { $null=[IO.Directory]::CreateDirectory($target); continue }
            $entry=$zip.GetEntry('tree/'+[string]$item.Name)
            if (-not $entry -or $entry.Length -ne [long]$item.Length) { throw 'backup_entry_mismatch' }
            $null=[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($target))
            $source=$entry.Open(); $output=$null; $sha=[Security.Cryptography.SHA256]::Create()
            try {
                $output=New-Object IO.FileStream($target,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
                $buffer=New-Object byte[] 65536; [long]$total=0
                while (($count=$source.Read($buffer,0,$buffer.Length)) -gt 0) {
                    $total+=$count; if ($total -gt [long]$item.Length) { throw 'backup_entry_mismatch' }
                    $null=$sha.TransformBlock($buffer,0,$count,$null,0); $output.Write($buffer,0,$count)
                }
                $null=$sha.TransformFinalBlock($buffer,0,0); $output.Flush($true)
                $hash=([BitConverter]::ToString($sha.Hash)).Replace('-','').ToLowerInvariant()
                if ($total -ne [long]$item.Length -or $hash -cne [string]$item.Hash) { throw 'backup_entry_mismatch' }
            } finally { $sha.Dispose(); if ($output) { $output.Dispose() }; $source.Dispose() }
            if ([long]$item.Ticks -gt 0) { [IO.File]::SetLastWriteTimeUtc($target,(New-Object DateTime([long]$item.Ticks,[DateTimeKind]::Utc))) }
        }
        # Content proof first, then ACLs (deepest first so a restrictive parent ACL cannot block children).
        $actual=Get-EloRuntimeManifest $Root $stage
        $actualMap=@{}; foreach ($item in $actual.Entries) { $actualMap[[string]$item.Name]=$item }
        if ($actualMap.Count -ne $expected.Count) { throw 'restored_content_mismatch' }
        foreach ($key in $expected.Keys) {
            $a=$actualMap[$key]; $e=$expected[$key]
            if (-not $a -or [bool]$a.Directory -ne [bool]$e.Directory -or [long]$a.Length -ne [long]$e.Length -or [string]$a.Hash -cne [string]$e.Hash) { throw 'restored_content_mismatch' }
        }
        foreach ($item in @($manifest | Sort-Object { ([string]$_.Name).Length } -Descending)) {
            $target=$stage; if ([string]$item.Name) { $target=Join-Path $stage ([string]$item.Name).Replace('/','\') }
            $acl=$null; if ([bool]$item.Directory) { $acl=New-Object Security.AccessControl.DirectorySecurity } else { $acl=New-Object Security.AccessControl.FileSecurity }
            try { $acl.SetSecurityDescriptorSddlForm([string]$item.Sddl); Set-Acl -LiteralPath $target -AclObject $acl -ErrorAction Stop }
            catch {
                $aclExact=$false
                try {
                    $acl=$null; if ([bool]$item.Directory) { $acl=New-Object Security.AccessControl.DirectorySecurity } else { $acl=New-Object Security.AccessControl.FileSecurity }
                    $acl.SetSecurityDescriptorSddlForm([string]$item.Sddl,[Security.AccessControl.AccessControlSections]::Access); Set-Acl -LiteralPath $target -AclObject $acl -ErrorAction Stop
                } catch { }
            }
        }
        if ($Quiesce) { $quiesced=$true; $null=& $Quiesce }
        $moved=$false
        try {
            if (Test-Path -LiteralPath $Runtime) { [IO.Directory]::Move($Runtime,$replaced); $moved=$true }
            [IO.Directory]::Move($stage,$Runtime)
        } catch {
            if ($moved -and -not (Test-Path -LiteralPath $Runtime)) { [IO.Directory]::Move($replaced,$Runtime) }
            throw
        }
        return @{Restored=$true;Replaced=$(if ($moved) { $replaced } else { $null });AclExact=$aclExact}
    } finally {
        if ($zip) { $zip.Dispose() }; $input.Dispose()
        if ($quiesced -and $Resume) { try { $null=& $Resume } catch { } }
    }
}
function New-EloWindowsUpdateAdapters {
    param([Parameter(Mandatory=$true)][string]$ApprovedRoot,[Parameter(Mandatory=$true)][string]$Runtime,[switch]$AllowServiceStop)
    # Factory itself performs no IO. Only direct, explicitly invoked adapter calls
    # can do work. Engine production gate remains closed regardless of injection.
    $state=@{Root=$ApprovedRoot;Runtime=$Runtime;Original=$null;Staged=$null;FailedPath=$null;Stopped=(New-Object 'System.Collections.Generic.List[string]');AllowServiceStop=[bool]$AllowServiceStop}
    $adapters=@{
        EloWindowsAdapters=$true
        Clock={ [DateTime]::UtcNow }
        Admin={
            $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
            try { (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
            finally { $identity.Dispose() }
        }
        Inspect={ param($Path)
            if ($Path -cne $state.Runtime) { throw 'runtime_not_explicitly_selected' }
            $manifest=Get-EloRuntimeManifest $state.Root $Path
            $identity=Get-EloRuntimeIdentity $Path; $identity.Fingerprint=$manifest.Fingerprint
            $state.Original=$manifest; $identity
        }.GetNewClosure()
        Evidence={ param($Detected,$Package)
            $record=Get-EloPinnedRelease $Package
            @{Official=$true;PublishedHash=$true;Compatibility=$false}
        }
        Preflight={ param($Paths)
            Assert-EloUpdatePaths $Paths
            if ($Paths.Runtime -cne $state.Runtime) { throw 'runtime_not_explicitly_selected' }
            foreach ($key in @('Runtime','Old','Stage','Backup','Download')) {
                $null=Assert-EloWindowsBoundary $state.Root $Paths[$key]
                if ($key -ne 'Runtime' -and (Test-Path -LiteralPath $Paths[$key])) { throw 'recovery_or_staging_path_exists' }
                if ([IO.Path]::GetDirectoryName($Paths[$key]) -ine [IO.Path]::GetDirectoryName($Paths.Runtime)) { throw 'sibling_paths_required' }
            }
            $manifest=Get-EloRuntimeManifest $state.Root $Paths.Runtime
            $drive=New-Object IO.DriveInfo($Paths.Runtime.Substring(0,3))
            # Real, fail-closed checks; services are never stopped or restarted here.
            $quiescent=$false
            if ($state.AllowServiceStop) { $users=Get-EloRuntimeUsers $Paths.Runtime; $quiescent=(($users.Processes.Count -eq 0) -and ($users.Services.Count -gt 0 -or (Test-EloRuntimeQuiescent $Paths.Runtime))) }
            else { $quiescent=Test-EloRuntimeQuiescent $Paths.Runtime }
            @{SafePaths=$true;Quiescent=$quiescent
              Permissions=((Test-EloDirectoryWritable $Paths.Runtime) -and (Test-EloDirectoryWritable ([IO.Path]::GetDirectoryName($Paths.Runtime))))
              Space=($drive.AvailableFreeSpace -gt (6*$manifest.Bytes+1GB))}
        }.GetNewClosure()
        Backup={ param($Paths) Write-EloVerifiedBackup $state.Root $Paths $state.Original }.GetNewClosure()
        VerifyBackup={ param($Paths,$Detected)
            Initialize-EloZip
            $input=[IO.File]::OpenRead($Paths.Backup); $zip=$null
            try {
                $zip=New-Object IO.Compression.ZipArchive($input,[IO.Compression.ZipArchiveMode]::Read,$true)
                (Test-EloBackupArchive $zip $state.Original) -and
                    ((Get-EloRuntimeManifest $state.Root $Paths.Runtime).Fingerprint -ceq $Detected.Fingerprint)
            } finally { if ($zip) { $zip.Dispose() }; $input.Dispose() }
        }.GetNewClosure()
        Download={ param($Package,$Paths) Invoke-EloPinnedDownload $Package $Paths.Download }
        VerifyPackage={ param($Package,$Paths)
            $record=Get-EloPinnedRelease $Package
            (Get-FileHash -LiteralPath $Paths.Download -Algorithm SHA256 -ErrorAction Stop).Hash -ieq $record.Sha256
        }
        Stage={ param($Package,$Paths)
            Expand-EloPinnedArchive $state.Root $Package $Paths
            $state.Staged=Get-EloRuntimeManifest $state.Root $Paths.Stage
        }.GetNewClosure()
        Probe={ param($Path,$Package) Invoke-EloJavaProbe $Path $Package }
        Preserve={ param($Paths)
            $null=Assert-EloWindowsBoundary $state.Root $Paths.Runtime -MustExist
            $null=Assert-EloWindowsBoundary $state.Root $Paths.Old
            if ((Get-EloRuntimeManifest $state.Root $Paths.Runtime).Fingerprint -cne $state.Original.Fingerprint) { throw 'original_changed_before_rename' }
            [IO.Directory]::Move($Paths.Runtime,$Paths.Old)
        }.GetNewClosure()
        Replace={ param($Paths)
            $null=Assert-EloWindowsBoundary $state.Root $Paths.Stage -MustExist
            $null=Assert-EloWindowsBoundary $state.Root $Paths.Runtime
            if ((Get-EloRuntimeManifest $state.Root $Paths.Stage).Fingerprint -cne $state.Staged.Fingerprint) { throw 'stage_changed_before_rename' }
            [IO.Directory]::Move($Paths.Stage,$Paths.Runtime)
        }.GetNewClosure()
        ValidateInstalled={ param($Paths,$Package)
            ((Get-EloRuntimeManifest $state.Root $Paths.Runtime).Fingerprint -ceq $state.Staged.Fingerprint) -and
                (Invoke-EloJavaProbe $Paths.Runtime $Package)
        }.GetNewClosure()
        Restore={ param($Paths)
            $null=Assert-EloWindowsBoundary $state.Root $Paths.Old
            $null=Assert-EloWindowsBoundary $state.Root $Paths.Runtime
            if (Test-Path -LiteralPath $Paths.Old) {
                if ((Get-EloRuntimeManifest $state.Root $Paths.Old).Fingerprint -cne $state.Original.Fingerprint) { throw 'old_runtime_changed_manual_zip_restore_required' }
                if (Test-Path -LiteralPath $Paths.Runtime) {
                    $state.FailedPath=$Paths.Stage+'.failed-'+[guid]::NewGuid().ToString('N')
                    $null=Assert-EloWindowsBoundary $state.Root $state.FailedPath
                    [IO.Directory]::Move($Paths.Runtime,$state.FailedPath)
                }
                [IO.Directory]::Move($Paths.Old,$Paths.Runtime)
            } elseif ((Get-EloRuntimeManifest $state.Root $Paths.Runtime).Fingerprint -cne $state.Original.Fingerprint) {
                throw 'old_runtime_missing_manual_zip_restore_required'
            }
        }.GetNewClosure()
        VerifyRestored={ param($Paths,$Detected)
            (Get-EloRuntimeManifest $state.Root $Paths.Runtime).Fingerprint -ceq $Detected.Fingerprint
        }.GetNewClosure()
    }
    if ($AllowServiceStop) {
        # Opt-in (the user confirmed the services listed in the preview). Only services that
        # actually use this runtime are stopped, dependents are restarted, and Resume runs
        # on success and on failure alike.
        $adapters.Quiesce={ param($Paths)
            $users=Get-EloRuntimeUsers $Paths.Runtime
            if ($users.Processes.Count -gt 0) { throw 'runtime_in_use_by_process' }
            foreach ($user in $users.Services) {
                $service=Get-Service -Name $user.Name -ErrorAction Stop
                $state.Stopped.Add([string]$user.Name)
                foreach ($dependent in @($service.DependentServices | Where-Object { $_.Status -eq 'Running' })) { $state.Stopped.Add([string]$dependent.Name) }
                Stop-Service -Name $user.Name -Force -ErrorAction Stop
                $service.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(90))
            }
            if (-not (Test-EloRuntimeQuiescent $Paths.Runtime)) { throw 'runtime_still_in_use_after_service_stop' }
            @($state.Stopped)
        }.GetNewClosure()
        $adapters.Resume={ param($Paths,$Stopped)
            $failed=New-Object 'System.Collections.Generic.List[string]'
            foreach ($name in @($state.Stopped)) {
                try { $service=Get-Service -Name $name -ErrorAction Stop; if ($service.Status -ne 'Running') { Start-Service -Name $name -ErrorAction Stop; $service.WaitForStatus('Running',[TimeSpan]::FromSeconds(90)) } }
                catch { $failed.Add($name) }
            }
            $state.Stopped.Clear()
            if ($failed.Count -gt 0) { throw ('service_restart_failed:'+($failed -join '+')) }
        }.GetNewClosure()
    }
    return $adapters
}
::ELO_PATCH_END:UPDATE_PS

::ELO_PATCH_BEGIN:CATALOG_PS
# Embeddable Windows PowerShell 5.1 module: dot-sourcing defines functions ONLY.
# Release catalog for runtime updates. The newest GA release of a Java branch is
# resolved at preview time from the vendor's OFFICIAL metadata API over HTTPS
# (Azul Zulu: api.azul.com; Eclipse Temurin: api.adoptium.net). The package URI and
# SHA256 returned by the API are then validated against a STRICT per-vendor policy
# (host allowlist, URL shape, size bounds) before anything is downloaded. The policy
# lives here, never in the API response, an HTTP client or the UI.
# Supported: Windows, branches 8/11/17/21/25 and any other numeric branch the vendor
# publishes, architectures x86/x64/ARM64, images jdk/jre, plain GA builds (no CRaC/FX).

function Get-EloVendorPolicy {
    return @{
        'Azul Zulu' = @{
            ApiHosts = @('api.azul.com'); DownloadHosts = @('cdn.azul.com')
            PathPattern = '^/zulu/bin/zulu[0-9.]+-ca-(jdk|jre)[0-9.]+-win_(x64|i686|aarch64)\.zip$'
        }
        'Eclipse Adoptium' = @{
            ApiHosts = @('api.adoptium.net'); DownloadHosts = @('github.com', 'release-assets.githubusercontent.com')
            PathPattern = '^/adoptium/temurin[0-9]+-binaries/releases/download/[A-Za-z0-9._%+-]+/OpenJDK[0-9]+U-(jdk|jre)_(x64|x86-32|aarch64)_windows_hotspot_[A-Za-z0-9._%+-]+\.zip$'
        }
    }
}
function ConvertTo-EloJavaVersion {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { throw 'unrecognized_java_version' }
    $s = $Text.Trim(); $build = 0
    if ($s -cmatch '^(.*?)\+(\d+)(?:-.*)?$') { $s = $Matches[1]; $build = [int]$Matches[2] }
    elseif ($s -cmatch '^(.*?)-b(\d+)$') { $s = $Matches[1]; $build = [int]$Matches[2] }
    else { $s = $s -creplace '-[A-Za-z].*$', '' }
    if ($s -cmatch '^1\.(\d+)\.(\d+)_(\d+)$') { $numbers = @([int]$Matches[1], [int]$Matches[2], [int]$Matches[3]) }
    elseif ($s -cmatch '^(\d+)u(\d+)$') { $numbers = @([int]$Matches[1], 0, [int]$Matches[2]) }
    elseif ($s -cmatch '^\d+(\.\d+){0,4}$') { $numbers = @($s.Split('.') | ForEach-Object { [int]$_ }) }
    else { throw 'unrecognized_java_version' }
    foreach ($n in $numbers) { if ($n -lt 0 -or $n -gt 100000) { throw 'unrecognized_java_version' } }
    return @{ Numbers = $numbers; Build = $build; Branch = [string]$numbers[0]; Text = (($numbers -join '.') + '+' + $build) }
}
function Compare-EloJavaVersion {
    # -1 when $Left is older than $Right, 0 when equal, 1 when newer.
    param([Parameter(Mandatory = $true)]$Left, [Parameter(Mandatory = $true)]$Right)
    $length = [Math]::Max($Left.Numbers.Count, $Right.Numbers.Count)
    for ($i = 0; $i -lt $length; $i++) {
        $a = 0; if ($i -lt $Left.Numbers.Count) { $a = $Left.Numbers[$i] }
        $b = 0; if ($i -lt $Right.Numbers.Count) { $b = $Right.Numbers[$i] }
        if ($a -ne $b) { if ($a -lt $b) { return -1 } else { return 1 } }
    }
    if ($Left.Build -ne $Right.Build) { if ($Left.Build -lt $Right.Build) { return -1 } else { return 1 } }
    return 0
}
function ConvertFrom-EloJsonArray {
    # Windows PowerShell 5.1 returns a JSON array as ONE object; always enumerate it.
    param([string]$Text)
    $parsed = ConvertFrom-Json $Text
    return @($parsed | ForEach-Object { $_ })
}
function Invoke-EloCatalogGet {
    # Bounded HTTPS GET to an allowlisted vendor API host: no redirects, no cookies,
    # 2 MiB cap, 20 s timeout, TLS 1.2 enabled only for the duration of the request.
    param([Parameter(Mandatory = $true)][string]$Uri, [Parameter(Mandatory = $true)][string[]]$AllowedHosts)
    $target = Assert-EloHttpsHost $Uri $AllowedHosts
    $previous = [Net.ServicePointManager]::SecurityProtocol
    [Net.ServicePointManager]::SecurityProtocol = $previous -bor [Net.SecurityProtocolType]::Tls12
    $response = $null
    try {
        $request = [Net.HttpWebRequest]::Create($target)
        $request.AllowAutoRedirect = $false; $request.UseDefaultCredentials = $false
        $request.Timeout = 20000; $request.ReadWriteTimeout = 20000; $request.UserAgent = 'ELO-Patch-Tools'
        $response = $request.GetResponse()
        if ([int]$response.StatusCode -ne 200) { throw 'catalog_http_status' }
        $stream = $response.GetResponseStream(); $buffer = New-Object byte[] 8192
        $memory = New-Object IO.MemoryStream
        try {
            while (($count = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                $memory.Write($buffer, 0, $count)
                if ($memory.Length -gt 2MB) { throw 'catalog_response_too_large' }
            }
            return [Text.Encoding]::UTF8.GetString($memory.ToArray())
        } finally { $memory.Dispose(); $stream.Dispose() }
    } finally { if ($response) { $response.Dispose() }; [Net.ServicePointManager]::SecurityProtocol = $previous }
}
function Assert-EloReleaseRecord {
    # Strict validation of a resolved release. The vendor policy, not the record,
    # decides which hosts and URL shapes are acceptable. Returns a normalized copy.
    param([Parameter(Mandatory = $true)]$Record)
    $policies = Get-EloVendorPolicy
    $vendor = [string]$Record.Vendor
    if (-not $policies.ContainsKey($vendor)) { throw 'unsupported_vendor' }
    $policy = $policies[$vendor]
    if ([string]$Record.Branch -cnotmatch '^\d{1,2}$') { throw 'invalid_release_branch' }
    if ([string]$Record.Architecture -cnotin @('x86', 'x64', 'ARM64')) { throw 'invalid_release_architecture' }
    if ([string]$Record.ImageType -cnotin @('jdk', 'jre')) { throw 'invalid_release_image_type' }
    $version = ConvertTo-EloJavaVersion ([string]$Record.Version)
    if ($version.Branch -cne [string]$Record.Branch) { throw 'release_branch_mismatch' }
    if ([string]$Record.Sha256 -cnotmatch '^[a-fA-F0-9]{64}$') { throw 'invalid_release_checksum' }
    [long]$size = 0
    if (-not [long]::TryParse([string]$Record.Size, [ref]$size) -or $size -lt 1MB -or $size -gt 800MB) { throw 'invalid_release_size' }
    $uri = Assert-EloHttpsHost ([string]$Record.Uri) $policy.DownloadHosts
    if ($uri.AbsolutePath -cnotmatch $policy.PathPattern -or $uri.Query) { throw 'unverified_release_uri' }
    $null = $uri.AbsolutePath -cmatch $policy.PathPattern
    $expectedImage = $Matches[1]
    $name = $uri.AbsolutePath.Substring($uri.AbsolutePath.LastIndexOf('/') + 1)
    if ($expectedImage -cne [string]$Record.ImageType) { throw 'release_image_mismatch' }
    return @{
        Vendor = $vendor; Branch = [string]$Record.Branch; Architecture = [string]$Record.Architecture; ImageType = [string]$Record.ImageType
        Version = $version.Text; Uri = $uri.AbsoluteUri; Sha256 = ([string]$Record.Sha256).ToLowerInvariant(); Size = $size
        Format = 'zip'; AllowedHosts = @($policy.DownloadHosts); Name = $name
        MaxArchiveBytes = [long]($size + 1MB); MaxExpandedBytes = [long]2GB
    }
}
function Get-EloZuluRelease {
    param([string]$Branch, [string]$Architecture, [string]$ImageType, [scriptblock]$Getter)
    $apiArch = @{ x64 = 'x64'; x86 = 'x86'; ARM64 = 'arm' }[$Architecture]
    $suffix = @{ x64 = 'win_x64'; x86 = 'win_i686'; ARM64 = 'win_aarch64' }[$Architecture]
    $list = 'https://api.azul.com/metadata/v1/zulu/packages/?java_version=' + $Branch + '&os=windows&arch=' + $apiArch +
        '&archive_type=zip&java_package_type=' + $ImageType + '&latest=true&release_status=ga&availability_types=CA&page_size=100'
    $items = ConvertFrom-EloJsonArray (& $Getter $list @('api.azul.com'))
    $best = $null; $bestVersion = $null
    foreach ($item in $items) {
        $name = [string]$item.name
        # Plain builds only: no CRaC, no JavaFX bundle.
        if ($name -cnotmatch ('^zulu[0-9.]+-ca-' + $ImageType + '[0-9.]+-' + $suffix + '\.zip$')) { continue }
        if (@($item.java_version).Count -lt 1 -or [string]$item.java_version[0] -cne $Branch) { continue }
        $candidate = ConvertTo-EloJavaVersion (((@($item.java_version) | ForEach-Object { [string]$_ }) -join '.') + '+' + [int]$item.openjdk_build_number)
        if ($null -eq $best -or (Compare-EloJavaVersion $candidate $bestVersion) -gt 0) { $best = $item; $bestVersion = $candidate }
    }
    if ($null -eq $best) { throw 'no_release_found' }
    $detail = (& $Getter ('https://api.azul.com/metadata/v1/zulu/packages/' + [string]$best.package_uuid) @('api.azul.com')) | ConvertFrom-Json
    if ([string]$best.package_uuid -cnotmatch '^[0-9a-f-]{36}$' -or [string]$detail.name -cne [string]$best.name -or
        [string]$detail.package_uuid -cne [string]$best.package_uuid -or [string]$detail.os -cne 'windows') { throw 'catalog_detail_mismatch' }
    return @{ Vendor = 'Azul Zulu'; Branch = $Branch; Architecture = $Architecture; ImageType = $ImageType; Version = $bestVersion.Text
        Uri = [string]$detail.download_url; Sha256 = [string]$detail.sha256_hash; Size = [long]$detail.size }
}
function Get-EloTemurinRelease {
    param([string]$Branch, [string]$Architecture, [string]$ImageType, [scriptblock]$Getter)
    $apiArch = @{ x64 = 'x64'; x86 = 'x32'; ARM64 = 'aarch64' }[$Architecture]
    $uri = 'https://api.adoptium.net/v3/assets/latest/' + $Branch + '/hotspot?architecture=' + $apiArch + '&image_type=' + $ImageType + '&os=windows&vendor=eclipse'
    $items = ConvertFrom-EloJsonArray (& $Getter $uri @('api.adoptium.net'))
    $best = $null; $bestVersion = $null
    foreach ($item in $items) {
        if ([string]$item.binary.os -cne 'windows' -or [string]$item.binary.image_type -cne $ImageType -or [string]$item.binary.jvm_impl -cne 'hotspot') { continue }
        $candidate = ConvertTo-EloJavaVersion ([string]$item.version.openjdk_version)
        if ($candidate.Branch -cne $Branch) { continue }
        if ($null -eq $best -or (Compare-EloJavaVersion $candidate $bestVersion) -gt 0) { $best = $item; $bestVersion = $candidate }
    }
    if ($null -eq $best) { throw 'no_release_found' }
    $package = $best.binary.package
    return @{ Vendor = 'Eclipse Adoptium'; Branch = $Branch; Architecture = $Architecture; ImageType = $ImageType; Version = $bestVersion.Text
        Uri = [string]$package.link; Sha256 = [string]$package.checksum; Size = [long]$package.size }
}
function Resolve-EloLatestRelease {
    # Newest GA release of the SAME vendor, branch, architecture and image type.
    param([Parameter(Mandatory = $true)][string]$Vendor, [Parameter(Mandatory = $true)][string]$Branch,
        [Parameter(Mandatory = $true)][string]$Architecture, [string]$ImageType = 'jdk',
        [scriptblock]$Getter = { param($Uri, $Hosts) Invoke-EloCatalogGet $Uri $Hosts })
    if ($Branch -cnotmatch '^\d{1,2}$' -or $Architecture -cnotin @('x86', 'x64', 'ARM64') -or $ImageType -cnotin @('jdk', 'jre')) { throw 'invalid_release_request' }
    $raw = $null
    switch ($Vendor) {
        'Azul Zulu' { $raw = Get-EloZuluRelease $Branch $Architecture $ImageType $Getter }
        'Eclipse Adoptium' { $raw = Get-EloTemurinRelease $Branch $Architecture $ImageType $Getter }
        default { throw 'unsupported_vendor' }
    }
    return Assert-EloReleaseRecord $raw
}
::ELO_PATCH_END:CATALOG_PS

::ELO_PATCH_BEGIN:VULNDB_PS
# Vulnerability catalog engine (Windows PowerShell 5.1). Dot-source to load; no startup work.
# The catalog (vulndb.json) holds everything about a vulnerability: detection probes (java.exe argument
# lists, never a shell), expect patterns, problem/solution messages, fix actions and report text.
# A catalog entry can only reference a fixed set of action TYPES and a fixed set of argument shapes, so a
# new or AI-drafted entry can never run an arbitrary command. Drafts (status "draft") are validated but
# never used by the scan. Passwords and API keys never belong in the catalog.

$script:EloVulnPlaceholders = @('vendor','version','id','alias','option','runtime','count','vulnerable','n','list','variable','old','new','kind')
$script:EloVulnSeverities = @('high','medium','low')
$script:EloVulnStatuses = @('active','draft','retired')
$script:EloActionTypes = @('runtime-update','jvm-option','restore-backup')
$script:EloVulnCache = $null

function Get-EloVulnDbPath {
    # Reviewed catalog installed by the tool (see Install-EloVulnDb) wins over the packaged one.
    param([string]$ProgramDataRoot = $env:ProgramData)
    if ($ProgramDataRoot) {
        $installed = Join-Path (Join-Path $ProgramDataRoot 'ELO-Patch-Tools') 'vulndb.json'
        if (Test-Path -LiteralPath $installed -PathType Leaf) { return $installed }
    }
    return (Join-Path $PSScriptRoot 'vulndb.json')
}
function Test-EloVulnProbeArgs {
    param($Args_)
    $list = @($Args_)
    if ($list.Count -lt 1 -or $list.Count -gt 6) { return $false }
    foreach ($a in $list) { if ($a -isnot [string] -or $a -cnotmatch '^-[A-Za-z0-9:+=_.\-]{1,64}$') { return $false } }
    return $true
}
function Test-EloRegex {
    param([string]$Pattern)
    if ([string]::IsNullOrEmpty($Pattern) -or $Pattern.Length -gt 512) { return $false }
    try { $null = New-Object Text.RegularExpressions.Regex($Pattern, [Text.RegularExpressions.RegexOptions]::None, [TimeSpan]::FromSeconds(2)); return $true } catch { return $false }
}
function Test-EloBilingualText {
    param($Value, [int]$Max = 4096)
    if ($null -eq $Value) { return $false }
    foreach ($lang in @('en','de')) {
        $t = $Value.$lang
        if ($t -isnot [string] -or $t.Trim().Length -lt 1 -or $t.Length -gt $Max -or $t -match '[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]') { return $false }
        foreach ($m in [regex]::Matches($t, '\{([A-Za-z]+)\}')) { if ($script:EloVulnPlaceholders -cnotcontains $m.Groups[1].Value) { return $false } }
    }
    return $true
}
function Test-EloVulnDb {
    # Returns the list of problems (empty = valid). Pure validation: reads nothing, runs nothing.
    param($Db)
    $errors = New-Object 'System.Collections.Generic.List[string]'
    if ($null -eq $Db -or $Db.schemaVersion -ne 1) { $errors.Add('schemaVersion must be 1'); return $errors.ToArray() }
    foreach ($s in @($Db.sources)) {
        if ($s.url -isnot [string] -or $s.url -cnotmatch '^https://[A-Za-z0-9.\-]+(:[0-9]+)?/[^\s"<>]{0,512}$') { $errors.Add("source '$($s.id)': url must be https") }
        if ($s.PSObject.Properties.Name -contains 'password' -or $s.PSObject.Properties.Name -contains 'apiKey') { $errors.Add("source '$($s.id)': credentials are not allowed in the catalog") }
    }
    $seen = @{}
    $vulns = @($Db.vulnerabilities)
    if ($vulns.Count -gt 200) { $errors.Add('too many vulnerabilities') }
    foreach ($v in $vulns) {
        $id = [string]$v.id
        $where = "vulnerability '$id'"
        if ($id -cnotmatch '^[A-Za-z0-9._\-]{3,64}$') { $errors.Add("${where}: invalid id"); continue }
        if ($seen.ContainsKey($id)) { $errors.Add("${where}: duplicate id") }
        $seen[$id] = $true
        if ($script:EloVulnSeverities -cnotcontains [string]$v.severity) { $errors.Add("${where}: severity must be high, medium or low") }
        if ($script:EloVulnStatuses -cnotcontains [string]$v.status) { $errors.Add("${where}: status must be active, draft or retired") }
        foreach ($field in @('title','problem','solution')) { if (-not (Test-EloBilingualText $v.$field 2048)) { $errors.Add("${where}: $field needs English and German text") } }
        foreach ($adv in @($v.advisories)) {
            if ($adv.url -isnot [string] -or $adv.url -cnotmatch '^https://[A-Za-z0-9.\-]+/[^\s"<>]{0,512}$') { $errors.Add("${where}: advisory '$($adv.id)' url must be https") }
            if (-not (Test-EloBilingualText $adv.title 512)) { $errors.Add("${where}: advisory '$($adv.id)' title needs English and German text") }
        }
        $det = $v.detection
        if ($null -eq $det -or @('version-table','probe-expect') -cnotcontains [string]$det.method) { $errors.Add("${where}: detection.method must be version-table or probe-expect") }
        else {
            $probes = @($det.probes)
            if ($probes.Count -lt 1 -or $probes.Count -gt 4) { $errors.Add("${where}: 1 to 4 probes are required") }
            $probeIds = @{}
            foreach ($p in $probes) {
                if ([string]$p.id -cnotmatch '^[a-z0-9\-]{1,32}$' -or $probeIds.ContainsKey([string]$p.id)) { $errors.Add("${where}: probe id invalid or duplicated") }
                $probeIds[[string]$p.id] = $true
                if (-not (Test-EloVulnProbeArgs $p.args)) { $errors.Add("${where}: probe '$($p.id)' args must be java.exe options such as -version (no shell, no paths)") }
                if ($null -ne $p.timeoutSec -and ([int]$p.timeoutSec -lt 1 -or [int]$p.timeoutSec -gt 60)) { $errors.Add("${where}: probe '$($p.id)' timeoutSec must be 1..60") }
                foreach ($e in @($p.expect)) { if (-not (Test-EloRegex ([string]$e.pattern))) { $errors.Add("${where}: probe '$($p.id)' expect '$($e.id)' is not a valid pattern") } }
            }
            if ([string]$det.method -ceq 'version-table') {
                $vendors = $det.vendors
                if ($null -eq $vendors -or @($vendors.PSObject.Properties).Count -lt 1) { $errors.Add("${where}: version-table needs vendors") }
                else {
                    foreach ($prop in $vendors.PSObject.Properties) {
                        if ($prop.Name -cnotmatch '^[A-Za-z0-9 ]{1,32}$') { $errors.Add("${where}: vendor name invalid"); continue }
                        if (@('temurin-build') -cnotcontains [string]$prop.Value.parser) { $errors.Add("${where}: vendor '$($prop.Name)' parser is not supported") }
                        $fixed = @($prop.Value.fixed)
                        if ($fixed.Count -lt 1 -or $fixed.Count -gt 64) { $errors.Add("${where}: vendor '$($prop.Name)' needs 1 to 64 fixed builds") }
                        foreach ($f in $fixed) { if ([string]$f -cnotmatch '^[0-9]{1,3}(\.[0-9]{1,9}){0,3}\+[0-9]{1,9}$') { $errors.Add("${where}: fixed build '$f' is not a Java build such as 17.0.21.1+2") } }
                        if ([string]$prop.Value.fixedSource -cnotmatch '^https://[A-Za-z0-9.\-]+/[^\s"<>]{0,512}$') { $errors.Add("${where}: vendor '$($prop.Name)' fixedSource must be https") }
                    }
                }
            } else {
                $rule = $det.rule
                if ($null -eq $rule -or -not (Test-EloRegex ([string]$rule.vulnerablePattern)) -or ($rule.safePattern -and -not (Test-EloRegex ([string]$rule.safePattern))) -or [string]$rule.probe -cnotmatch '^[a-z0-9\-]{1,32}$' -or -not $probeIds.ContainsKey([string]$rule.probe)) { $errors.Add("${where}: probe-expect needs rule.probe and rule.vulnerablePattern") }
            }
        }
        $actionIds = @{}
        foreach ($a in @($v.actions)) {
            $aid = [string]$a.id
            if ($aid -cnotmatch '^[a-z0-9\-]{1,32}$' -or $actionIds.ContainsKey($aid)) { $errors.Add("${where}: action id invalid or duplicated"); continue }
            $actionIds[$aid] = $true
            if ($script:EloActionTypes -cnotcontains [string]$a.type) { $errors.Add("${where}: action '$aid' type must be one of $($script:EloActionTypes -join ', ')"); continue }
            if (-not (Test-EloBilingualText $a.label 128)) { $errors.Add("${where}: action '$aid' label needs English and German text") }
            if ([string]$a.type -ceq 'jvm-option') {
                if ([string]$a.variable -cne 'JAVA_TOOL_OPTIONS') { $errors.Add("${where}: action '$aid' variable must be JAVA_TOOL_OPTIONS") }
                if ([string]$a.option -cnotmatch '^-XX:[+-][A-Za-z0-9_]{1,64}$') { $errors.Add("${where}: action '$aid' option must be one -XX:+/-Flag") }
                if ([string]$a.conflictPattern -cnotmatch '^[A-Za-z0-9_]{1,64}$') { $errors.Add("${where}: action '$aid' conflictPattern invalid") }
                if (-not (Test-EloBilingualText $a.summary 4096)) { $errors.Add("${where}: action '$aid' summary needs English and German text") }
                if ($null -ne $a.verify) {
                    if (-not (Test-EloVulnProbeArgs $a.verify.args) -or -not (Test-EloRegex ([string]$a.verify.expect)) -or @('true','false') -cnotcontains [string]$a.verify.mustBe) { $errors.Add("${where}: action '$aid' verify is invalid") }
                }
            }
        }
        $actives = @($v.actions | Where-Object { $_.type -ceq 'jvm-option' })
        if ($actives.Count -gt 1) { $errors.Add("${where}: at most one jvm-option action") }
        foreach ($name in @('restoreVulnerable','restoreFixed','restoreUnknown')) { if ($null -ne $v.messages -and $null -ne $v.messages.$name -and -not (Test-EloBilingualText $v.messages.$name 2048)) { $errors.Add("${where}: messages.$name needs English and German text") } }
        if ($null -ne $v.report -and $null -ne $v.report.headline -and -not (Test-EloBilingualText $v.report.headline 512)) { $errors.Add("${where}: report.headline needs English and German text") }
        $sim = $v.simulation
        if ($null -ne $sim) {
            foreach ($prop in @($sim.probes.PSObject.Properties)) { if ($prop.Value -isnot [string] -or $prop.Value.Length -gt 8192) { $errors.Add("${where}: simulation probe '$($prop.Name)' must be text up to 8 KiB") } }
        }
    }
    return $errors.ToArray()
}
function Read-EloVulnDbFile {
    param([Parameter(Mandatory=$true)][string]$Path)
    $info = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($info.PSIsContainer -or ($info.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'vulndb_not_a_file' }
    if ($info.Length -gt 1MB) { throw 'vulndb_too_large' }
    $text = [IO.File]::ReadAllText($info.FullName, (New-Object Text.UTF8Encoding($false,$true)))
    try { $db = $text | ConvertFrom-Json } catch { throw 'vulndb_invalid_json' }
    $problems = @(Test-EloVulnDb $db)
    if ($problems.Count -gt 0) { throw ('vulndb_invalid: ' + (($problems | Select-Object -First 5) -join '; ')) }
    return $db
}
function Get-EloVulnDb {
    param([string]$Path, [switch]$Refresh)
    if (-not $Path -and $script:EloVulnCache -and -not $Refresh) { return $script:EloVulnCache }
    $explicit = [bool]$Path
    if (-not $Path) { $Path = Get-EloVulnDbPath }
    try { $db = Read-EloVulnDbFile $Path }
    catch {
        # A broken installed catalog never disables detection: fall back to the packaged one.
        $packaged = Join-Path $PSScriptRoot 'vulndb.json'
        if ($explicit -or $Path -ceq $packaged) { throw }
        $db = Read-EloVulnDbFile $packaged
    }
    if (-not $explicit) { $script:EloVulnCache = $db }
    return $db
}
function Get-EloActiveVulnerabilities {
    param($Db = (Get-EloVulnDb))
    return @($Db.vulnerabilities | Where-Object { $_.status -ceq 'active' })
}
function Format-EloVulnText {
    # Replaces {name} placeholders from a fixed allowlist; unknown names are left untouched. Never evaluates anything.
    param([AllowNull()][string]$Template, [hashtable]$Values = @{})
    if ($null -eq $Template) { return '' }
    return [regex]::Replace($Template, '\{([A-Za-z]+)\}', {
        param($m)
        $key = $m.Groups[1].Value
        if ($script:EloVulnPlaceholders -ccontains $key -and $Values.ContainsKey($key)) { return [string]$Values[$key] }
        return $m.Value
    })
}
function Get-EloVulnText {
    param($Bilingual, [ValidateSet('en','de')][string]$Language = 'en', [hashtable]$Values = @{})
    return (Format-EloVulnText ([string]$Bilingual.$Language) $Values)
}
function Get-EloVulnAction {
    param($Vulnerability, [string]$Type)
    return @($Vulnerability.actions | Where-Object { $_.type -ceq $Type }) | Select-Object -First 1
}
function Get-EloScanRules {
    # What the scanner needs per active vulnerability: version-table rules (fixed builds per vendor) and
    # probe-expect rules (a java probe plus the patterns that mean vulnerable / safe).
    param($Db = (Get-EloVulnDb))
    $rules = New-Object 'System.Collections.Generic.List[object]'
    foreach ($v in (Get-EloActiveVulnerabilities $Db)) {
        if ([string]$v.detection.method -ceq 'version-table') {
            foreach ($prop in $v.detection.vendors.PSObject.Properties) {
                $rules.Add(@{ Id = [string]$v.id; Severity = [string]$v.severity; Method = 'version-table'; Vendor = [string]$prop.Name; Parser = [string]$prop.Value.parser
                    Fixed = @($prop.Value.fixed | ForEach-Object { [string]$_ }); Source = [string]$prop.Value.fixedSource })
            }
        } elseif ([string]$v.detection.method -ceq 'probe-expect') {
            $probe = @($v.detection.probes | Where-Object { $_.id -ceq [string]$v.detection.rule.probe })[0]
            $timeout = 15; if ($probe.timeoutSec) { $timeout = [int]$probe.timeoutSec }
            $source = ''; if (@($v.advisories).Count -gt 0) { $source = [string]@($v.advisories)[0].url }
            $rules.Add(@{ Id = [string]$v.id; Severity = [string]$v.severity; Method = 'probe-expect'; ProbeArgs = @($probe.args | ForEach-Object { [string]$_ }); TimeoutSec = $timeout
                VulnerablePattern = [string]$v.detection.rule.vulnerablePattern; SafePattern = [string]$v.detection.rule.safePattern; Source = $source })
        }
    }
    return $rules.ToArray()
}function Get-EloPrimaryVulnerability {
    param($Db = (Get-EloVulnDb))
    return (Get-EloActiveVulnerabilities $Db | Select-Object -First 1)
}
function Test-EloExpect {
    # Evaluates every expect pattern of a probe against its output: {id -> matched}.
    param($Probe, [AllowEmptyString()][string]$Output)
    $result = [ordered]@{}
    foreach ($e in @($Probe.expect)) {
        $re = New-Object Text.RegularExpressions.Regex([string]$e.pattern, [Text.RegularExpressions.RegexOptions]::None, [TimeSpan]::FromSeconds(2))
        try { $result[[string]$e.id] = $re.IsMatch($Output) } catch { $result[[string]$e.id] = $false }
    }
    return $result
}
function Invoke-EloVulnProbe {
    # Runs one catalog probe through $Runner (real: java.exe with the argument list; simulated: canned text).
    param($Probe, [Parameter(Mandatory=$true)][scriptblock]$Runner)
    if (-not (Test-EloVulnProbeArgs $Probe.args)) { throw 'probe_args_rejected' }
    $output = [string](& $Runner @($Probe.args))
    return @{ Id = [string]$Probe.id; Output = $output; Expect = (Test-EloExpect $Probe $output) }
}
function Invoke-EloVulnSimulation {
    # Replays the entry's simulation probes through the real detection (scan.ps1 must be loaded) and compares the
    # outcome with simulation.expected. This is how a new catalog entry (also a draft) is tested without a vulnerable
    # Java: the entry is evaluated as if it were active, on canned probe output, never on the machine.
    param($Vulnerability, $Db = $null)
    $sim = $Vulnerability.simulation
    if ($null -eq $sim -or $null -eq $sim.expected) { return @{ Passed = $false; Reason = 'no_simulation' } }
    $copy = $Vulnerability | ConvertTo-Json -Depth 20 | ConvertFrom-Json
    $copy.status = 'active'
    $rules = @(Get-EloScanRules ([pscustomobject]@{ vulnerabilities = @($copy) }))
    if ($rules.Count -eq 0) { return @{ Passed = $false; Reason = 'no_rule' } }
    if ([string]$copy.detection.method -ceq 'probe-expect') {
        $rule = $rules[0]
        $prop = $sim.probes.PSObject.Properties[[string]$copy.detection.rule.probe]
        if ($null -eq $prop) { return @{ Passed = $false; Reason = 'no_probe_output' } }
        $re = New-Object Text.RegularExpressions.Regex([string]$rule.VulnerablePattern, [Text.RegularExpressions.RegexOptions]::None, [TimeSpan]::FromSeconds(2))
        $status = 'Inconclusive'
        if ($re.IsMatch([string]$prop.Value)) { $status = 'PotentiallyVulnerable' }
        elseif ($rule.SafePattern -and (New-Object Text.RegularExpressions.Regex([string]$rule.SafePattern, [Text.RegularExpressions.RegexOptions]::None, [TimeSpan]::FromSeconds(2))).IsMatch([string]$prop.Value)) { $status = 'KnownFixed' }
        return @{ Passed = ($status -ceq [string]$sim.expected.status); Status = $status; Vendor = ''; Version = '' }
    }
    $c = Get-EloJavaClassification -Evidence ([string]$sim.probes.version) -Rules $rules
    $ok = ($c.Status -ceq [string]$sim.expected.status -and $c.Vendor -ceq [string]$sim.expected.vendor -and [string]$c.FullVersion -ceq [string]$sim.expected.version)
    return @{ Passed = $ok; Status = $c.Status; Vendor = $c.Vendor; Version = $c.FullVersion }
}
# ---- quarantine: every file the tool is about to modify is copied here first, with a manifest and a hash.
function Get-EloQuarantineRoot {
    param([string]$ProgramDataRoot = $env:ProgramData)
    if ([string]::IsNullOrWhiteSpace($ProgramDataRoot)) { throw 'quarantine_root_unavailable' }
    return (Join-Path (Join-Path $ProgramDataRoot 'ELO-Patch-Tools') 'quarantine')
}
function Get-EloFileSha256 {
    param([string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash
}
function Backup-EloFileToQuarantine {
    # Copies $Path into quarantine\<stamp>-<name>\ (file + manifest.json). Returns the record. Never deletes.
    param([Parameter(Mandatory=$true)][string]$Path, [Parameter(Mandatory=$true)][string]$Reason, [string]$Root = (Get-EloQuarantineRoot))
    $full = [IO.Path]::GetFullPath($Path)
    $info = Get-Item -LiteralPath $full -Force -ErrorAction Stop
    if ($info.PSIsContainer -or ($info.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'quarantine_source_not_a_file' }
    $stamp = [DateTime]::UtcNow.ToString('yyyyMMddHHmmssfff')
    $leaf = ($info.Name -creplace '[^A-Za-z0-9._\-]', '_')
    $id = $stamp + '-' + $leaf
    $dir = Join-Path $Root $id
    $null = [IO.Directory]::CreateDirectory($dir)
    $copy = Join-Path $dir $leaf
    [IO.File]::Copy($info.FullName, $copy, $false)
    $hash = Get-EloFileSha256 $copy
    if ($hash -cne (Get-EloFileSha256 $info.FullName)) { throw 'quarantine_copy_mismatch' }
    $record = [ordered]@{ id = $id; originalPath = $info.FullName; file = $leaf; sha256 = $hash; size = $info.Length; reason = $Reason; createdUtc = [DateTime]::UtcNow.ToString('o') }
    [IO.File]::WriteAllText((Join-Path $dir 'manifest.json'), ($record | ConvertTo-Json), (New-Object Text.UTF8Encoding($false)))
    return [pscustomobject]$record
}
function Get-EloQuarantineEntries {
    param([string]$Root = (Get-EloQuarantineRoot))
    if (-not (Test-Path -LiteralPath $Root -PathType Container)) { return @() }
    $entries = @()
    foreach ($dir in @(Get-ChildItem -LiteralPath $Root -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending | Select-Object -First 200)) {
        $manifest = Join-Path $dir.FullName 'manifest.json'
        if (-not (Test-Path -LiteralPath $manifest -PathType Leaf)) { continue }
        try { $m = [IO.File]::ReadAllText($manifest) | ConvertFrom-Json } catch { continue }
        if ($m.id -cne $dir.Name -or [string]$m.file -cnotmatch '^[A-Za-z0-9._\-]{1,128}$') { continue }
        $entries += $m
    }
    return @($entries)
}
function Restore-EloFileFromQuarantine {
    # Puts a quarantined copy back at its original path. The file being replaced is quarantined first, so a
    # restore can itself be undone. The copy's SHA256 is verified before and after.
    param([Parameter(Mandatory=$true)][string]$Id, [string]$Root = (Get-EloQuarantineRoot))
    if ($Id -cnotmatch '^[0-9]{17}-[A-Za-z0-9._\-]{1,128}$') { throw 'quarantine_id_invalid' }
    $dir = Join-Path $Root $Id
    $manifestPath = Join-Path $dir 'manifest.json'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) { throw 'quarantine_entry_missing' }
    $m = [IO.File]::ReadAllText($manifestPath) | ConvertFrom-Json
    $source = Join-Path $dir ([string]$m.file)
    if ((Get-EloFileSha256 $source) -cne [string]$m.sha256) { throw 'quarantine_hash_mismatch' }
    $target = [string]$m.originalPath
    if ([string]::IsNullOrWhiteSpace($target) -or -not [IO.Path]::IsPathRooted($target)) { throw 'quarantine_target_invalid' }
    $replaced = $null
    if (Test-Path -LiteralPath $target -PathType Leaf) { $replaced = Backup-EloFileToQuarantine -Path $target -Reason ('replaced by restore of ' + $Id) -Root $Root }
    $null = [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($target))
    $temp = $target + '.restore-' + [guid]::NewGuid().ToString('N')
    [IO.File]::Copy($source, $temp, $false)
    if ((Get-EloFileSha256 $temp) -cne [string]$m.sha256) { Remove-Item -LiteralPath $temp -Force; throw 'quarantine_restore_mismatch' }
    if (Test-Path -LiteralPath $target -PathType Leaf) { [IO.File]::Delete($target) }
    [IO.File]::Move($temp, $target)
    return [pscustomobject]@{ restored = $target; from = $Id; replacedCopy = $(if ($replaced) { $replaced.id } else { $null }) }
}
function Install-EloVulnDb {
    # Installs a reviewed catalog: validate -> quarantine the current installed copy -> atomic replace -> verify.
    param([Parameter(Mandatory=$true)][string]$Source, [string]$ProgramDataRoot = $env:ProgramData)
    $null = Read-EloVulnDbFile $Source
    $targetDir = Join-Path $ProgramDataRoot 'ELO-Patch-Tools'
    $target = Join-Path $targetDir 'vulndb.json'
    $null = [IO.Directory]::CreateDirectory($targetDir)
    $backup = $null
    if (Test-Path -LiteralPath $target -PathType Leaf) { $backup = Backup-EloFileToQuarantine -Path $target -Reason 'catalog replaced by install' -Root (Get-EloQuarantineRoot $ProgramDataRoot) }
    $temp = $target + '.new-' + [guid]::NewGuid().ToString('N')
    [IO.File]::Copy($Source, $temp, $false)
    try {
        $null = Read-EloVulnDbFile $temp
        if (Test-Path -LiteralPath $target -PathType Leaf) { [IO.File]::Delete($target) }
        [IO.File]::Move($temp, $target)
    } catch { if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force }; throw }
    if ((Get-EloFileSha256 $target) -cne (Get-EloFileSha256 $Source)) { throw 'vulndb_install_mismatch' }
    $script:EloVulnCache = $null
    return [pscustomobject]@{ installed = $target; quarantined = $(if ($backup) { $backup.id } else { $null }) }
}
::ELO_PATCH_END:VULNDB_PS

::ELO_PATCH_BEGIN:VULNDB_JSON
{
  "schemaVersion": 1,
  "updated": "2026-11-25",
  "description": "Vulnerability catalog of ELO Patch Tools. Everything the tool knows about a vulnerability lives here: how to detect it (java.exe argument lists + expect patterns), the problem message, the actions that fix it and the final report text. Add an entry to support a new vulnerability. No passwords or API keys belong in this file.",
  "sources": [
    {
      "id": "elo-community-kbb103",
      "type": "elo-community",
      "title": "ELO Community knowledge board KBB103 (vulnerability reports)",
      "url": "https://community.elo.com/community/plugin/de.elo.ix.plugin.proxy/wf/apps/app/sol.knowledge.apps.KnowledgeBoard/#/?board=KBB103&page=1",
      "access": "login required; credentials are read from the environment (ELO_COMMUNITY_USER, ELO_COMMUNITY_PASSWORD), never stored here"
    }
  ],
  "vulnerabilities": [
    {
      "id": "CVE-2026-114938",
      "aliases": ["Java4Shell"],
      "severity": "high",
      "status": "active",
      "origin": "built-in",
      "title": {
        "en": "CVE-2026-114938 (Java4Shell): flawed JIT BASE64 intrinsics",
        "de": "CVE-2026-114938 (Java4Shell): fehlerhafte JIT-BASE64-Intrinsics"
      },
      "verifiedOn": "2026-11-23",
      "advisories": [
        {
          "id": "temurin-november-2026",
          "url": "https://adoptium.net/news/2026/11/temurin-november-2026-cspu-java4shell/",
          "title": {
            "en": "Temurin vendor advisory: parent fetched directly (2026-11-23); exact listed Temurin builds only",
            "de": "Temurin-Herstellerhinweis: Elternagent rief direkt ab (2026-11-23); nur exakt aufgefuehrte Temurin-Builds"
          },
          "reportLabel": "Adoptium Temurin November 2026 CSPU",
          "provenanceNote": "Official Adoptium vendor advisory directly fetched by parent.",
          "provenance": "Fetched"
        },
        {
          "id": "oracle-cve-2026-114938",
          "url": "https://linux.oracle.com/cve/CVE-2026-114938.html",
          "title": {
            "en": "Oracle Linux CVE-2026-114938: parent fetched directly (2026-11-23); not ELO compatibility verification",
            "de": "Oracle Linux CVE-2026-114938: Elternagent rief direkt ab (2026-11-23); keine ELO-Kompatibilitaetspruefung"
          },
          "reportLabel": "Oracle CVE-2026-114938",
          "provenanceNote": "Oracle Linux source directly fetched by parent.",
          "provenance": "Fetched"
        },
        {
          "id": "openjdk-2026-11-17",
          "url": "https://openjdk.org/groups/vulnerability/advisories/2026-11-17",
          "title": {
            "en": "OpenJDK advisory: parent reviewed user-supplied text; not fetched directly (2026-11-23)",
            "de": "OpenJDK: Elternagent pruefte vom Benutzer gelieferten Text; nicht direkt abgerufen (2026-11-23)"
          },
          "reportLabel": "OpenJDK 2026-11-17",
          "provenanceNote": "User-supplied OpenJDK text reviewed by parent; not independently fetched.",
          "provenance": "Supplied"
        }
      ],
      "detection": {
        "method": "version-table",
        "probes": [
          {
            "id": "version",
            "args": ["-version"],
            "timeoutSec": 15,
            "expect": [
              { "id": "vendor-temurin", "pattern": "(?i)\\bTemurin\\b", "meaning": "The runtime is Eclipse Temurin" },
              { "id": "build-token", "pattern": "\\(build\\s+[^\\s,)]+", "meaning": "A build token is present for the version comparison" }
            ]
          }
        ],
        "vendors": {
          "Temurin": {
            "parser": "temurin-build",
            "fixed": ["17.0.21.1+2", "21.0.13.1+2", "25.0.5.1+2", "27.0.1.1+4"],
            "fixedSource": "https://adoptium.net/news/2026/11/temurin-november-2026-cspu-java4shell/"
          }
        },
        "unknownVendor": "inconclusive"
      },
      "problem": {
        "en": "{n} runtime(s) are before the fixed release: {list}. The JIT BASE64 intrinsics flaw lets this Java produce wrong results; the vendor fixed it in a newer release.",
        "de": "{n} Runtime(s) liegen vor der behobenen Version: {list}. Der Fehler in den JIT-BASE64-Intrinsics kann falsche Ergebnisse liefern; der Hersteller hat ihn in einer neueren Version behoben."
      },
      "solution": {
        "en": "update Java to the current release of the same branch (step 3, Update Java runtime). The temporary mitigation only reduces the risk until you update.",
        "de": "Java auf die aktuelle Version desselben Branches aktualisieren (Schritt 3, Java-Runtime aktualisieren). Die vorlaeufige Risikominderung senkt das Risiko nur bis zum Update."
      },
      "actions": [
        {
          "id": "update-runtime",
          "type": "runtime-update",
          "recommended": true,
          "label": { "en": "Update Java runtime", "de": "Java-Runtime aktualisieren" }
        },
        {
          "id": "mitigate",
          "type": "jvm-option",
          "scope": "machine-environment",
          "variable": "JAVA_TOOL_OPTIONS",
          "option": "-XX:-UseBASE64Intrinsics",
          "conflictPattern": "UseBASE64Intrinsics",
          "label": { "en": "Temporary mitigation", "de": "Vorlaeufige Risikominderung" },
          "verify": {
            "args": ["-XX:+PrintFlagsFinal", "-version"],
            "expect": "(?m)^\\s*bool\\s+UseBASE64Intrinsics\\s*(?::=|=)\\s*(true|false)\\b[^\\r\\n]*$",
            "mustBe": "false"
          },
          "summary": {
            "en": "Set exactly one {option} in MACHINE {variable}, removing standalone duplicate/conflicting +/- flags (all future inheriting JVMs, not just ELO). Previous value: {old} (registry type: {kind}). New value: [{new}]. Registry type and all other option bytes are preserved. Backup: exact previous value retained in this session. On verification failure restore it automatically; after success use an approved Registry Editor procedure to restore {variable} under HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment with the previous value AND registry type above (delete it if absent). No ELO files are changed. Confirmation authorizes one disposable java -XX:+PrintFlagsFinal -version probe with the proposed options, followed by registry write, readback and a second probe.",
            "de": "Genau einmal {option} in der systemweiten Variable {variable} setzen; eigenstaendige doppelte/widerspruechliche +/- Optionen entfernen (alle kuenftig erbenden JVMs, nicht nur ELO). Alter Wert: {old} (Registrierungstyp: {kind}). Neuer Wert: [{new}]. Typ und alle anderen Optionszeichen bleiben erhalten. Sicherung: exakter alter Wert in dieser Sitzung. Bei Prueffehler automatische Wiederherstellung; nach Erfolg per freigegebenem Registrierungseditor {variable} unter HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment mit altem Wert UND Typ wiederherstellen (bei zuvor fehlendem Wert loeschen). Keine ELO-Dateien werden geaendert. Bestaetigung erlaubt einen Test mit java -XX:+PrintFlagsFinal -version, danach Registrierungsaenderung, Ruecklesen und zweiten Test."
          }
        },
        {
          "id": "restore-backup",
          "type": "restore-backup",
          "label": { "en": "Restore this backup", "de": "Dieses Backup wiederherstellen" }
        }
      ],
      "messages": {
        "restoreVulnerable": {
          "en": "SECURITY: this backup holds {vendor} {version}, which is BEFORE the fix for {id} ({alias}, BASE64 intrinsics). Restoring brings the vulnerability back. After the restore, apply the temporary mitigation ({option}) or update the runtime again.",
          "de": "SICHERHEIT: Dieses Backup enthaelt {vendor} {version}, also eine Version VOR dem Fix fuer {id} ({alias}, BASE64-Intrinsics). Die Wiederherstellung bringt die Schwachstelle zurueck. Nach der Wiederherstellung die temporaere Risikominderung ({option}) anwenden oder die Runtime erneut aktualisieren."
        },
        "restoreFixed": {
          "en": "Security: {vendor} {version} is a build listed as fixed for {id}. This is a narrow advisory classification, not a whole-system safety claim, and ELO compatibility is not verified.",
          "de": "Sicherheit: {vendor} {version} ist ein fuer {id} als behoben aufgefuehrter Build. Das ist eine enge Advisory-Einstufung, keine Gesamtaussage zur Systemsicherheit; die ELO-Kompatibilitaet ist nicht geprueft."
        },
        "restoreUnknown": {
          "en": "SECURITY: the vulnerability status of {vendor} {version} for {id} cannot be determined from the available evidence. Treat it as potentially vulnerable and apply the temporary mitigation ({option}) after the restore.",
          "de": "SICHERHEIT: Der Schwachstellenstatus von {vendor} {version} fuer {id} ist mit den vorhandenen Nachweisen nicht bestimmbar. Als potenziell verwundbar behandeln und nach der Wiederherstellung die temporaere Risikominderung ({option}) anwenden."
        },
        "logRestoreVulnerable": "SECURITY: {runtime} was restored to {version}, which is BEFORE the {id} fix. Update Java again or apply the mitigation ({option}).",
        "logRestoreUnknown": "SECURITY: {runtime} was restored to {version}; its status for {id} is unknown. Treat it as potentially vulnerable.",
        "logRestoreFixed": "Restored {runtime} to {version} (listed as fixed for {id}).",
        "logScan": "Scan finished: {count} Java runtime(s) found, {vulnerable} vulnerable ({id})."
      },
      "report": {
        "headline": {
          "en": "{id} ({alias}): potentially vulnerable runtimes were found",
          "de": "{id} ({alias}): potenziell verwundbare Runtimes wurden gefunden"
        },
        "mitigationDetail": "{option}"
      },
      "simulation": {
        "description": "Makes a runtime look like Temurin 17.0.2+8 (before the fix) so the detection, the alert, the mitigation and the report can be exercised without a vulnerable Java installed.",
        "probes": {
          "version": "openjdk version \"17.0.2\" 2022-01-18\nOpenJDK Runtime Environment Temurin-17.0.2+8 (build 17.0.2+8)\nOpenJDK 64-Bit Server VM Temurin-17.0.2+8 (build 17.0.2+8, mixed mode, sharing)\n",
          "flags": "     bool UseBASE64Intrinsics                      = true                                   {product} {default}\n"
        },
        "expected": { "status": "PotentiallyVulnerable", "vendor": "Temurin", "version": "17.0.2+8" }
      }
    }
  ]
}
::ELO_PATCH_END:VULNDB_JSON
