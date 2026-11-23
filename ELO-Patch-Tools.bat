@echo off
setlocal DisableDelayedExpansion
rem Single-file integration candidate. Automatic runtime update is unavailable.
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
for /f "usebackq delims=" %%D in (`powershell.exe -NoProfile -NonInteractive -Command "$ErrorActionPreference='Stop'; $dir=$null; try { $files=@{BOOTSTRAP_PS='launcher.ps1';BACKEND_PS='backend.ps1';SCAN_PS='scan.ps1';SERVER_PS='server.ps1';CLI_PS='cli.ps1';UI_HTML='ui.html';REPORT_PS='report.ps1'}; $blocks=@{}; $active=$null; $buffer=New-Object 'System.Collections.Generic.List[string]'; foreach($line in [IO.File]::ReadAllLines($env:ELO_PATCH_SOURCE,[Text.Encoding]::UTF8)) { if($line.TrimStart().StartsWith('::ELO_PATCH_',[StringComparison]::OrdinalIgnoreCase)) { if($line -cnotmatch '^::ELO_PATCH_(BEGIN|END):(BOOTSTRAP_PS|BACKEND_PS|SCAN_PS|SERVER_PS|CLI_PS|UI_HTML|REPORT_PS)$') { throw 'Malformed extraction marker' }; $kind=$Matches[1]; $name=$Matches[2]; if($kind -ceq 'BEGIN') { if($null -ne $active -or $blocks.ContainsKey($name)) { throw 'Duplicate or nested extraction marker' }; $active=$name; $buffer.Clear() } else { if($active -cne $name) { throw 'Unmatched extraction marker' }; $blocks[$name]=[string]::Join([Environment]::NewLine,$buffer); $active=$null } } elseif($null -ne $active) { $buffer.Add($line) } }; if($null -ne $active -or $blocks.Count -ne $files.Count) { throw 'Missing extraction marker' }; $id=[guid]::NewGuid().ToString('N'); $dir=Join-Path $env:ELO_PATCH_BASE ('elo-patch-'+$id); [void][IO.Directory]::CreateDirectory($dir); foreach($name in $files.Keys) { [IO.File]::WriteAllText((Join-Path $dir $files[$name]),$blocks[$name],[Text.Encoding]::UTF8) }; Write-Output $id } catch { if($null -ne $dir -and [IO.Directory]::Exists($dir)) { [IO.Directory]::Delete($dir,$true) }; [Console]::Error.WriteLine($_.Exception.Message); exit 1 }"`) do set "ELO_PATCH_SESSION=%ELO_PATCH_BASE%\elo-patch-%%D"
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
. (Join-Path $PSScriptRoot 'cli.ps1')
function New-EloPackagedCliActions {
    param([hashtable]$Session)
    $trusted = New-EloCliBackendAdapters -Session $Session
    $private = @{ BackendPreview=$null; PublicPreview=$null }
    # The CLI serializes its preview into its report. Keep backend capability IDs
    # in this closure, never in that public report or the console preview.
    $preview = {
        param($Result)
        $private.BackendPreview = & $trusted.Preview $Result
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
        & $trusted.Apply $backendPreview
    }.GetNewClosure()
    @{ IsAdmin=$trusted.IsAdmin; Preview=$preview; Apply=$apply }
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
        if ($Arguments -ccontains '--mitigate') {
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
    param([AllowEmptyString()][string]$Evidence)
    $source = 'https://adoptium.net/news/2026/11/temurin-november-2026-cspu-java4shell/'
    $fixed = @('17.0.21.1+2', '21.0.13.1+2', '25.0.5.1+2', '27.0.1.1+4')
    $vendor = 'Unknown'
    if ($Evidence -match '(?i)\bTemurin\b') { $vendor = 'Temurin' }
    # Include VM build tokens as well as runtime tokens: conflicting versions must
    # not disappear merely because a VM line ends with ', mixed mode, sharing)'.
    $builds = @([regex]::Matches($Evidence, '(?i)\(build\s+([^\s,)]+)') | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique)
    $build = $null
    $status = 'Inconclusive'
    $reason = 'Vendor/build evidence is unknown or outside the supported comparison rules; exploitability is not determined.'
    $conflictingVendor = $Evidence -match '(?i)\b(Oracle|Zulu|Corretto|Microsoft|GraalVM|Semeru|OpenJ9|Liberica|SapMachine|Dragonwell)\b'
    $foreignRuntime = @($Evidence -split '\r?\n' | Where-Object { $_ -match '(?i)Runtime Environment' -and $_ -notmatch '(?i)\bTemurin\b' }).Count -gt 0
    if ($conflictingVendor -or $foreignRuntime) { $vendor = 'Unknown' }
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
        [scriptblock]$ShouldCancel = { $false }
    )
    $result = [ordered]@{ Succeeded = $false; Cancelled = $false; Evidence = ''; Error = $null; ExitCode = $null }
    $process = $null
    try {
        if (& $ShouldCancel) { $result.Cancelled = $true; return [pscustomobject]$result }
        if (-not [IO.File]::Exists($JavaPath)) { throw 'Java executable does not exist.' }
        $info = New-Object System.Diagnostics.ProcessStartInfo
        $info.FileName = $JavaPath
        $info.Arguments = '-version'
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
    $state = @{ Cancelled = $false; LimitReached = $false; DepthLimitReached = $false; VisitedEntries = 0 }
    # One global entry budget. Manual scanning runs BEFORE automatic root discovery.
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
                    if (-not $locations.Contains($entry.FullName)) {
                        $locations.Add($entry.FullName)
                        $candidates.Add([pscustomobject]@{ Location = $entry.FullName; EloCandidateRoot = $item.EloRoot; EloPathRationale = $item.Rationale })
                    }
                }
            }
        }
    }
    if (& $ShouldCancel) { $state.Cancelled = $true }
    if (-not $state.Cancelled -and $ManualPath) {
        $queue.Enqueue([pscustomobject]@{ Path = $ManualPath; Depth = 0; EloRoot = $ManualPath; Rationale = 'User-selected explicit manual directory; ELO ownership is not verified.' })
        & $drainQueue
    }
    if (-not $state.Cancelled -and -not $state.LimitReached) {
        if (-not $PSBoundParameters.ContainsKey('DriveRoots')) {
            $DriveRoots = @(Get-PSDrive -PSProvider FileSystem | ForEach-Object { $_.Root })
        }
        foreach ($root in $DriveRoots) {
            if ($state.Cancelled -or $state.LimitReached) { break }
            foreach ($entry in @(& $readChildren $root)) {
                if (-not $entry.PSIsContainer -or ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint)) { continue }
                if ($entry.Name -match '^(?i:ELO)') {
                    $queue.Enqueue([pscustomobject]@{ Path = $entry.FullName; Depth = 0; EloRoot = $entry.FullName; Rationale = "ELO-prefix directory name heuristic under drive root $root; ELO ownership is not verified." })
                } elseif ($entry.Name -in @('Program Files', 'Program Files (x86)', 'ProgramData')) {
                    foreach ($child in @(& $readChildren $entry.FullName)) {
                        if ($child.PSIsContainer -and $child.Name -match '^(?i:ELO)' -and -not ($child.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                            $queue.Enqueue([pscustomobject]@{ Path = $child.FullName; Depth = 0; EloRoot = $child.FullName; Rationale = "ELO-prefix directory name heuristic under $($entry.FullName); ELO ownership is not verified." })
                        }
                    }
                }
            }
        }
        & $drainQueue
    }
    [pscustomobject]@{
        Locations = $locations.ToArray(); Candidates = $candidates.ToArray(); Issues = $issues.ToArray(); Cancelled = $state.Cancelled
        LimitReached = $state.LimitReached; DepthLimitReached = $state.DepthLimitReached; VisitedEntries = $state.VisitedEntries
        ScannedLocations = $scanned.ToArray(); CoverageRecords = $attempts.ToArray()
        Coverage = "Manual directory first, then bounded ELO-prefix roots on available drives; depth $MaxDepth, global entry budget $MaxEntries. ScannedLocations lists enumerated directories (possibly partial); CoverageRecords lists attempts and outcomes. Not exhaustive; absence of results is not proof of absence."
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
        [scriptblock]$ProbeJava = { param($Path, $Cancel) Invoke-EloJavaVersion -JavaPath $Path -ShouldCancel $Cancel }
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
        $classification = Get-EloJavaClassification -Evidence $probe.Evidence
        if (-not $probe.Succeeded) { $classification.Status = 'Inconclusive'; $classification.Reason = 'Java version probe did not complete successfully; exploitability is not determined.' }
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
            Evidence = $probe.Evidence; Error = $probe.Error; ExitCode = $probe.ExitCode; Reason = $classification.Reason; Source = $classification.Source
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
  --scan                  Read-only, bounded discovery on available drives.
  --json                  Emit one JSON report (including errors); no progress noise.
  --manual-path "D:\ELO"   Add a literal local directory; searched before drive roots.
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
  --update-runtime        Separate option: NOT IMPLEMENTED; always fails closed.
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
Automatic runtime update remains disabled; no runtime backup/replacement is claimed.
CLI JSON and UI JSON exports are raw diagnostics, NOT this sanitized HTML report.
Review raw exports before sharing; never enter secrets into paths or JVM options.

Security/evidence:
Scanning does not write ELO files or machine configuration. It may execute trusted
local java.exe -version, which is code execution: scan trusted installations only.
Discovery is bounded, heuristic and not exhaustive; no match is not proof of safety.
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
   test replacement and restoration. Automatic runtime update is NOT IMPLEMENTED.

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
3 runtime update not implemented. Only modification requests prompt; no credentials.
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
    @{ IsAdmin=$admin; Preview=$preview; Apply=$apply }
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
            '--confirm-mitigation','--update-runtime')
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
        if (-not $options.ContainsKey('--mitigate') -and
            ($options.ContainsKey('--target') -or $options.ContainsKey('--confirm-admin') -or $options.ContainsKey('--confirm-mitigation'))) {
            throw 'Action arguments require --mitigate.'
        }
        if ($options.ContainsKey('--help') -or $options.ContainsKey('--manual')) {
            $text = Get-EloCliReadme
            if ($json) { $text = @{ readme=$text } | ConvertTo-Json -Depth 4 }
            return [pscustomobject]@{ ExitCode=0; Output=$text }
        }
        $report.keepTemp = $options.ContainsKey('--keep-temp')
        if ($options.ContainsKey('--update-runtime')) {
            $code = 3; throw 'Runtime update not implemented: provenance, compatibility, backup, replacement and rollback are not verified.'
        }
        $manualPath = $null
        if ($options.ContainsKey('--manual-path')) {
            $manualPath = [string]$options['--manual-path']
            if ($manualPath.Length -gt 1024 -or $manualPath -cnotmatch '^[A-Za-z]:\\' -or
                $manualPath -match '[\x00-\x1f\x7f"<>|?*/;`$]' -or $manualPath.Substring(2).Contains(':')) { throw 'Invalid literal local manual path.' }
            foreach ($part in $manualPath.Substring(3).Split('\')) {
                if ($part -match '[. ]$' -or $part -match '^(?i:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)') { throw 'Invalid path component.' }
            }
        }
        if ($options.ContainsKey('--mitigate')) {
            if (-not $options.ContainsKey('--target') -or [string]$options['--target'] -cnotmatch '^(0|[1-9][0-9]{0,5})$' -or
                -not $options.ContainsKey('--confirm-admin') -or -not $options.ContainsKey('--confirm-mitigation')) {
                throw 'Mitigation requires --target N --confirm-admin --confirm-mitigation; read --help first.'
            }
            $code = 1
            foreach ($name in @('IsAdmin','Preview','Apply')) {
                if ($Actions[$name] -isnot [scriptblock]) { throw 'Trusted action backend not available.' }
            }
            if ((& $Actions.IsAdmin) -ne $true) { throw 'Administrator privileges required.' }
        }
        $code = 1
        $scan = & $Scanner $manualPath
        if ($null -eq $scan -or $null -eq $scan.Results -or $null -eq $scan.Cancelled) { throw 'Invalid scanner response.' }
        $report.scan = $scan
        if ($scan.Cancelled) { throw 'Scan cancelled; no action performed.' }
        if ($options.ContainsKey('--mitigate')) {
            $index = [int]$options['--target']; $rows = @($scan.Results)
            if ($index -ge $rows.Count -or $rows[$index].Status -cne 'PotentiallyVulnerable') { throw 'Target not eligible.' }
            $preview = & $Actions.Preview $rows[$index]
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
            $null = & $Console.Write 'Type APPLY MITIGATION to authorize this exact preview; anything else cancels:'
            $answer = & $Console.ReadLine
            if ($answer -isnot [string] -or $answer -cne 'APPLY MITIGATION') { throw 'Mitigation cancelled; no action performed.' }
            if ((& $Actions.IsAdmin) -ne $true) { throw 'Administrator privileges required.' }
            $report.readOnly = $false
            $result = & $Actions.Apply $preview
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
        ReportJvms=@(); ReportActions=@(); ReportIndexes=@{}
        Adapters=@{
            Admin={ Test-EloAdministrator }; ReadOptions={ Get-EloMachineOptions }
            WriteOptions={ param($Value) Set-EloMachineOptions $Value }
            Fingerprint={ param($Path) Get-EloJavaFingerprint $Path }
            Verify={ param($Path,$Options) Invoke-EloFlagProbe $Path $Options }
            Clock={ [DateTime]::UtcNow }; Resources={ Get-EloReportWindowsResources }
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
param($source,$roots,$manual,$control)
$ErrorActionPreference='Stop'
. ([scriptblock]::Create($source))
$cancel = { [bool]$control.Cancel }.GetNewClosure()
Invoke-EloJavaScan -DriveRoots $roots -ManualPath $manual -ShouldCancel $cancel
'@
    try {
        $null = $ps.AddScript($wrapper).AddArgument($Session.ScanSource).AddArgument($roots).AddArgument($ManualPath).AddArgument($control)
        $handle = $ps.BeginInvoke()
        $Session.Worker = @{PowerShell=$ps; Handle=$handle; Control=$control}
        $Session.State = 'scanning'
    } catch { $ps.Dispose(); $Session.State='error'; throw }
}
function Get-EloSecurityMetadata {
    # Verification supplied by the primary parent, NOT fetched by this module.
    # Titles carry provenance because the HTML contract has no provenance field.
    return @{verifiedOn='2026-11-23';advisories=@(
        @{id='openjdk-2026-11-17';url='https://openjdk.org/groups/vulnerability/advisories/2026-11-17';title=@{
            en='OpenJDK advisory: parent reviewed user-supplied text; not fetched directly (2026-11-23)'
            de='OpenJDK: Elternagent pruefte vom Benutzer gelieferten Text; nicht direkt abgerufen (2026-11-23)'}},
        @{id='oracle-cve-2026-114938';url='https://linux.oracle.com/cve/CVE-2026-114938.html';title=@{
            en='Oracle Linux CVE-2026-114938: parent fetched directly (2026-11-23); not ELO compatibility verification'
            de='Oracle Linux CVE-2026-114938: Elternagent rief direkt ab (2026-11-23); keine ELO-Kompatibilitaetspruefung'}},
        @{id='temurin-november-2026';url='https://adoptium.net/news/2026/11/temurin-november-2026-cspu-java4shell/';title=@{
            en='Temurin vendor advisory: parent fetched directly (2026-11-23); exact listed Temurin builds only'
            de='Temurin-Herstellerhinweis: Elternagent rief direkt ab (2026-11-23); nur exakt aufgefuehrte Temurin-Builds'}})}
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
        $fixed=@('17.0.21.1+2','21.0.13.1+2','25.0.5.1+2','27.0.1.1+4')
        if ($item.Status -ceq 'KnownFixed' -and $item.Vendor -ceq 'Temurin' -and $fixed -ccontains $item.FullVersion -and
            $item.Build -ceq $item.FullVersion -and $item.Source -ceq 'https://adoptium.net/news/2026/11/temurin-november-2026-cspu-java4shell/') { $status='patched' }
        $architecture = 'unknown'
        if ($item.Architecture -in @('x86','x64','ARM64')) { $architecture=$item.Architecture.ToLowerInvariant() }
        $version = 'Unknown'; if ($item.FullVersion) { $version=[string]$item.FullVersion }
        $vendor = 'Unknown'; if ($item.Vendor) { $vendor=[string]$item.Vendor }
        $rationale = [string]$item.EloPathRationale
        if ([string]::IsNullOrWhiteSpace($rationale)) { $rationale='ELO association is not verified.' }
        $rationale += " Runtime-root inference: $($item.RuntimeRootRationale)"
        $provenance='Parent verification 2026-11-23: OpenJDK advisory reviewed as user-supplied text, not fetched directly; Oracle Linux CVE-2026-114938 and Temurin vendor advisory fetched directly by parent. This module did not fetch them. Exact listed Temurin builds only; no ELO compatibility or other vendor verification. Patched is a narrow advisory classification, not a whole-system safety claim.'
        $evidence = "$provenance`nScanner classification: $($item.Status). $($item.Reason)`n$($item.Evidence)`nReported architecture: $($item.Architecture)`nProbe error: $($item.Error)`nRule source: $($item.Source)"
        $row = [ordered]@{id=$id;path=[string]$item.Location;runtimeRoot=[string]$item.RuntimeRoot;version=$version;vendor=$vendor;architecture=$architecture;status=$status
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
            Vendor=$evidence.Vendor;VendorVerified=($observed -and $evidence.Vendor -ceq 'Temurin')
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
    param([AllowNull()][AllowEmptyString()][string]$Existing)
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
        if ($token -cmatch '^-XX:[+-]UseBASE64Intrinsics$') { continue }
        if ($token -match '^-XX:.*UseBASE64Intrinsics') { Stop-EloRequest 409 'ambiguous_intrinsics_option' }
        $null=$kept.Append($Existing.Substring($start,$i-$start))
    }
    if ($kept.Length -eq 0) { return '-XX:-UseBASE64Intrinsics' }
    return $kept.ToString() + ' -XX:-UseBASE64Intrinsics'
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
    param([string]$Evidence)
    $matches=[regex]::Matches($Evidence,'(?m)^\s*bool\s+UseBASE64Intrinsics\s*(?::=|=)\s*(true|false)\b[^\r\n]*$')
    return $matches.Count -eq 1 -and $matches[0].Groups[1].Value -ceq 'false'
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
        $info.FileName=$JavaPath; $info.Arguments='-XX:+PrintFlagsFinal -version'
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
    $after=@{Exists=$true;Value=(Merge-EloJavaOptions $before.Value);Kind=$before.Kind}
    $fingerprint=& $Session.Adapters.Fingerprint $target.Location
    # Preview is read-only, including registry/configuration. A disposable JVM is
    # started only after explicit action confirmation, never during preview.
    $preview=@{Id=(New-EloSecret);ResultId=$ResultId;ActionId='mitigate';Before=$before;After=$after;Fingerprint=$fingerprint
        JavaPath=$target.Location;Expires=(& $Session.Adapters.Clock).AddMinutes(2)}
    $old='(absent)'; if ($before.Exists) { $old="[$($before.Value)]" }
    $summaryEn="Set exactly one -XX:-UseBASE64Intrinsics in MACHINE JAVA_TOOL_OPTIONS, removing standalone duplicate/conflicting +/- flags (all future inheriting JVMs, not just ELO). Previous value: $old (registry type: $($before.Kind)). New value: [$($after.Value)]. Registry type and all other option bytes are preserved. Backup: exact previous value retained in this session. On verification failure restore it automatically; after success use an approved Registry Editor procedure to restore JAVA_TOOL_OPTIONS under HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment with the previous value AND registry type above (delete it if absent). No ELO files are changed. Confirmation authorizes one disposable java -XX:+PrintFlagsFinal -version probe with the proposed options, followed by registry write, readback and a second probe."
    $summaryDe="Genau einmal -XX:-UseBASE64Intrinsics in der systemweiten Variable JAVA_TOOL_OPTIONS setzen; eigenstaendige doppelte/widerspruechliche +/- Optionen entfernen (alle kuenftig erbenden JVMs, nicht nur ELO). Alter Wert: $old (Registrierungstyp: $($before.Kind)). Neuer Wert: [$($after.Value)]. Typ und alle anderen Optionszeichen bleiben erhalten. Sicherung: exakter alter Wert in dieser Sitzung. Bei Prueffehler automatische Wiederherstellung; nach Erfolg per freigegebenem Registrierungseditor JAVA_TOOL_OPTIONS unter HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment mit altem Wert UND Typ wiederherstellen (bei zuvor fehlendem Wert loeschen). Keine ELO-Dateien werden geaendert. Bestaetigung erlaubt einen Test mit java -XX:+PrintFlagsFinal -version, danach Registrierungsaenderung, Ruecklesen und zweiten Test."
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
function Get-EloSessionReportHtml {
    param($Session,[ValidateSet('en','de')][string]$Language)
    $report=New-EloTechnicalReport -ResourceCollector $Session.Adapters.Resources -JvmEvidence $Session.ReportJvms -Actions $Session.ReportActions
    $html=ConvertTo-EloTechnicalReportHtml $report -Language $Language
    $states=@{idle='Ready';scanning='Scanning';cancelling='Cancelling';completed='Completed';cancelled='Cancelled';error='Failed'}
    $notice='Session scan state: '; $scope='Session observations (including earlier scans); only a completed scan is a complete snapshot. Automatic runtime update is disabled. ELO API support and running ELO process mitigation are not verified.'
    if ($Language -eq 'de') {
        $states=@{idle='Bereit';scanning='Scan laeuft';cancelling='Abbruch angefordert';completed='Abgeschlossen';cancelled='Abgebrochen';error='Fehlgeschlagen'}
        $notice='Scanstatus der Sitzung: '; $scope='Sitzungsnachweise (auch fruehere Scans); nur ein abgeschlossener Scan ist eine vollstaendige Momentaufnahme. Automatisches Runtime-Update ist deaktiviert. ELO-API-Unterstuetzung und Risikominderung im laufenden ELO-Prozess sind nicht nachgewiesen.'
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
        return @{results=@($Session.Results);security=(Get-EloSecurityMetadata)}
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
            return @{ok=$true}
        }
        '/api/cancel' {
            $null=ConvertFrom-EloBody $Request.Body
            $Session.Preview=$null
            if ($Session.Worker) { $Session.Worker.Control.Cancel=$true; $Session.State='cancelling' }
            return @{ok=$true}
        }
        default {
            $required=@('actionId','resultId'); if ($Request.Target -ceq '/api/action') { $required+= 'previewId' }
            $body=ConvertFrom-EloBody $Request.Body -Required $required
            foreach ($key in $required) { if ($body.$key -cnotmatch '^[A-Za-z0-9_-]{1,128}$') { Stop-EloRequest 400 'invalid_id' } }
            if ($body.actionId -cnotin @('mitigate','update-runtime')) { Stop-EloRequest 400 'invalid_action' }
            if ($body.actionId -ceq 'update-runtime') { $Session.Preview=$null; Stop-EloRequest 503 'update_unavailable_provenance_compatibility_backup_replacement_rollback_not_verified' }
            if ($Session.RecoveryRequired) { Stop-EloRequest 409 'manual_recovery_required_close_session' }
            if ($Session.State -cne 'completed' -or $Session.Worker) { Stop-EloRequest 409 'completed_scan_required' }
            if ($Request.Target -ceq '/api/preview') { return New-EloMitigationPreview $Session $body.resultId }
            return Invoke-EloMitigation $Session $body
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
 POST scan -> {} for all available drives, or {searchPath: absolute local Windows
 directory} for an optional manual root (1..1024, no controls/wildcards/device/UNC/
 relative paths). This is the ONLY path input. Preserve spaces; treat as plain JSON
 data, never shell/PowerShell text or a command. Backend MUST independently validate
 and canonicalize, enforce local read-only traversal, handle reparse points safely,
 and reject invalid/inaccessible roots. Do not echo the root into activity logs.
 POST cancel -> {}; both respond {ok:true}. Cancel is a request, not completion.
 POST preview -> {actionId: mitigate|update-runtime, resultId}; response
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
 rollback_failed_manual_recovery_required and 409 manual_recovery_required_close_session
 latch a visible manual-recovery lock for this page lifetime, including across polling
 success/network errors. Malformed warnings on recognized recovery errors are discarded
 without hiding that lock. Other malformed/unknown error bodies discard all server text;
 fallback is auth for 401, access denied for 403, otherwise generic failure.
 503 update_unavailable_provenance_compatibility_backup_replacement_rollback_not_verified
 means automatic update is unavailable (no download/replacement). This server currently
 supports mitigation only. Request errors remain visible through successful background
 polls until another explicit request; poll errors clear on a validated refresh.
 No backend diagnostic text is logged. JSON export retains all documented JVM
 evidence and advisory metadata, lastSuccessfulRefresh (ISO timestamp|null) and
 assessmentComplete (false for active/cancelled/failed scans or stale snapshots),
 and recoveryRequired (a sticky client-side safety lock, not proof of recovery).
 Activity export contains fixed translated events only.
 This UI does not implement backend scanning, updates, rollback or BAT extraction.
-->
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'none'; base-uri 'none'; form-action 'none'">
<title>ELO Patch Tools</title>
<style>
body{font:16px system-ui,sans-serif;max-width:960px;margin:2rem auto;padding:0 1rem;color:#202830;background:#f5f7fa}section{background:white;padding:1rem;margin:1rem 0;border:1px solid #ccd3dc;border-radius:.4rem}button,select{font:inherit;padding:.5rem;margin:.3rem}button:disabled{opacity:.55}pre{white-space:pre-wrap;overflow-wrap:anywhere}label{display:block;margin:.5rem 0}#error{color:#a01818}progress{width:100%}small{display:block}h1,h2{line-height:1.2}input[type=text]{font:inherit;width:min(95%,45rem);padding:.5rem}.table-wrap{overflow-x:auto}table{border-collapse:collapse;width:100%}th,td{padding:.5rem;border:1px solid #ccd3dc;text-align:left;vertical-align:top;white-space:pre-wrap;overflow-wrap:anywhere}td{min-width:7rem}a{color:#174f92}
</style>
</head>
<body>
<h1>ELO Patch Tools</h1>
<label><span data-i18n="language">Language</span> <select id="language"><option value="en">English</option><option value="de">Deutsch</option></select></label>
<p data-i18n="intro"></p>
<pre id="error" role="alert"></pre>
<pre id="recoveryNotice" role="alert"></pre>
<section aria-labelledby="scanHeading">
<h2 id="scanHeading" data-i18n="scanHeading"></h2>
<p id="status" role="status" aria-live="polite"></p>
<progress id="progress" max="100" aria-label="Progress"></progress><p id="progressText"></p>
<label><span data-i18n="searchPath"></span><input id="searchPath" type="text" maxlength="1024" autocomplete="off" spellcheck="false" aria-describedby="searchHelp"></label>
<p id="searchHelp" data-i18n="searchHelp"></p>
<button id="scan" data-i18n="scan"></button><button id="cancel" data-i18n="cancel" disabled></button>
<label><span data-i18n="results"></span><select id="results"></select></label>
<p id="resultNotice" role="status"></p>
<div class="table-wrap"><table><caption data-i18n="jvmTable"></caption><thead><tr><th scope="col" data-i18n="path"></th><th scope="col" data-i18n="runtimeRoot"></th><th scope="col" data-i18n="version"></th><th scope="col" data-i18n="vendor"></th><th scope="col" data-i18n="architecture"></th><th scope="col" data-i18n="classification"></th><th scope="col" data-i18n="eloRationale"></th><th scope="col" data-i18n="classificationEvidence"></th></tr></thead><tbody id="jvmRows"></tbody></table></div>
<pre id="details"></pre>
</section>
<section aria-labelledby="actionHeading">
<h2 id="actionHeading" data-i18n="actionHeading"></h2>
<p data-i18n="warning"></p>
<button id="mitigate" data-i18n="mitigate" disabled></button><button id="update" data-i18n="update" disabled></button>
<h3 data-i18n="preview"></h3><pre id="preview"></pre>
<label><input id="confirm" type="checkbox" disabled><span id="confirmation"></span></label>
<button id="apply" data-i18n="apply" disabled></button>
</section>
<section aria-labelledby="securityHeading"><h2 id="securityHeading" data-i18n="securityHeading"></h2><p data-i18n="securityHelp"></p><p id="verifiedOn"></p><ul id="advisories"></ul></section>
<section aria-labelledby="manualHeading"><h2 id="manualHeading" data-i18n="manualHeading"></h2><p data-i18n="manualIntro"></p><ol id="manual"></ol></section>
<section aria-labelledby="exportHeading"><h2 id="exportHeading" data-i18n="exportHeading"></h2><button id="exportTechnical" data-i18n="technicalReport"></button><button id="exportJson" data-i18n="exportJson"></button><button id="exportLog" data-i18n="exportLog"></button><pre id="activity" aria-live="polite"></pre></section>
<script>
'use strict';
(() => {
const messages = {
 en: {
 language:'Language',intro:'Local, read-only discovery. No change is made by scanning or previewing. Keep this session open while work is running.',
 technicalReport:'Download technical HTML report',scanHeading:'Discovery',scan:'Start read-only scan',cancel:'Cancel scan',results:'Select JVM for preview',none:'No JVMs found',
 actionHeading:'Separate, optional changes',warning:'Temporary mitigation is not a runtime update. Updating may affect compatibility and vendor support. Nothing is applied automatically.',
 mitigate:'Preview temporary mitigation',update:'Preview runtime update',preview:'Change preview',apply:'Apply confirmed change',
 confirmMitigation:'I reviewed the mitigation preview, backup and rollback plan and authorize this change.',confirmUpdate:'I reviewed the update preview, compatibility risks, backup and rollback plan and authorize this runtime update.',
 noPreview:'Select a JVM and preview one change. A new scan, search root, selection or preview clears confirmation.',
 manualHeading:'Manual patch instructions',manualIntro:'These instructions do not execute commands or change the system. Follow ELO and runtime vendor guidance for your exact installation.',
 manual:['Identify the affected ELO service and its actual Java runtime from the scan. Verify the version against vendor advisories; a potential finding is not proof of exploitability.',
 'Plan a maintenance window. Record existing JVM options and environment settings. Back up the service configuration and runtime; verify a rollback procedure before changing anything.',
 'Temporary mitigation: in the affected service’s supported JVM configuration, add -XX:-UseBASE64Intrinsics without replacing existing options or global environment values. Confirm that the runtime supports this flag. This is not a permanent fix.',
 'Separate runtime update: obtain a vendor-approved, compatible patched runtime from a trusted vendor source. Verify integrity, architecture and ELO support. Do not replace a running runtime or use an arbitrary download.',
 'Stop only the affected service during the approved window, apply the chosen change using the vendor procedure, then restart. Check service health and effective JVM options/version. If checks fail, stop and restore the saved configuration/runtime.',
 'Rescan and document the outcome. Keep the backup until validated. Contact ELO support if paths, service ownership or compatibility are uncertain.'],
 exportHeading:'Reports',exportJson:'Export JSON results',exportLog:'Export activity log',
 idle:'Ready',scanning:'Scanning',cancelling:'Cancellation requested; waiting for the scanner',completed:'Scan completed',cancelled:'Scan cancelled; results may be incomplete',error:'Operation failed',unknown:'Unknown',
 vulnerable:'Potentially vulnerable',safe:'No vulnerability detected by current rules',mitigated:'Mitigation detected',unsupported:'Unsupported runtime',
 progress:'Progress',indeterminate:'Progress unavailable',path:'Installation path',version:'Runtime version',classification:'Assessment',
 auth:'Missing or rejected session token. Reopen the local session link.',network:'Cannot reach the local service. Check that the BAT is still running.',
 invalid:'The local service returned an invalid response.',failed:'The request failed. Check the local service and retry.',expired:'The preview expired or no longer matches the target. Request a fresh preview.',
 accessDenied:'Access denied. Check elevation and filesystem/registry permissions without bypassing access controls. No protection is claimed.',
 adminNeeded:'Mitigation requires an elevated administrator session. Read-only scanning does not require elevation. This is not a session-token error.',
 boundaryRejected:'The local service rejected the request boundary. Reopen the original local session link; do not bypass origin or host checks.',
 rollbackFailed:'Rollback failed — manual recovery is required.',manualRecovery:'Manual recovery is required before any further change.',
 recoveryGuidance:'CRITICAL: JAVA_TOOL_OPTIONS may still be changed. Further requests that could change state are locked in this page. Restore the exact previous value AND registry type saved from the preview using an approved Registry Editor procedure, with your administrator. Verify manually before closing this session and starting another. Opening a new session alone does not restore the environment. Existing JVM protection is not claimed.',
 rolledBack:'Verification failed. The exact previous environment value and registry type were restored and read back. No protection is claimed.',
 probeFailed:'JVM-option verification failed before any change. No protection is claimed.',
 updateUnavailable:'Automatic runtime update is unavailable: provenance, ELO compatibility, backup, replacement and rollback have not been verified. Nothing was downloaded or replaced. Use the manual instructions and vendor support.',
 incompleteScan:'The scan is incomplete or exceeds evidence limits. Choose a narrower accessible local directory and review permissions without bypassing access controls.',
 inaccessiblePath:'The selected local directory is missing or inaccessible. Check the directory and permissions.',
 scanBusy:'A scan is already running. Wait for completion or request cancellation.',completedScan:'Complete a successful scan before requesting a change.',
 targetIneligible:'The selected JVM is not eligible for mitigation. Review the scan evidence.',optionsUnsupported:'Existing JVM/environment settings are ambiguous or unsupported. Review them with your administrator before making changes.',
 scanSent:'Scan requested',cancelSent:'Cancellation requested',previewReady:'Preview received',actionSent:'Confirmed action completed',connected:'Session connected',report:'Report exported',log:'Activity log exported',
 units:'items checked',previewKind:'Selected change',mitigation:'Temporary mitigation',runtimeUpdate:'Runtime update',
 searchPath:'Optional local search directory',searchHelp:'Leave empty to discover all available drives. Or enter an absolute local directory, e.g. C:\\ELO data. It is read-only search data, never a command. Network/device paths and wildcards are not accepted.',
 invalidPath:'Enter an absolute local Windows directory of at most 1024 characters, without controls, wildcards or relative segments.',
 jvmTable:'Discovered JVMs and evidence',runtimeRoot:'Runtime root',vendor:'Vendor',architecture:'Architecture',eloRationale:'ELO association rationale',classificationEvidence:'Classification evidence',
 patched:'Patched', 'not-affected':'Not affected',inconclusive:'Inconclusive',
 securityHeading:'Security information',securityHelp:'Official advisory links and verification date are supplied and verified by the backend maintainer. This UI checks their format and official host, not their live content or applicability. Links open only on request; no remote assets are loaded. Review evidence and vendor support before acting.',
 resultNotice:'Results may be incomplete or stale during a scan, after cancellation or after an error. They are not a fresh, complete assessment.',
 verifiedDate:'Source verification date (UTC)',noAdvisories:'No verified advisory information supplied. Do not infer that this runtime is safe.'
 },
 de: {
 language:'Sprache',intro:'Lokale, schreibgeschützte Suche. Scan und Vorschau ändern nichts. Lassen Sie diese Sitzung während laufender Vorgänge geöffnet.',
 technicalReport:'Technischen HTML-Bericht herunterladen',scanHeading:'Suche',scan:'Schreibgeschützten Scan starten',cancel:'Scan abbrechen',results:'JVM für Vorschau auswählen',none:'Keine JVMs gefunden',
 actionHeading:'Getrennte, optionale Änderungen',warning:'Die vorübergehende Risikominderung ist kein Laufzeit-Update. Ein Update kann Kompatibilität und Herstellersupport beeinträchtigen. Nichts wird automatisch angewendet.',
 mitigate:'Vorübergehende Risikominderung prüfen',update:'Laufzeit-Update prüfen',preview:'Änderungsvorschau',apply:'Bestätigte Änderung anwenden',
 confirmMitigation:'Ich habe die Vorschau zur Risikominderung sowie Sicherung und Wiederherstellung geprüft und genehmige diese Änderung.',confirmUpdate:'Ich habe die Update-Vorschau, Kompatibilitätsrisiken sowie Sicherung und Wiederherstellung geprüft und genehmige dieses Laufzeit-Update.',
 noPreview:'Wählen Sie eine JVM und prüfen Sie eine Änderung. Ein neuer Scan, Suchpfad, eine Auswahl oder eine Vorschau setzt die Bestätigung zurück.',
 manualHeading:'Anleitung für die manuelle Korrektur',manualIntro:'Diese Anleitung führt keine Befehle aus und ändert das System nicht. Beachten Sie die ELO- und Laufzeit-Herstellerhinweise für Ihre konkrete Installation.',
 manual:['Ermitteln Sie den betroffenen ELO-Dienst und seine tatsächliche Java-Laufzeit anhand des Scans. Vergleichen Sie die Version mit Herstellerhinweisen; ein Verdacht ist kein Nachweis der Ausnutzbarkeit.',
 'Planen Sie ein Wartungsfenster. Dokumentieren Sie vorhandene JVM-Optionen und Umgebungswerte. Sichern Sie Dienstkonfiguration und Laufzeit und prüfen Sie vor Änderungen den Wiederherstellungsablauf.',
 'Vorübergehende Risikominderung: Ergänzen Sie -XX:-UseBASE64Intrinsics in der unterstützten JVM-Konfiguration des betroffenen Dienstes, ohne vorhandene Optionen oder globale Umgebungswerte zu ersetzen. Prüfen Sie, ob die Laufzeit diese Option unterstützt. Dies ist keine dauerhafte Korrektur.',
 'Getrenntes Laufzeit-Update: Beziehen Sie eine vom Hersteller freigegebene, kompatible und korrigierte Laufzeit aus einer vertrauenswürdigen Herstellerquelle. Prüfen Sie Integrität, Architektur und ELO-Unterstützung. Ersetzen Sie keine laufende Laufzeit und verwenden Sie keinen beliebigen Download.',
 'Stoppen Sie nur den betroffenen Dienst im genehmigten Wartungsfenster, führen Sie die gewählte Änderung nach Herstellerverfahren aus und starten Sie ihn erneut. Prüfen Sie Dienstzustand und wirksame JVM-Optionen beziehungsweise Version. Bei Fehlern stoppen und gesicherte Konfiguration oder Laufzeit wiederherstellen.',
 'Scannen Sie erneut und dokumentieren Sie das Ergebnis. Bewahren Sie die Sicherung bis zur erfolgreichen Prüfung auf. Bei unklaren Pfaden, Dienstzuordnung oder Kompatibilität wenden Sie sich an den ELO-Support.'],
 exportHeading:'Berichte',exportJson:'JSON-Ergebnisse exportieren',exportLog:'Aktivitätsprotokoll exportieren',
 idle:'Bereit',scanning:'Scan läuft',cancelling:'Abbruch angefordert; Scanner wird abgewartet',completed:'Scan abgeschlossen',cancelled:'Scan abgebrochen; Ergebnisse möglicherweise unvollständig',error:'Vorgang fehlgeschlagen',unknown:'Unbekannt',
 vulnerable:'Möglicherweise verwundbar',safe:'Nach aktuellen Regeln keine Schwachstelle erkannt',mitigated:'Risikominderung erkannt',unsupported:'Nicht unterstützte Laufzeit',
 progress:'Fortschritt',indeterminate:'Fortschritt nicht verfügbar',path:'Installationspfad',version:'Laufzeitversion',classification:'Bewertung',
 auth:'Sitzungstoken fehlt oder wurde abgelehnt. Öffnen Sie den lokalen Sitzungslink erneut.',network:'Lokaler Dienst nicht erreichbar. Prüfen Sie, ob die BAT-Datei noch läuft.',
 invalid:'Der lokale Dienst hat eine ungültige Antwort geliefert.',failed:'Anfrage fehlgeschlagen. Prüfen Sie den lokalen Dienst und versuchen Sie es erneut.',expired:'Die Vorschau ist abgelaufen oder passt nicht mehr zum Ziel. Fordern Sie eine neue Vorschau an.',
 accessDenied:'Zugriff verweigert. Administratorrechte und Datei-/Registrierungsberechtigungen prüfen, ohne den Zugriffsschutz zu umgehen. Kein Schutz zugesichert.',
 adminNeeded:'Risikominderung erfordert eine erhöhte Administratorsitzung. Schreibgeschützte Scans benötigen keine Erhöhung. Dies ist kein Sitzungstoken-Fehler.',
 boundaryRejected:'Der lokale Dienst hat die Anfragegrenzen abgelehnt. Öffnen Sie den ursprünglichen lokalen Sitzungslink erneut; Herkunfts- und Host-Prüfungen nicht umgehen.',
 rollbackFailed:'Wiederherstellung fehlgeschlagen — manuelle Wiederherstellung erforderlich.',manualRecovery:'Vor weiteren Änderungen ist eine manuelle Wiederherstellung erforderlich.',
 recoveryGuidance:'KRITISCH: JAVA_TOOL_OPTIONS ist möglicherweise noch geändert. Weitere zustandsändernde Anfragen sind auf dieser Seite gesperrt. Stellen Sie mit Ihrem Administrator den exakten alten Wert UND Registrierungstyp aus der Vorschau mit einem freigegebenen Registrierungseditor-Verfahren wieder her. Vor dem Schließen dieser Sitzung und dem Start einer neuen Sitzung manuell prüfen. Eine neue Sitzung allein stellt die Umgebung nicht wieder her. Kein Schutz bestehender JVMs zugesichert.',
 rolledBack:'Prüfung fehlgeschlagen. Der exakte alte Umgebungswert und Registrierungstyp wurden wiederhergestellt und zurückgelesen. Kein Schutz zugesichert.',
 probeFailed:'Prüfung der JVM-Option vor einer Änderung fehlgeschlagen. Kein Schutz zugesichert.',
 updateUnavailable:'Automatisches Laufzeit-Update nicht verfügbar: Herkunft, ELO-Kompatibilität, Sicherung, Ersetzung und Wiederherstellung sind nicht geprüft. Nichts wurde heruntergeladen oder ersetzt. Nutzen Sie die manuelle Anleitung und den Herstellersupport.',
 incompleteScan:'Der Scan ist unvollständig oder überschreitet Nachweisgrenzen. Engeres zugängliches lokales Verzeichnis wählen und Berechtigungen prüfen, ohne den Zugriffsschutz zu umgehen.',
 inaccessiblePath:'Das gewählte lokale Verzeichnis fehlt oder ist unzugänglich. Verzeichnis und Berechtigungen prüfen.',
 scanBusy:'Ein Scan läuft bereits. Abschluss abwarten oder Abbruch anfordern.',completedScan:'Vor einer Änderung einen erfolgreichen Scan abschließen.',
 targetIneligible:'Die gewählte JVM ist für diese Risikominderung nicht geeignet. Scan-Nachweise prüfen.',optionsUnsupported:'Vorhandene JVM-/Umgebungseinstellungen sind mehrdeutig oder nicht unterstützt. Vor Änderungen mit Ihrem Administrator prüfen.',
 scanSent:'Scan angefordert',cancelSent:'Abbruch angefordert',previewReady:'Vorschau empfangen',actionSent:'Bestätigte Änderung abgeschlossen',connected:'Sitzung verbunden',report:'Bericht exportiert',log:'Aktivitätsprotokoll exportiert',
 units:'Elemente geprüft',previewKind:'Gewählte Änderung',mitigation:'Vorübergehende Risikominderung',runtimeUpdate:'Laufzeit-Update',
 searchPath:'Optionales lokales Suchverzeichnis',searchHelp:'Leer lassen, um alle verfügbaren Laufwerke zu durchsuchen. Oder ein absolutes lokales Verzeichnis eingeben, z. B. C:\\ELO data. Die Eingabe ist nur ein schreibgeschützter Suchpfad, niemals ein Befehl. Netzwerk- und Gerätepfade sowie Platzhalter sind nicht zulässig.',
 invalidPath:'Geben Sie ein absolutes lokales Windows-Verzeichnis mit höchstens 1024 Zeichen ohne Steuerzeichen, Platzhalter oder relative Segmente ein.',
 jvmTable:'Gefundene JVMs und Nachweise',runtimeRoot:'Laufzeit-Stammverzeichnis',vendor:'Hersteller',architecture:'Architektur',eloRationale:'Begründung der ELO-Zuordnung',classificationEvidence:'Nachweis der Einstufung',
 patched:'Gepatcht','not-affected':'Nicht betroffen',inconclusive:'Nicht eindeutig',
 securityHeading:'Sicherheitsinformationen',securityHelp:'Offizielle Sicherheitshinweise und Prüfdatum werden vom Backend-Verantwortlichen bereitgestellt und geprüft. Diese Oberfläche prüft Format und offizielle Domain, nicht den aktuellen Inhalt oder die Anwendbarkeit. Links öffnen sich nur auf Anforderung; externe Ressourcen werden nicht geladen. Prüfen Sie Nachweise und Herstellersupport vor Änderungen.',
 resultNotice:'Während eines Scans, nach einem Abbruch oder Fehler können Ergebnisse unvollständig oder veraltet sein. Sie sind keine aktuelle, vollständige Bewertung.',
 verifiedDate:'Prüfdatum der Quellen (UTC)',noAdvisories:'Keine geprüften Sicherheitshinweise bereitgestellt. Daraus darf keine Unbedenklichkeit der Laufzeit abgeleitet werden.'
 }
};
const $ = id => document.getElementById(id);
const token = new URLSearchParams(location.hash.slice(1)).get('token') || '';
history.replaceState(null, '', location.pathname + location.search);
let language = 'en', state = 'idle', rows = [], preview = null, pending = false, polling = false, lastError = '';
let progress = null, checked = null, lastSuccessfulRefresh = null, security = {verifiedOn:null,advisories:[]};
let lastWarnings = [], errorFromPoll = false, recoveryRequired = false, recoveryWarnings = [];
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
const validRow = row => keys(row,rowFields) && validId(row.id) && text(row.path,1024) && text(row.runtimeRoot,1024) && text(row.version,128) && text(row.vendor,256) && ['x86','x64','arm64','unknown'].includes(row.architecture) && classifications.includes(row.status) && bilingual(row.eloRationale,2048) && bilingual(row.classificationEvidence,4096);
function validSearchPath(value) {
 return value.length <= 1024 && /^[A-Za-z]:\\/.test(value) && !/[\u0000-\u001f\u007f"<>|?*\/]/.test(value) && !value.slice(2).includes(':') && !value.split('\\').slice(1).some(part => /[. ]$/.test(part) || /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(part));
}
function officialUrl(value) {
 if (!text(value,512) || (token && value.includes(token))) return false;
 try {
 const url = new URL(value);
 return url.href === value && url.protocol === 'https:' && !url.username && !url.password && !url.port && !url.search && !url.hash &&
 ((url.hostname === 'www.oracle.com' && /^\/security-alerts\/(?:[a-z0-9-]+\.html)?$/.test(url.pathname)) ||
 (url.hostname === 'openjdk.org' && /^\/groups\/vulnerability\/advisories\/(?:[a-z0-9-]+(?:\.html|\/)?)?$/.test(url.pathname)) ||
 value === 'https://adoptium.net/news/2026/11/temurin-november-2026-cspu-java4shell/' ||
 value === 'https://linux.oracle.com/cve/CVE-2026-114938.html');
 } catch (_) { return false; }
}
function validSecurity(value) {
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
 rollbackFailed:['rollback_failed_manual_recovery_required'],manualRecovery:['manual_recovery_required_close_session'],
 rolledBack:['verification_failed_rolled_back'],probeFailed:['probe_failed_no_change'],
 updateUnavailable:['update_unavailable_provenance_compatibility_backup_replacement_rollback_not_verified'],
 incompleteScan:['scan_incomplete','narrow_scan_root','evidence_out_of_bounds'],inaccessiblePath:['inaccessible_path'],
 invalidPath:['invalid_path','nonlocal_path','reparse_path'],scanBusy:['scan_busy'],completedScan:['completed_scan_required'],
 targetIneligible:['target_not_eligible','invalid_java_target'],
 optionsUnsupported:['unsupported_environment_type','unsupported_options','ambiguous_option_quoting','malformed_option_quoting','ambiguous_intrinsics_option','ambiguous_jvm_options','ambiguous_environment_expansion'],
 failed:['operation_failed','scan_failed','unknown_route','method_rejected','unexpected_body','json_required','invalid_id','invalid_action','invalid_json','invalid_parameters','missing_parameter','request_timeout','incomplete_request','invalid_header','headers_too_large','invalid_request_line','duplicate_header','unsupported_framing','invalid_length','length_required','body_too_large','incomplete_body','invalid_utf8']
}).flatMap(([key,codes]) => codes.map(code => [code,key])));
const recoveryCodes = ['rollback_failed_manual_recovery_required','manual_recovery_required_close_session'];
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
function render() {
 document.documentElement.lang = language;
 document.querySelectorAll('[data-i18n]').forEach(el => { el.textContent = t(el.dataset.i18n); });
 $('error').textContent = lastError ? [t(lastError),...lastWarnings.map(localized)].join('\n') : '';
 $('recoveryNotice').textContent = recoveryRequired ? [t('recoveryGuidance'),...recoveryWarnings.map(localized)].join('\n') : '';
 $('status').textContent = t(recoveryRequired ? 'error' : state);
 $('resultNotice').textContent = lastError || recoveryRequired || running() || state === 'cancelled' || state === 'error' ? t('resultNotice') : '';
 $('progress').setAttribute('aria-label',t('progress'));
 if (progress === null) $('progress').removeAttribute('value'); else $('progress').value = progress;
 $('progressText').textContent = (progress === null ? t('indeterminate') : t('progress')+': '+progress+'%') + (checked === null ? '' : ' — '+checked+' '+t('units'));
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
 $('preview').textContent = preview ? t('previewKind')+': '+t(preview.actionId === 'mitigate' ? 'mitigation' : 'runtimeUpdate')+'\n'+localized(preview.summary)+(preview.warnings.length ? '\n'+preview.warnings.map(localized).join('\n') : '') : t('noPreview');
 $('confirmation').textContent = t(preview && preview.actionId === 'update-runtime' ? 'confirmUpdate' : 'confirmMitigation');
 $('confirm').disabled = pending || !preview || running() || recoveryRequired;
 $('apply').disabled = pending || !preview || !$('confirm').checked || running() || recoveryRequired;
 $('manual').replaceChildren(); messages[language].manual.forEach(text => { const li = document.createElement('li'); li.textContent = text; $('manual').append(li); });
 renderLog();
}
async function refresh() {
 if (polling || pending || !token) return;
 polling = true;
 try {
 const status = await api('status');
 if (!keys(status,['state'],['progress','checked']) || !states.includes(status.state) || (status.progress !== undefined && (!Number.isFinite(status.progress) || status.progress < 0 || status.progress > 100)) || (status.checked !== undefined && (!Number.isSafeInteger(status.checked) || status.checked < 0))) throw 'invalid';
 const result = await api('results');
 if (!keys(result,['results','security']) || !Array.isArray(result.results) || result.results.length > 250 || result.results.some(row => !validRow(row)) || new Set(result.results.map(row => row.id)).size !== result.results.length || !validSecurity(result.security)) throw 'invalid';
 const nextRows = result.results;
 if (state !== status.state || JSON.stringify(rows) !== JSON.stringify(nextRows) || JSON.stringify(security) !== JSON.stringify(result.security)) clearPreview();
 state = status.state; rows = nextRows; security = result.security;
 progress = Number.isFinite(status.progress) ? Math.max(0,Math.min(100,status.progress)) : null;
 checked = Number.isSafeInteger(status.checked) && status.checked >= 0 ? status.checked : null;
 lastSuccessfulRefresh = new Date().toISOString();
 if (errorFromPoll) { lastError = recoveryRequired ? 'manualRecovery' : ''; lastWarnings = []; errorFromPoll = false; }
 render();
 } catch (error) { clearPreview(); fail(error,true); }
 finally { polling = false; }
}
async function perform(work, allowRecovery = false) {
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
 return perform(async () => { clearPreview(); await acknowledge('scan',searchPath === '' ? {} : {searchPath}); state = 'scanning'; rows = []; lastSuccessfulRefresh = null; progress = null; checked = null; log('scanSent'); });
};
$('cancel').onclick = () => perform(async () => { clearPreview(); await acknowledge('cancel',{}); state = 'cancelling'; log('cancelSent'); });
async function getPreview(actionId) {
 const row = selected(); if (!row || running() || recoveryRequired || (lastError && errorFromPoll)) return;
 await perform(async () => {
 clearPreview(); const data = await api('preview',{actionId,resultId:row.id});
 if (!keys(data,['previewId','summary','warnings']) || !validId(data.previewId) || !bilingual(data.summary,4096) || !Array.isArray(data.warnings) || data.warnings.length > 16 || data.warnings.some(w => !bilingual(w,2048))) throw 'invalid';
 preview = {previewId:data.previewId,actionId,resultId:row.id,summary:data.summary,warnings:data.warnings}; log('previewReady');
 });
}
$('mitigate').onclick = () => getPreview('mitigate');
$('update').onclick = () => getPreview('update-runtime');
$('apply').onclick = () => {
 if (!preview || !$('confirm').checked || running() || lastError || recoveryRequired) return;
 const request = {actionId:preview.actionId,resultId:preview.resultId,previewId:preview.previewId};
 return perform(async () => { clearPreview(); await acknowledge('action',request); log('actionSent'); });
};
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
# S10: JVM Vendor='Temurin' with VendorVerified(bool) enables same-provider
# official download/install guidance. All other/unverified vendors stay Unknown.
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
    if ($Value -is [string] -and $Value.Length -le 64 -and $Value -cmatch '^\d{1,8}(?:[._+\-]\d{1,8}){0,7}(?:-ea)?$') { return $Value }
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
function New-EloTechnicalReport {
    param(
        [scriptblock]$ResourceCollector = { Get-EloReportWindowsResources },
        [object[]]$JvmEvidence = @(),
        [object[]]$Actions = @(),
        [scriptblock]$EloVersionAdapter
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
        if ($state -eq 'Proven' -and (Test-EloReportProof $jvm.ClassificationVerified) -and $jvm.Classification -is [string] -and $classCodes.ContainsKey($jvm.Classification) -and $jvm.EvidenceCode -ceq $classCodes[$jvm.Classification]) {
            $classification=$jvm.Classification; $evidence=$jvm.EvidenceCode
        }
        $vendor='Unknown'
        if ($jvm.Vendor -ceq 'Temurin' -and (Test-EloReportProof $jvm.VendorVerified)) { $vendor='Temurin' }
        $jvms+=@{RuntimeIndex=($jvms.Count+1);Status=$state;Version=$version;ExecutionStatus=$execution;Classification=$classification;ClassificationVerified=($classification -ne 'Unknown');EvidenceCode=$evidence;Vendor=$vendor;VendorVerified=($vendor -eq 'Temurin')}
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
    @{System=$system;Jvms=$jvms;Actions=$normalized;Elo=$elo}
}
function ConvertTo-EloTechnicalReportHtml {
    param([Parameter(Mandatory=$true)]$Report, [ValidateSet('en','de')][string]$Language='en')
    # Normalize again: renderer never reflects arbitrary DTO fields or messages.
    $r=New-EloTechnicalReport -ResourceCollector { $Report.System }.GetNewClosure() -JvmEvidence @($Report.Jvms | ForEach-Object { @{Version=$_.Version;Verified=($_.Status -ceq 'Proven');ExecutionVerified=($_.ExecutionStatus -ceq 'Proven');Classification=$_.Classification;ClassificationVerified=$_.ClassificationVerified;EvidenceCode=$_.EvidenceCode;Vendor=$_.Vendor;VendorVerified=$_.VendorVerified} }) -Actions $Report.Actions -EloVersionAdapter { @{Version=$Report.Elo.Version;Verified=($Report.Elo.Status -ceq 'Proven')} }.GetNewClosure()
    if ($Report.System.Status -ceq 'Failed') { $r.System.Status='Failed' }
    if ($Report.Elo.Status -ceq 'Failed') { $r.Elo.Status='Failed' }
    $t=@{Title='Technical report';Server='Server';Windows='Windows version / build';Ram='Total RAM';Disk='Disk: total / free';Jvm='Detected JVM versions';Execution='Execution evidence';Elo='ELO version';Unknown='Unknown / unavailable';Failed='Failed';NotPerformed='Not performed';Proven='Verified';Update='Runtime update';Mitigation='Temporary mitigation';Backup='Backup';Restore='Restore';From='Previous version';To='Verified resulting version';BackupVersion='Verified backup JVM version';Sources='Official information sources';Notice='States reflect supplied verified evidence only. Compatibility, vulnerability and successful remediation are not inferred. No credentials or raw diagnostics are included.';Missing='Missing official installation-specific endpoint, authentication method, version operation and response schema. Java Client IXConnectionIF getVersion/getImplVersion is not a universal REST API contract.'}
    if ($Language -eq 'de') {
        $t=@{Title='Technischer Bericht';Server='Server';Windows='Windows-Version / Build';Ram='Gesamter RAM';Disk='Datentraeger: gesamt / frei';Jvm='Erkannte JVM-Versionen';Execution='Ausfuehrungsnachweis';Elo='ELO-Version';Unknown='Unbekannt / nicht verfuegbar';Failed='Fehlgeschlagen';NotPerformed='Nicht ausgefuehrt';Proven='Nachgewiesen';Update='Runtime-Aktualisierung';Mitigation='Vorlaeufige Risikominderung';Backup='Sicherung';Restore='Wiederherstellung';From='Vorherige Version';To='Nachgewiesene Ergebnisversion';BackupVersion='Nachgewiesene JVM-Version der Sicherung';Sources='Offizielle Informationsquellen';Notice='Statusangaben beruhen nur auf uebergebenen Nachweisen. Kompatibilitaet, Verwundbarkeit und erfolgreiche Behebung werden nicht abgeleitet. Keine Zugangsdaten oder Rohdiagnosen enthalten.';Missing='Offizieller installationsspezifischer Endpunkt, Authentifizierungsmethode, Versionsoperation und Antwortschema fehlen. Java Client IXConnectionIF getVersion/getImplVersion ist kein universeller REST-API-Vertrag.'}
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
            if ($a.Status -eq 'Proven') { $detail+='; -XX:-UseBASE64Intrinsics' }
        }
        $lines.Add('<li>'+$t[$a.Kind]+': '+$t[$a.Status]+$detail+'</li>')
    }
    $lines.Add('</ul><h2>'+$t.Sources+'</h2><ul>')
    $lines.Add('<li>'+$t.Checked+': 2026-11-23. '+$t.Changes+'</li>')
    foreach ($source in @(@('OpenJDK 2026-11-17','https://openjdk.org/groups/vulnerability/advisories/2026-11-17','Supplied'),@('Oracle CVE-2026-114938','https://linux.oracle.com/cve/CVE-2026-114938.html','Fetched'),@('Adoptium Temurin November 2026 CSPU','https://adoptium.net/news/2026/11/temurin-november-2026-cspu-java4shell/','Fetched'))) {
        $lines.Add('<li><a href="'+$source[1]+'">'+$source[0]+'</a> - '+$t[$source[2]]+'</li>')
    }
    $lines.Add('</ul></body></html>')
    return ($lines -join "`r`n")
}
::ELO_PATCH_END:REPORT_PS
