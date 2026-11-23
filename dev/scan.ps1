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
