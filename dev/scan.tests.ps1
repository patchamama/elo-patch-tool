# Run with Windows PowerShell 5.1; no external test framework or fixture writes.
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\scan.ps1"
$script:Passed = 0
function Assert-Equal($Actual, $Expected, [string]$Label) {
    if ($Actual -cne $Expected) { throw "$Label : expected [$Expected], got [$Actual]" }
    $script:Passed++
}
$zulu = Get-EloJavaClassification -Evidence 'OpenJDK Runtime Environment Zulu21.30+15-CA (build 21.0.1+12-LTS)'
Assert-Equal $zulu.Vendor 'Azul Zulu' 'Recognize Zulu runtime identity'
Assert-Equal $zulu.Status 'Inconclusive' 'Zulu is not classified by Temurin advisory'
Assert-Equal $zulu.Build '21.0.1+12-LTS' 'Zulu build preserved'
foreach ($build in @('21.0.13.1+2', '21.0.12+7')) {
    $result = Get-EloJavaClassification -Evidence "OpenJDK Runtime Environment Zulu21.30+15-CA (build $build)"
    Assert-Equal $result.Vendor 'Azul Zulu' 'Zulu identity independent of build'
    Assert-Equal $result.Status 'Inconclusive' 'Temurin milestones do not apply to Zulu'
}
foreach ($evidence in @(
    "OpenJDK Runtime Environment Zulu21.30+15-CA (build 21.0.1+12-LTS)`nTemurin (build 21.0.1+12-LTS)",
    "OpenJDK Runtime Environment Temurin-21.0.13.1+2 (build 21.0.13.1+2)`nZulu21.30 notice",
    "OpenJDK Runtime Environment Zulu21.30+15-CA (build 21.0.1+12-LTS)`nOpenJDK Runtime Environment OtherVendor (build 21.0.1+12-LTS)",
    'OpenJDK Runtime Environment NotZulu21.30 (build 21.0.1+12-LTS)',
    'Zulu notice without runtime identification',
    "OpenJDK Runtime Environment Zulu21.30+15-CA (build 21.0.1+12-LTS)`nOracle VM (build 21.0.1+12-LTS)"
)) {
    Assert-Equal (Get-EloJavaClassification -Evidence $evidence).Vendor 'Unknown' 'Ambiguous vendor remains unknown'
}
foreach ($version in @('17.0.21.1+2', '21.0.13.1+2', '25.0.5.1+2', '27.0.1.1+4')) {
    $evidence = "openjdk version `"$($version.Split('+')[0])`"`nOpenJDK Runtime Environment Temurin-$version (build $version)"
    $result = Get-EloJavaClassification -Evidence $evidence
    Assert-Equal $result.Status 'KnownFixed' "Exact Temurin $version"
    Assert-Equal $result.Build $version 'Preserve full build'
}
foreach ($evidence in @(
    'OpenJDK Runtime Environment Temurin-17.0.21.1+3 (build 17.0.21.1+3)',
    'OpenJDK Runtime Environment Temurin-28+1 (build 28+1)',
    'OpenJDK Runtime Environment OtherVendor (build 17.0.21.1+2)',
    'Temurin unparseable', '',
    "Temurin notice`nOtherVendor (build 17.0.21.1+2)",
    'Temurin-17.0.21.1+20 (build 17.0.21.1+20)',
    "Temurin (build 17.0.21.1+2)`nOther (build 21.0.13.1+2)"
)) {
    Assert-Equal (Get-EloJavaClassification -Evidence $evidence).Status 'Inconclusive' 'Unknown or ambiguous evidence'
}
foreach ($version in @('17.0.20+7', '17.0.21+2', '17.0.21.1+1', '21.0.12+7', '25.0.4+5', '27+36', '27.0.1.1+3')) {
    $classification = Get-EloJavaClassification -Evidence "OpenJDK Runtime Environment Temurin-$version (build $version)"
    Assert-Equal $classification.Status 'PotentiallyVulnerable' "Earlier stable Temurin $version"
    Assert-Equal $classification.FullVersion $version 'Full version includes build'
}
foreach ($evidence in @(
    'Temurin (build 17.0.22+1)', 'Temurin (build 21.0.14+1)',
    'Temurin (build 25.0.6+1)', 'Temurin (build 27.0.2+1)',
    'Temurin (build 11.0.20+8)', 'Temurin (build 17.0.20-ea+7)',
    'Temurin (build 17.0.20+7-custom)', 'Temurin (build 017.0.20+7)',
    'Temurin (build 999999999999999999999.0.1+1)',
    "Temurin (build 17.0.20+7)`nOpenJDK Runtime Environment Zulu (build 17.0.20+7)",
    "Temurin (build 17.0.20+7)`nOther VM (build 17.0.21.1+2, mixed mode)",
    "openjdk version `"21.0.12`"`nTemurin (build 17.0.20+7)",
    'OpenJDK Runtime Environment Temurin-17.0.21.1+2 (build 17.0.20+7)'
)) {
    Assert-Equal (Get-EloJavaClassification -Evidence $evidence).Status 'Inconclusive' 'No unsupported range/vendor/build inference'
}
foreach ($case in @(
    @('Temurin (build 17.0.20+7) OpenJDK 64-Bit Server VM', '64-bit'),
    @('Temurin (build 17.0.20+7) aarch64 64-Bit Server VM', 'ARM64'),
    @('Temurin (build 17.0.20+7) amd64', 'x64'),
    @('Temurin (build 17.0.20+7) i386 32-Bit Client VM', 'x86'),
    @('Temurin (build 17.0.20+7)', 'Unknown'),
    @('Temurin (build 17.0.20+7) aarch64 amd64', 'Unknown')
)) {
    Assert-Equal (Get-EloJavaClassification -Evidence $case[0]).Architecture $case[1] 'Architecture from evidence only'
}
function New-Entry([string]$Path, [bool]$Directory, [bool]$Link = $false) {
    $attributes = [IO.FileAttributes]::Normal
    if ($Link) { $attributes = [IO.FileAttributes]::ReparsePoint }
    [pscustomobject]@{ FullName = $Path; Name = ($Path -split '\\')[-1]; PSIsContainer = $Directory; Attributes = $attributes }
}
# Automatic discovery inspects X:\java\bin, X:\ELO\java\bin and X:\<folder>\java\bin only.
$exactTree = @{
    'Q:\java\bin\java.exe' = @((New-Entry 'Q:\java\bin\java.exe' $false))
    'Q:\ELO\java\bin\java.exe' = @((New-Entry 'Q:\ELO\java\bin\java.exe' $false))
}
$exactScan = Get-EloJavaCandidates -DriveRoots @('Q:\') -GetChildren { param($Path) $exactTree[$Path] } -IsReparsePoint { $false }
Assert-Equal $exactScan.Locations.Count 2 'Both exact root layouts discovered without traversal'
$calls = New-Object 'System.Collections.Generic.List[string]'
$allDrives = Get-EloJavaCandidates -IsReparsePoint { $false } -GetChildren { param($Path) $calls.Add($Path) }
Assert-Equal $calls.Count 72 'C through Z: two exact executables plus one first-level folder listing per drive'
# Generalized layout: X:\java\bin (level 1) and X:\<any folder>\java\bin (level 2), never deeper.
$levelTree = @{
    'Q:\' = @((New-Entry 'Q:\OtraCarpeta' $true), (New-Entry 'Q:\ELO' $true), (New-Entry 'Q:\Windows' $true), (New-Entry 'Q:\Linked' $true $true), (New-Entry 'Q:\Datos' $true), (New-Entry 'Q:\file.txt' $false))
    'Q:\java\bin\java.exe' = @((New-Entry 'Q:\java\bin\java.exe' $false))
    'Q:\ELO\java\bin\java.exe' = @((New-Entry 'Q:\ELO\java\bin\java.exe' $false))
    'Q:\OtraCarpeta\java\bin\java.exe' = @((New-Entry 'Q:\OtraCarpeta\java\bin\java.exe' $false))
    'Q:\Datos\sub\java\bin\java.exe' = @((New-Entry 'Q:\Datos\sub\java\bin\java.exe' $false))
}
$levelCalls = New-Object 'System.Collections.Generic.List[string]'
$levelScan = Get-EloJavaCandidates -DriveRoots @('Q:\') -GetChildren { param($Path) $levelCalls.Add($Path); $levelTree[$Path] } -IsReparsePoint { $false }
Assert-Equal ((@($levelScan.Locations) | Sort-Object) -join '|') 'Q:\ELO\java\bin\java.exe|Q:\java\bin\java.exe|Q:\OtraCarpeta\java\bin\java.exe' 'levels 1 and 2 are found in every drive'
Assert-Equal (@($levelCalls | Where-Object { $_ -like 'Q:\Windows*' -or $_ -like 'Q:\Linked*' }).Count) 0 'system and linked folders are not searched'
Assert-Equal (@($levelCalls | Where-Object { $_ -eq 'Q:\ELO\java\bin\java.exe' }).Count) 1 'ELO layout is checked once, not again as a generic folder'
Assert-Equal ($levelScan.Locations -contains 'Q:\Datos\sub\java\bin\java.exe') $false 'third level is never searched automatically'
Assert-Equal (@($levelScan.Candidates | Where-Object { $_.EloCandidateRoot -eq 'Q:\OtraCarpeta\' -and $_.EloPathRationale -like 'Second-level*' }).Count) 1 'second-level hits explain their layout and make no ELO claim'
Assert-Equal $calls[0] 'C:\java\bin\java.exe' 'First drive exact path'
Assert-Equal $calls[-2] 'Z:\ELO\java\bin\java.exe' 'Last drive exact path (followed by the first-level folder listing)'
Assert-Equal $calls[-1] 'Z:\' 'Last call lists the first-level folders of the last drive'
$invalidCalls = New-Object 'System.Collections.Generic.List[string]'
$null = Get-EloJavaCandidates -DriveRoots @('B:\', 'Q:\nested\', 'Z:\') -IsReparsePoint { $false } -GetChildren { param($Path) $invalidCalls.Add($Path) }
Assert-Equal $invalidCalls.Count 3 'Only C-Z drive roots accepted (two layouts plus the folder listing, for Z: only)'
$linkedCalls = New-Object 'System.Collections.Generic.List[string]'
$linked = Get-EloJavaCandidates -DriveRoots @('Q:\') -IsReparsePoint { param($Path) $Path -eq 'Q:\ELO' } -GetChildren { param($Path) $linkedCalls.Add($Path) }
Assert-Equal (@($linkedCalls | Where-Object { $_ -like '*ELO*' }).Count) 0 'Reparse ancestor prevents exact file access'
Assert-Equal $linkedCalls.Count 2 'only java\bin and the first-level listing are read'
Assert-Equal $linked.CoverageRecords[1].Outcome 'SkippedReparsePoint' 'Reparse ancestor tracked'
$missing = Get-EloJavaCandidates -DriveRoots @('Q:\') -IsReparsePoint { throw [System.Management.Automation.ItemNotFoundException]::new('missing') } -GetChildren { throw 'Unexpected access' }
Assert-Equal $missing.Issues.Count 0 'Missing roots are normal'
Assert-Equal $missing.CoverageRecords[0].Outcome 'NotFound' 'Missing path tracked'
$cancelAutoState = @{ Calls = 0 }
$cancelAuto = Get-EloJavaCandidates -DriveRoots @('Q:\') -ShouldCancel { $cancelAutoState.Calls++; $cancelAutoState.Calls -ge 4 } -IsReparsePoint { $false } -GetChildren { throw 'Must not access file after cancellation' }
Assert-Equal $cancelAuto.Cancelled $true 'Cancellation during ancestor checks'
Assert-Equal $cancelAuto.CoverageRecords[0].Outcome 'Cancelled' 'Cancelled exact check tracked'
$dedup = Get-EloJavaCandidates -DriveRoots @('Q:\', 'q:\') -ManualPath 'Q:\java\bin' -IsReparsePoint { $false } -GetChildren {
    param($Path)
    if ($Path -ieq 'Q:\java\bin\java.exe' -or $Path -ieq 'Q:\java\bin') { New-Entry 'Q:\java\bin\java.exe' $false }
}
Assert-Equal $dedup.Locations.Count 1 'Automatic and manual duplicates ignored case-insensitively'
$tree = @{
    'Q:\ELO\java\bin\java.exe' = @((New-Entry 'Q:\ELO\java\bin\java.exe' $false))
    'M:\Manual Path' = @((New-Entry 'M:\Manual Path\java.exe' $false))
}
$children = { param($Path) if ($tree.ContainsKey($Path)) { $tree[$Path] } }
$scan = Get-EloJavaCandidates -DriveRoots @('Q:\') -ManualPath 'M:\Manual Path' -GetChildren $children -IsReparsePoint { param($Path) $false }
Assert-Equal $scan.Locations.Count 2 'Automatic and manual paths with spaces'
Assert-Equal ($scan.Locations -contains 'M:\Manual Path\java.exe') $true 'Preserve path spaces'
Assert-Equal $scan.Cancelled $false 'Normal scan completes'
Assert-Equal ($scan.ScannedLocations -contains 'Q:\ELO\java\bin\java.exe') $true 'Coverage includes checked executable'
$manualFirst = Get-EloJavaCandidates -DriveRoots @('Q:\') -ManualPath 'M:\Manual Path' -GetChildren $children -IsReparsePoint { $false } -MaxEntries 1
Assert-Equal ($manualFirst.Locations -contains 'M:\Manual Path\java.exe') $true 'Automatic enumeration cannot starve manual path'
Assert-Equal ($manualFirst.Locations -contains 'Q:\ELO\java\bin\java.exe') $true 'Automatic discovery precedes manual budget'
Assert-Equal $manualFirst.VisitedEntries 1 'Manual scan preserves global entry bound'
Assert-Equal $manualFirst.LimitReached $true 'Budget truncation remains explicit'
$cancelled = Get-EloJavaCandidates -DriveRoots @('Q:\') -GetChildren { throw 'Must not enumerate' } -ShouldCancel { $true }
Assert-Equal $cancelled.Cancelled $true 'Immediate cancellation'
$limited = Get-EloJavaCandidates -DriveRoots @('Q:\') -GetChildren $children -IsReparsePoint { $false } -MaxEntries 1
Assert-Equal $limited.LimitReached $false 'Exact checks do not consume manual budget'
$shallow = Get-EloJavaCandidates -DriveRoots @('Q:\') -GetChildren $children -IsReparsePoint { $false } -MaxDepth 0
Assert-Equal $shallow.Locations.Count 1 'Automatic discovery independent of depth'
$denied = Get-EloJavaCandidates -DriveRoots @('Q:\') -IsReparsePoint { $false } -GetChildren { throw 'Access denied' }
Assert-Equal ($denied.Issues.Count -gt 0) $true "Access errors reported ($($denied.CoverageRecords | ForEach-Object { $_.Outcome }))"
$probe = Invoke-EloJavaVersion -JavaPath 'Z:\missing path\java.exe'
Assert-Equal $probe.Succeeded $false 'Missing executable handled'
$probe = Invoke-EloJavaVersion -JavaPath 'Z:\missing path\java.exe' -ShouldCancel { $true }
Assert-Equal $probe.Cancelled $true 'Probe cancellation before launch'
$report = Invoke-EloJavaScan -DriveRoots @('Q:\') -GetChildren $children -IsReparsePoint { $false } -ProbeJava {
    param($Path, $Cancel)
    [pscustomobject]@{ Succeeded = $true; Cancelled = $false; Evidence = 'Temurin (build 17.0.21.1+2)'; Error = $null; ExitCode = 0 }
}
Assert-Equal $report.Results.Count 1 'Probe discovered runtime'
Assert-Equal $report.Results[0].Location 'Q:\ELO\java\bin\java.exe' 'Report location'
Assert-Equal $report.Results[0].Status 'KnownFixed' 'Report classification'
Assert-Equal $report.Results[0].Evidence 'Temurin (build 17.0.21.1+2)' 'Report raw evidence'
Assert-Equal $report.Results[0].RuntimeRoot 'Q:\ELO\java' 'Runtime root inferred from bin'
Assert-Equal $report.Results[0].FullVersion '17.0.21.1+2' 'Report full build version'
Assert-Equal $report.Results[0].Architecture 'Unknown' 'No architecture guess from host'
Assert-Equal $report.Results[0].EloCandidateRoot 'Q:\' 'Drive root retained'
Assert-Equal ($report.Results[0].EloPathRationale -match 'not verified') $true 'ELO association rationale not proof'
$binTree = @{
    'M:\Manual Path' = @((New-Entry 'M:\Manual Path\bin' $true))
    'M:\Manual Path\bin' = @((New-Entry 'M:\Manual Path\bin\java.exe' $false))
}
$manualReport = Invoke-EloJavaScan -DriveRoots @() -ManualPath 'M:\Manual Path' -GetChildren { param($Path) $binTree[$Path] } -IsReparsePoint { $false } -ProbeJava {
    [pscustomobject]@{ Succeeded = $true; Cancelled = $false; Evidence = 'Temurin (build 21.0.12+7) OpenJDK 64-Bit Server VM'; Error = $null; ExitCode = 0 }
}
Assert-Equal $manualReport.Results[0].RuntimeRoot 'M:\Manual Path' 'Runtime root from bin/java.exe'
Assert-Equal $manualReport.Results[0].Architecture '64-bit' 'Reported bitness does not invent ISA'
Assert-Equal $manualReport.Results[0].Status 'PotentiallyVulnerable' 'Potential vulnerability flows into report'
Assert-Equal ($manualReport.Results[0].EloPathRationale -match 'explicit manual') $true 'Manual association rationale retained'
$failed = Invoke-EloJavaScan -DriveRoots @('Q:\') -GetChildren $children -IsReparsePoint { $false } -ProbeJava {
    param($Path, $Cancel)
    [pscustomobject]@{ Succeeded = $false; Cancelled = $false; Evidence = 'Temurin (build 17.0.21.1+2)'; Error = 'Failed'; ExitCode = 1 }
}
Assert-Equal $failed.Results[0].Status 'Inconclusive' 'Failed probe cannot imply fixed'
# Alternate roots, duplicate discovery, and link boundaries.
$programTree = @{
    'R:\' = @((New-Entry 'R:\Program Files' $true), (New-Entry 'R:\Development' $true))
    'R:\Program Files' = @((New-Entry 'R:\Program Files\ELO' $true))
    'R:\Program Files\ELO' = @((New-Entry 'R:\Program Files\ELO\java.exe' $false))
}
$programScan = Get-EloJavaCandidates -DriveRoots @('R:\') -ManualPath 'R:\Program Files\ELO' -GetChildren {
    param($Path)
    if ($Path -eq 'R:\Development') { throw 'Unrelated directory was traversed' }
    $programTree[$Path]
} -IsReparsePoint { $false }
Assert-Equal $programScan.Locations.Count 1 'Program Files discovery and deduplication'
Assert-Equal $programScan.Issues.Count 0 'Unrelated directory excluded'
$linkScan = Get-EloJavaCandidates -DriveRoots @() -ManualPath 'R:\linked ELO' -GetChildren { throw 'Link must not be followed' } -IsReparsePoint { $true }
Assert-Equal $linkScan.Locations.Count 0 'Manual reparse root excluded'
Assert-Equal $linkScan.Issues.Count 1 'Reparse exclusion reported'
$throwing = Invoke-EloJavaScan -DriveRoots @('Q:\') -GetChildren $children -IsReparsePoint { $false } -ProbeJava { throw 'Probe unavailable' }
Assert-Equal $throwing.Results[0].Status 'Inconclusive' 'Probe exception contained'
Assert-Equal $throwing.Results[0].Error 'Probe unavailable' 'Probe exception evidence'
$cancelProbe = Invoke-EloJavaScan -DriveRoots @('Q:\') -GetChildren $children -IsReparsePoint { $false } -ProbeJava {
    [pscustomobject]@{ Succeeded = $false; Cancelled = $true; Evidence = ''; Error = $null; ExitCode = $null }
}
Assert-Equal $cancelProbe.Cancelled $true 'Cancellation propagated from probe'
# Exercise ProcessStartInfo without launching Java or writing fixtures. The host's
# -version option lacks its required value and should fail, never classify fixed.
$hostProbe = Invoke-EloJavaVersion -JavaPath (Join-Path $PSHOME 'powershell.exe') -TimeoutSeconds 5
Assert-Equal $hostProbe.Succeeded $false 'Real non-Java process rejected'
Assert-Equal ([string]::IsNullOrEmpty($hostProbe.Error)) $false 'Real process failure explained'
# Coverage records distinguish successful enumeration, truncation and failure.
Assert-Equal $manualFirst.CoverageRecords[-1].Outcome 'BudgetBounded' 'Partial coverage labelled'
Assert-Equal $manualFirst.CoverageRecords[-1].EntriesSeen 1 'Coverage counts entries'
Assert-Equal $linkScan.CoverageRecords[0].Outcome 'SkippedReparsePoint' 'Skipped manual root tracked'
Assert-Equal $linkScan.ScannedLocations.Count 0 'Skipped root not advertised as scanned'
Assert-Equal $denied.CoverageRecords[0].Outcome 'Error' 'Failed attempt tracked'
Assert-Equal $shallow.DepthLimitReached $false 'Automatic checks do not hit depth limit'
$cancelState = @{ Stop = $false }
$midCancel = Invoke-EloJavaScan -DriveRoots @() -ManualPath 'M:\Manual Path' -IsReparsePoint { $false } -ShouldCancel { $cancelState.Stop } -GetChildren {
    New-Entry 'M:\Manual Path\java.exe' $false
    $cancelState.Stop = $true
    New-Entry 'M:\Manual Path\second.exe' $false
} -ProbeJava { throw 'Must not probe after cancellation' }
Assert-Equal $midCancel.Cancelled $true 'Cancellation during enumeration propagated'
Assert-Equal $midCancel.Results.Count 0 'No probing after discovery cancellation'
Assert-Equal $midCancel.Discovery.CoverageRecords[0].Outcome 'Cancelled' 'Partial cancelled enumeration tracked'
$guarded = Get-EloJavaCandidates -DriveRoots @('Q:\') -IsReparsePoint { $false } -GetChildren {
    param($Path)
    if ($Path -eq 'Q:\ELO Suite\link') { throw 'Reparse child followed' }
    if ($tree.ContainsKey($Path)) { $tree[$Path] }
}
Assert-Equal $guarded.Issues.Count 0 'Reparse child never enumerated'
$parseTokens = $null; $parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'scan.ps1'), [ref]$parseTokens, [ref]$parseErrors)
Assert-Equal $parseErrors.Count 0 'Module parses with PowerShell 5.1'
Assert-Equal @($ast.EndBlock.Statements | Where-Object { $_ -isnot [System.Management.Automation.Language.FunctionDefinitionAst] }).Count 0 'Module contains only callable definitions'
Write-Output "PASS: $script:Passed assertions"
