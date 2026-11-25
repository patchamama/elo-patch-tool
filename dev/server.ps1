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
        $m=Get-EloVulnAction $v 'jvm-option'
        if ($m) { $list[-1].mitigation=@{variable=[string]$m.variable;option=[string]$m.option;verifyArgs=@(@($m.verify.args) | ForEach-Object { [string]$_ })} }
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
