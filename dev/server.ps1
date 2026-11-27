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
        ReportJvms=@(); ReportActions=@(); ReportIndexes=@{}; UpdateContext=$null; ReportRecovery=$null; LastUpdate=$null; Backups=@{}; BackupsCache=$null; BackupsLogged=-1; LastRejected=''; CommunityJob=$null; Online=$null
        Adapters=@{
            NewUpdateContext={ param($Root,$Runtime,$StopServices) New-EloUpdateContext -Adapters (New-EloWindowsUpdateAdapters -ApprovedRoot $Root -Runtime $Runtime -AllowServiceStop:([bool]$StopServices)) -Production }
            BackupRoots={ @([IO.DriveInfo]::GetDrives() | Where-Object { $_.IsReady -and $_.DriveType -in @([IO.DriveType]::Fixed,[IO.DriveType]::Removable) -and $_.Name -cmatch '^[C-Z]:\\$' } | ForEach-Object { $_.RootDirectory.FullName }) }
            CommunityRoot={
                $candidates=@()
                if ($env:ELO_PATCH_SOURCE) { $candidates+=(Join-Path (Split-Path -Parent $env:ELO_PATCH_SOURCE) 'tools\community') }
                $candidates+=(Join-Path (Split-Path -Parent $PSScriptRoot) 'tools\community')
                foreach ($c in $candidates) { if (Test-Path -LiteralPath (Join-Path $c 'bin\elo-community.js') -PathType Leaf) { return $c } }
                return $null
            }
            FindNode={ $n=Get-Command node -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1; if ($n) { return [string]$n.Source } else { return $null } }
            FindChrome={ foreach ($b in @($env:ProgramFiles,${env:ProgramFiles(x86)},$env:LOCALAPPDATA)) { if ($b) { $p=Join-Path $b 'Google\Chrome\Application\chrome.exe'; if (Test-Path -LiteralPath $p) { return $p } } }; return $null }
            RunProcess={ param($FilePath,$Arguments,$Environment,$WorkingDirectory,$TimeoutSec)
                $psi=New-Object Diagnostics.ProcessStartInfo; $psi.FileName=$FilePath; $psi.Arguments=$Arguments; $psi.UseShellExecute=$false; $psi.CreateNoWindow=$true
                $psi.RedirectStandardOutput=$true; $psi.RedirectStandardError=$true; $psi.WorkingDirectory=$WorkingDirectory
                foreach ($k in $Environment.Keys) { $psi.EnvironmentVariables[[string]$k]=[string]$Environment[$k] }
                $p=New-Object Diagnostics.Process; $p.StartInfo=$psi
                try {
                    if (-not $p.Start()) { throw 'process_start_failed' }
                    $out=$p.StandardOutput.ReadToEndAsync(); $err=$p.StandardError.ReadToEndAsync()
                    if (-not $p.WaitForExit([int]$TimeoutSec*1000)) { try { $p.Kill() } catch { }; throw 'process_timeout' }
                    $null=[Threading.Tasks.Task]::WaitAll(@($out,$err),5000)
                    return @{ExitCode=$p.ExitCode;Output=[string]$out.Result;Error=[string]$err.Result}
                } finally { $p.Dispose() }
            }
            StartProcess={ param($FilePath,$Arguments,$Environment,$WorkingDirectory)
                $psi=New-Object Diagnostics.ProcessStartInfo; $psi.FileName=$FilePath; $psi.Arguments=$Arguments; $psi.UseShellExecute=$false; $psi.CreateNoWindow=$true; $psi.WorkingDirectory=$WorkingDirectory
                foreach ($k in $Environment.Keys) { $psi.EnvironmentVariables[[string]$k]=[string]$Environment[$k] }
                $p=New-Object Diagnostics.Process; $p.StartInfo=$psi
                if (-not $p.Start()) { throw 'process_start_failed' }
                return $p
            }
            ScanRules={ if (Get-Command Get-EloScanRules -CommandType Function -ErrorAction SilentlyContinue) { ,@(Get-EloScanRules) } else { ,@() } }
            Log={ param($Message) Write-Host ((Get-Date).ToString('HH:mm:ss')+'  '+$Message) }
            Identity={ param($Path) Get-EloRuntimeIdentity $Path }
            EloVersion={ param($Roots) Get-EloInstalledIndexserverVersion $Roots }
            ResolveRelease={ param($Identity) Resolve-EloLatestRelease -Vendor $Identity.Vendor -Branch $Identity.Branch -Architecture $Identity.Architecture -ImageType $Identity.ImageType }
            RuntimeUsers={ param($Path) Get-EloAffectedServices $Path }
            RecordedServices={ param($Backup,$Runtime) Get-EloRecordedServices $Backup $Runtime }
            InstallUpdate={ param($Current,$Expected) Install-EloToolUpdate -BatPath $env:ELO_PATCH_SOURCE -CurrentVersion $Current -ExpectedVersion $Expected }
            RestoreBackup={ param($Root,$Runtime,$Backup,$StopServices,$Stamp)
                $services=New-EloWindowsUpdateAdapters -ApprovedRoot $Root -Runtime $Runtime -AllowServiceStop:([bool]$StopServices)
                $quiesce=$null; $resume=$null
                if ($StopServices) { $quiesce={ & $services.Quiesce @{Runtime=$Runtime;Backup=$Backup} }.GetNewClosure(); $resume={ & $services.Resume @{Runtime=$Runtime} $null }.GetNewClosure() }
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
        foreach ($a in @($v.advisories)) { $advTitle=@{en=[string]$a.title.en;de=[string]$a.title.de}; if ($a.title.es) { $advTitle.es=[string]$a.title.es }; $items+=@{id=[string]$a.id;url=[string]$a.url;title=$advTitle} }
    }
    if ($items.Count -eq 0) { return @{verifiedOn=$null;advisories=@()} }
    return @{verifiedOn=[string]($verified | Sort-Object -Descending | Select-Object -First 1);advisories=$items}
}
function Get-EloEnvironmentMitigation {
    # State of the mitigation option in the machine and user environment, whoever set it. Only the state
    # leaves the backend, never the variable. The tool process scope is not evidence about the server.
    param($Session)
    $state=@{machine='Unknown';user='Unknown'}
    try {
        $options=& $Session.Adapters.ReportOptions
        $state.machine=Get-EloReportOptionState $options.Machine
        $state.user=Get-EloReportOptionState $options.User
    } catch { }
    return $state
}
function Get-EloOnlineView {
    # The page rejects the whole results payload on an unexpected value: free-form catalog fields are blanked.
    param($Online)
    $updated=[string]$Online.Catalog.Updated; if ($updated -cnotmatch '^[0-9]{4}-[0-9]{2}-[0-9]{2}$') { $updated='' }
    $reason=[string]$Online.Catalog.Reason; if ($reason -cnotmatch '^[a-z_]{0,64}$') { $reason='' }
    return @{checked=[bool]$Online.Checked;current=[string]$Online.Current;latest=[string]$Online.Latest;available=[bool]$Online.Available;installed=[string]$Online.Installed
        catalog=@{source=[string]$Online.Catalog.Source;updated=$updated;reason=$reason}}
}
function Invoke-EloSelfUpdate {
    # Only the version the page offered, once, and never while a scan or a recovery is pending.
    param($Session,[string]$Version)
    $online=$Session.Online
    if (-not $online -or -not $online.Available -or $online.Installed -or [string]$online.Latest -cne $Version -or $Session.Worker -or $Session.RecoveryRequired) { Stop-EloRequest 409 'tool_update_unavailable' }
    try { $done=& $Session.Adapters.InstallUpdate ([string]$online.Current) $Version }
    catch {
        Write-EloLog $Session "Tool update to $Version FAILED: $(ConvertTo-EloUpdateCode $_.Exception.Message)"
        Stop-EloRequestDetail 409 'tool_update_failed' (ConvertTo-EloUpdateCode $_.Exception.Message)
    }
    $online.Installed=[string]$done.Version
    Write-EloLog $Session "Tool updated to $($done.Version). Previous file: $($done.Backup). Close this window and start the .bat again."
    return @{ok=$true}
}
function Get-EloVulnerabilityInfo {
    # What the UI needs per active vulnerability: severity, problem and solution texts, and the action ids.
    $list=@()
    foreach ($v in (Get-EloActiveVulnerabilities)) {
        $tri={ param($x) $o=@{en=[string]$x.en;de=[string]$x.de}; if ($x.es) { $o.es=[string]$x.es }; $o }
        $list+=@{id=[string]$v.id;alias=[string](@($v.aliases) | Select-Object -First 1);severity=[string]$v.severity
            title=(& $tri $v.title);problem=(& $tri $v.problem);solution=(& $tri $v.solution)
            actions=@(@($v.actions) | ForEach-Object { [string]$_.id })}
        # What can be done about it, in the catalog's own words, so new actions appear without UI changes (a restore is not a fix).
        $list[-1].actionLabels=@(@($v.actions) | Where-Object { $_ -and [string]$_.type -cne 'restore-backup' -and $_.label } | ForEach-Object { & $tri $_.label })
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
        $rules=@(); if ($Session.Adapters.ScanRules) { $allRules=& $Session.Adapters.ScanRules; $rules=@($allRules | Where-Object { $_.Vendor -ceq 'Temurin' }) }
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
    # The temporary mitigation is always allowed for a scanned runtime (also one the catalog does not classify as
    # vulnerable, e.g. Azul Zulu): the exact java.exe is probed with the flag BEFORE anything is written.
    if (-not $target) { Stop-EloRequest 409 'target_not_eligible' }
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
    $summaryAll=@{en=$summaryEn;de=$summaryDe}; if ($spec.Action.summary.es) { $summaryAll.es=Format-EloVulnText ([string]$spec.Action.summary.es) $values }
    $Session.Preview=$preview
    $notice=@()
    if ($target.Status -cne 'PotentiallyVulnerable') { $notice=@(@{en='This runtime is not classified as vulnerable by the catalog (for example another vendor). The temporary mitigation is allowed anyway: the option is probed with this exact java.exe first and nothing is written if that fails. It still applies machine-wide.';de='Diese Runtime wird vom Katalog nicht als verwundbar eingestuft (z. B. anderer Hersteller). Die vorlaeufige Risikominderung ist trotzdem erlaubt: die Option wird zuerst mit genau dieser java.exe geprueft; schlaegt das fehl, wird nichts geschrieben. Sie gilt weiterhin systemweit.'}) }
    return @{previewId=$preview.Id;summary=$summaryAll;warnings=@($notice)+@(
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
    if (-not $target -or $target.Location -cne $preview.JavaPath -or
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
    $Session.ReportActions+=@{At=(& $Session.Adapters.Clock);Kind='Mitigation';Status='Unknown';RuntimeIndex=$Session.ReportIndexes[$Body.resultId]}
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
    $Session.ReportActions+=@{At=(& $Session.Adapters.Clock);Kind='Mitigation';Status='Proven';Verified=$true;RuntimeIndex=$index
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
    if ($Vendor -ceq 'Azul Zulu') {
        try {
            $text=$Version; if ($text -cnotmatch '\+') { $text+='+0' }
            foreach ($rule in @(Get-EloScanRules | Where-Object { $_.Vendor -ceq 'Azul Zulu' })) {
                $verdict=Get-EloZuluClassification -Evidence "OpenJDK Runtime Environment Zulu (build $text)" -Rule $rule
                if ($verdict.Status -ceq 'PotentiallyVulnerable') { $result.Risk='vulnerable'; $result.Vulnerability=@(Get-EloActiveVulnerabilities | Where-Object { $_.id -ceq $rule.Id })[0]; break }
            }
        } catch { }
        return $result
    }
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
    $warning=@{en=(Format-EloVulnText ([string]$m.en) $values);de=(Format-EloVulnText ([string]$m.de) $values)}
    if ($m.es) { $warning.es=Format-EloVulnText ([string]$m.es) $values }
    return @($warning)
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
function Get-EloStopPendingWarning {
    param($Services)
    $names=@($Services | Where-Object { [string]$_.State -ceq 'Stop Pending' } | ForEach-Object { [string]$_.Name })
    if ($names.Count -eq 0) { return @() }
    $list=$names -join ', '
    return @(@{en="Already in Stop Pending: $list. The tool waits up to 3 minutes for it to stop and never kills it. If it stays stuck, the change is refused.";de="Bereits im Status Stop Pending: $list. Das Werkzeug wartet bis zu 3 Minuten auf das Beenden und erzwingt es nie. Bleibt der Dienst haengen, wird die Aenderung abgelehnt.";es="Ya están en Stop Pending: $list. La herramienta espera hasta 3 minutos a que se detengan y nunca los mata. Si siguen colgados, el cambio se rechaza."})
}
function Get-EloServiceOutcome {
    # The Java change succeeded but ELO did not come back cleanly: say it, and say that restoring is possible.
    param($Session,[string]$ServiceError)
    $code=ConvertTo-EloUpdateCode $ServiceError
    $services=([string]$ServiceError -replace '^[a-z_]+:?','') -replace '\+',', '
    $kind='services_not_restarted'
    if ($code -clike 'service_unhealthy*') { $kind='services_unhealthy' }
    Write-EloLog $Session "WARNING: $kind $services"
    $warning=@{en="Java was changed, but these ELO services did not start or load correctly: $services. The new Java version may be incompatible with ELO. Check the ELO logs; you can restore the previous version from the backup.";de="Java wurde geaendert, aber diese ELO-Dienste sind nicht korrekt gestartet oder geladen: $services. Die neue Java-Version ist moeglicherweise nicht mit ELO kompatibel. ELO-Logs pruefen; die vorherige Version kann aus dem Backup wiederhergestellt werden.";es="Se cambió Java, pero estos servicios de ELO no arrancaron o no cargaron bien: $services. La nueva versión de Java puede ser incompatible con ELO. Revisa los logs de ELO; puedes restaurar la versión anterior desde la copia."}
    return @{ok=$true;warning=$kind;warnings=@($warning)}
}
function Format-EloServiceList {
    param($Services)
    # Every service that will be stopped is named; a very long list says how many more there are.
    $names=@($Services | ForEach-Object { [string]$_.Name })
    $list=(@($names | Select-Object -First 30)) -join ', '
    if ($names.Count -gt 30) { $list+=' (+'+($names.Count-30)+')' }
    return $list
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
    $summaryEs="Sustituir el runtime $vendor $kind $($package.Branch) en $runtime ($from) por la última versión de la misma rama, $to ($($package.Architecture), SHA256 $($package.Sha256)). Pasos: copia ZIP verificada $($paths.Backup); descarga HTTPS del fabricante; extracción en $($paths.Stage); prueba de Java; renombrar el runtime antiguo a $($paths.Old); instalar; probar de nuevo. Cualquier fallo restaura el runtime antiguo. El runtime antiguo y la copia se conservan; no se borra nada."
    $warnings=@(
        @{en='ELO compatibility with this runtime is NOT verified; the update can affect ELO support. Confirming accepts this risk.';de='Die ELO-Kompatibilitaet dieser Runtime ist NICHT geprueft; das Update kann den ELO-Support beeintraechtigen. Mit der Bestaetigung wird dieses Risiko akzeptiert.'}
        @{en='The download is limited to the vendor''s official release host and its published SHA256. Installing the vendor package with its installer remains the preferred long-term fix.';de='Der Download ist auf den offiziellen Herstellerhost und die veroeffentlichte SHA256 beschraenkt. Die Installation des Herstellerpakets mit dem Installer bleibt die bevorzugte langfristige Loesung.'})
    if ($services.Count -gt 0) {
        $list=Format-EloServiceList $services
        $warnings=@(@{en="All active ELO services (and any other service using this runtime) will be STOPPED before the replacement and started again afterwards: $list. ELO is unavailable meanwhile. Confirming accepts this.";de="Alle aktiven ELO-Dienste (und jeder weitere Dienst, der diese Runtime verwendet) werden vor dem Austausch BEENDET und danach wieder gestartet: $list. ELO ist in dieser Zeit nicht verfuegbar. Mit der Bestaetigung wird dies akzeptiert.";es="Todos los servicios de ELO activos (y cualquier otro servicio que use este runtime) se DETENDRÁN antes de la sustitución y se volverán a arrancar después: $list. ELO no está disponible mientras tanto. Al confirmar aceptas esto."})+@(Get-EloStopPendingWarning $services)+$warnings
    }
    return @{previewId=$preview.Id;summary=@{en=$summaryEn;de=$summaryDe;es=$summaryEs};warnings=$warnings}
}
function Add-EloUpdateReportActions {
    param($Session,[string]$Outcome,$Preview,[int]$RuntimeIndex,[string]$FailureCode)
    $from=$Preview.FromVersion; $to=$Preview.Package.Version
    if ($Outcome -in @('Success','SimulatedSuccess','RolledBack','ManualRecoveryRequired')) {
        $Session.ReportActions+=@{At=(& $Session.Adapters.Clock);Kind='Backup';Status='Proven';Verified=$true;BackupVerified=$true;RuntimeIndex=$RuntimeIndex;EvidenceCode='BackupManifestMatched';EvidenceVerified=$true;FromVersion=$from;BackupVersion=$from}
        $Session.ReportRecovery=@{Validated=$true;RuntimeIndex=$RuntimeIndex;Archive=$Preview.Paths.Backup;Original=$Preview.Paths.Runtime;Destination=($Preview.Paths.Runtime+'.restore')}
        $Session.BackupsCache=$null
        $Session.LastUpdate=@{Runtime=$Preview.Paths.Runtime;Root=$Preview.Root;Backup=$Preview.Paths.Backup;FromVersion=$from;ToVersion=$to;RuntimeIndex=$RuntimeIndex;Services=$Preview.Services}
    }
    switch ($Outcome) {
        { $_ -in @('Success','SimulatedSuccess') } {
            # The installed runtime is new evidence: its version is classified by the catalog (fixed / vulnerable / unknown).
            $vendorName=[string]$Preview.Package.Vendor
            if ($vendorName -match '(?i)adoptium|temurin') { $vendorName='Temurin' } elseif ($vendorName -match '(?i)azul|zulu') { $vendorName='Azul Zulu' } else { $vendorName='Unknown' }
            $assessment=Get-EloBackupAssessment $vendorName ([string]$to)
            $cls='Unknown'; $clsCode='Unknown'
            if ($assessment.Risk -ceq 'patched') { $cls='Fixed'; $clsCode='AdvisoryFixedVersion' } elseif ($assessment.Risk -ceq 'vulnerable') { $cls='PotentiallyVulnerable'; $clsCode='AdvisoryRangeMatch' }
            $Session.ReportJvms+=@{Version=[string]$to;Verified=$true;ExecutionVerified=$true;Vendor=$vendorName;VendorVerified=($vendorName -cne 'Unknown');Classification=$cls;ClassificationVerified=($cls -cne 'Unknown');EvidenceCode=$clsCode}
        }
        { $_ -in @('Success','SimulatedSuccess') } { $Session.ReportActions+=@{At=(& $Session.Adapters.Clock);Kind='Update';Status='Proven';Verified=$true;RuntimeIndex=$RuntimeIndex;EvidenceCode='InstalledRuntimeValidated';EvidenceVerified=$true;FromVersion=$from;ToVersion=$to} }
        'RolledBack' {
            $Session.ReportActions+=@{At=(& $Session.Adapters.Clock);Kind='Update';Status='Failed';RuntimeIndex=$RuntimeIndex;EvidenceCode='ValidationFailed';EvidenceVerified=$true}
            $Session.ReportActions+=@{At=(& $Session.Adapters.Clock);Kind='Restore';Status='Proven';Verified=$true;RuntimeIndex=$RuntimeIndex;EvidenceCode='OriginalRuntimeRestored';EvidenceVerified=$true;FromVersion=$to;ToVersion=$from}
        }
        'ManualRecoveryRequired' {
            $Session.ReportActions+=@{At=(& $Session.Adapters.Clock);Kind='Update';Status='Failed';RuntimeIndex=$RuntimeIndex;EvidenceCode='ValidationFailed';EvidenceVerified=$true}
            $Session.ReportActions+=@{At=(& $Session.Adapters.Clock);Kind='Restore';Status='Failed';RuntimeIndex=$RuntimeIndex;EvidenceCode='RestoreFailed';EvidenceVerified=$true}
        }
        default {
            $code='ValidationFailed'; if ($FailureCode -cmatch '^(download|package_verification|unverified_https|unverified_response|truncated|redirect)') { $code='DownloadFailed' }
            $Session.ReportActions+=@{At=(& $Session.Adapters.Clock);Kind='Update';Status='Failed';RuntimeIndex=$RuntimeIndex;EvidenceCode=$code;EvidenceVerified=$true}
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
            if ($serviceNote) { return (Get-EloServiceOutcome $Session ([string]$result.ServiceError)) }
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
    $services=@(); if (Test-Path -LiteralPath $source.Runtime) { $services=@(Get-EloUpdateUsers $Session $source.Runtime) }
    # Services the update had stopped are started again even when they are not active now.
    try { $recorded=@(& $Session.Adapters.RecordedServices $source.Backup $source.Runtime) } catch { $recorded=@() }
    $activeNames=@($services | ForEach-Object { [string]$_.Name })
    $services=@(@($services)+@($recorded | Where-Object { $_ -and $activeNames -notcontains [string]$_.Name }))
    $now=& $Session.Adapters.Clock
    $preview=@{Id=(New-EloSecret);ResultId=$ResultId;ActionId='restore-backup';Runtime=$source.Runtime;Root=$source.Root;Backup=$source.Backup;Services=$services
        Stamp=$now.ToString('yyyyMMddHHmmss');FromVersion=$source.FromVersion;ToVersion=$source.ToVersion;Vendor=[string]$source.Vendor;Risk=[string]$source.Risk;JavaPath=$source.JavaPath;Index=$source.Index;Expires=$now.AddMinutes(2)}
    $Session.Preview=$preview
    $summaryEn="Restore the runtime ($($preview.ToVersion)) of $($source.Runtime) from the backup ZIP $($source.Backup). Every file is hash-checked before the swap; the current runtime (if any) is renamed to $($source.Runtime).replaced-$($preview.Stamp) and kept; nothing is deleted."
    $summaryDe="Die Runtime ($($preview.ToVersion)) von $($source.Runtime) aus dem Backup-ZIP $($source.Backup) wiederherstellen. Jede Datei wird vor dem Austausch per Hash geprueft; die aktuelle Runtime (falls vorhanden) wird nach $($source.Runtime).replaced-$($preview.Stamp) umbenannt und bleibt erhalten; es wird nichts geloescht."
    $summaryEs="Restaurar el runtime ($($preview.ToVersion)) de $($source.Runtime) desde el ZIP de copia $($source.Backup). Cada archivo se comprueba por hash antes del cambio; el runtime actual (si existe) se renombra a $($source.Runtime).replaced-$($preview.Stamp) y se conserva; no se borra nada."
    $ver=[string]$preview.ToVersion; $vend=[string]$source.Vendor
    $assessment=Get-EloBackupAssessment $vend $ver
    $warnings=@(Get-EloRestoreSecurityWarning ([string]$source.Risk) $assessment.Vulnerability $vend $ver)
    if ($services.Count -gt 0) {
        $list=Format-EloServiceList $services
        $warnings=@(@{en="The restore requires STOPPING all active ELO services (Tomcat) and any other service using this runtime: $list. ELO is unavailable while the runtime is swapped; they are started again afterwards. Confirming accepts this.";de="Die Wiederherstellung erfordert das BEENDEN aller aktiven ELO-Dienste (Tomcat) und jedes weiteren Dienstes, der diese Runtime verwendet: $list. ELO ist waehrend des Austauschs nicht verfuegbar; die Dienste werden danach wieder gestartet. Mit der Bestaetigung wird dies akzeptiert.";es="La restauración exige DETENER todos los servicios de ELO (Tomcat) activos y cualquier otro servicio que use este runtime: $list. ELO no está disponible mientras se cambia el runtime; después se vuelven a arrancar. Al confirmar aceptas esto."})+@(Get-EloStopPendingWarning $services)+$warnings
    } else {
        $warnings=@(@{en='No running service or process uses this runtime right now. If the ELO Tomcat services run on it, stop them first (ELO will be unavailable) or the restore is refused.';de='Zurzeit verwendet kein laufender Dienst oder Prozess diese Runtime. Laufen die ELO-Tomcat-Dienste darauf, diese zuerst beenden (ELO ist dann nicht verfuegbar), sonst wird die Wiederherstellung abgelehnt.'})+$warnings
    }
    return @{previewId=$preview.Id;summary=@{en=$summaryEn;de=$summaryDe;es=$summaryEs};warnings=$warnings}
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
        $swap=& $Session.Adapters.RestoreBackup $preview.Root $preview.Runtime $preview.Backup ($preview.Services.Count -gt 0) $preview.Stamp
        $restored=& $Session.Adapters.Identity $preview.Runtime
        if ([string]$preview.ToVersion -and [string]$preview.ToVersion -cne 'unknown' -and -not (Test-EloSameJavaRelease ([string]$restored.Version) ([string]$preview.ToVersion))) { throw 'restored_version_mismatch' }
    } catch {
        if ($index -gt 0) { $Session.ReportActions+=@{At=(& $Session.Adapters.Clock);Kind='Restore';Status='Failed';RuntimeIndex=$index;EvidenceCode='RestoreFailed';EvidenceVerified=$true} }
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
    $Session.ReportActions+=@{At=(& $Session.Adapters.Clock);Kind='Restore';Status='Proven';Verified=$true;RuntimeIndex=$newIndex;EvidenceCode='OriginalRuntimeRestored';EvidenceVerified=$true;FromVersion=$preview.FromVersion;ToVersion=$preview.ToVersion}
    $logAssessment=Get-EloBackupAssessment ([string]$preview.Vendor) ([string]$restored.Version)
    $logValues=Get-EloVulnMessageValues $logAssessment.Vulnerability ([string]$preview.Vendor) ([string]$restored.Version) ([string]$preview.Runtime)
    $logName='logRestoreFixed'; if ($classification -ceq 'PotentiallyVulnerable') { $logName='logRestoreVulnerable' } elseif ($classification -ceq 'Unknown') { $logName='logRestoreUnknown' }
    if ($logAssessment.Vulnerability -and $logAssessment.Vulnerability.messages.$logName) { Write-EloLog $Session (Format-EloVulnText ([string]$logAssessment.Vulnerability.messages.$logName) $logValues) }
    $Session.LastUpdate=$null; $Session.BackupsCache=$null
    if ($swap -and $swap.ServiceError) { return (Get-EloServiceOutcome $Session ([string]$swap.ServiceError)) }
    return @{ok=$true}
}function Get-EloSessionReportBundle {
    # One report in both formats, named after the server it describes.
    param($Session,[ValidateSet('en','de','es')][string]$Language)
    $html=Get-EloSessionReportHtml $Session $Language
    $hostName=''
    $title=[regex]::Match($html,'<title>[^<]* - ([A-Za-z0-9._-]{1,63})</title>')
    if ($title.Success) { $hostName=$title.Groups[1].Value }
    $fileName='elo-technical-'+$Language
    if ($hostName) { $fileName='elo-technical-'+$hostName+'-'+$Language }
    $pdf=[Convert]::ToBase64String((ConvertTo-EloReportPdf $html -Footer $hostName))
    return @{html=$html;pdf=$pdf;fileName=$fileName}
}
function Get-EloSessionReportHtml {
    param($Session,[ValidateSet('en','de','es')][string]$Language)
    # ELO version: only from the installed Indexserver files below the parent of a scanned runtime.
    $eloRoots=@($Session.Targets.Values | ForEach-Object { try { [IO.Path]::GetDirectoryName([IO.Path]::GetDirectoryName([IO.Path]::GetDirectoryName([string]$_.Location))) } catch { $null } } | Where-Object { $_ } | Select-Object -Unique)
    $eloVersion=$null; if ($Session.Adapters.EloVersion -is [scriptblock] -and $eloRoots.Count -gt 0) { try { $eloVersion=& $Session.Adapters.EloVersion $eloRoots } catch { $eloVersion=$null } }
    $eloAdapter={ @{Verified=(-not [string]::IsNullOrWhiteSpace([string]$eloVersion));Version=[string]$eloVersion} }.GetNewClosure()
    $report=New-EloTechnicalReport -EloVersionAdapter $eloAdapter -ResourceCollector $Session.Adapters.Resources -OptionsCollector $Session.Adapters.ReportOptions -JvmEvidence $Session.ReportJvms -Actions $Session.ReportActions -RecoveryEvidence $Session.ReportRecovery
    $html=ConvertTo-EloTechnicalReportHtml $report -Language $Language -GeneratedAt (& $Session.Adapters.Clock)
    $states=@{idle='Ready';scanning='Scanning';cancelling='Cancelling';completed='Completed';cancelled='Cancelled';error='Failed'}
    $notice='Session scan state: '; $scope='Session observations (including earlier scans); only a completed scan is a complete snapshot. A runtime update is performed only after explicit confirmation. ELO API support and running ELO process mitigation are not verified.'
    if ($Language -eq 'de') {
        $states=@{idle='Bereit';scanning='Scan laeuft';cancelling='Abbruch angefordert';completed='Abgeschlossen';cancelled='Abgebrochen';error='Fehlgeschlagen'}
        $notice='Scanstatus der Sitzung: '; $scope='Sitzungsnachweise (auch fruehere Scans); nur ein abgeschlossener Scan ist eine vollstaendige Momentaufnahme. Ein Runtime-Update erfolgt nur nach ausdruecklicher Bestaetigung. ELO-API-Unterstuetzung und Risikominderung im laufenden ELO-Prozess sind nicht nachgewiesen.'
    }
    if ($Language -eq 'es') {
        $states=@{idle='Listo';scanning='Escaneando';cancelling='Cancelación solicitada';completed='Completado';cancelled='Cancelado';error='Fallido'}
        $notice='Estado del escaneo de la sesión: '; $scope='Observaciones de la sesión (también de escaneos anteriores); solo un escaneo completado es una instantánea completa. Una actualización del runtime se realiza solo tras una confirmación explícita. La compatibilidad con la API de ELO y la mitigación en los procesos de ELO en ejecución no están verificadas.'
    }
    $state=$states[$Session.State]; if (-not $state) { $state=@{en='Unknown';de='Unbekannt';es='Desconocido'}[$Language] }
    # A failed rollback can invalidate earlier machine-option evidence. Do not
    # present a historical success as the current environment's postcondition.
    $recovery=''; if ($Session.RecoveryRequired) { $recovery=@{en='Manual recovery required.';de='Manuelle Wiederherstellung erforderlich.';es='Se requiere recuperación manual.'}[$Language] }
    return $html.Replace('<head>','<head><meta name="referrer" content="no-referrer"><meta http-equiv="Content-Security-Policy" content="default-src &#39;none&#39;; base-uri &#39;none&#39;; form-action &#39;none&#39;">').Replace('</header>','</header><p>'+ $notice+$state+'. '+$scope+' '+$recovery+'</p>')
}
# ---- ELO Community helper (optional Node tool in tools\community): status, model list, setup and analysis jobs.
# Credentials and API keys arrive in a request body, are handed to the child process through its environment for
# that one run, and are never stored, logged or returned.
$script:EloCommunitySecretKeys=@('ELO_COMMUNITY_USER','ELO_COMMUNITY_PASSWORD','OPENAI_API_KEY','ANTHROPIC_API_KEY')
function Get-EloCommunitySecretsPresent {
    param([string]$Root)
    $present=@{}
    foreach ($k in $script:EloCommunitySecretKeys) { $present[$k]=[bool][Environment]::GetEnvironmentVariable($k) }
    $file=Join-Path $Root 'secrets.local.env'
    if (Test-Path -LiteralPath $file -PathType Leaf) {
        foreach ($line in @([IO.File]::ReadAllLines($file))) { if ($line -cmatch '^\s*([A-Z][A-Z0-9_]*)\s*=\s*\S') { if ($script:EloCommunitySecretKeys -ccontains $Matches[1]) { $present[$Matches[1]]=$true } } }
    }
    return $present
}
function Get-EloCommunityStatus {
    param($Session)
    $root=& $Session.Adapters.CommunityRoot
    $status=@{helper=[bool]$root;node=$false;playwright=$false;chrome=$false
        secrets=@{communityUser=$false;communityPassword=$false;openaiKey=$false;anthropicKey=$false};ai=$null}
    if (-not $root) { return $status }
    $status.node=[bool](& $Session.Adapters.FindNode)
    $status.chrome=[bool](& $Session.Adapters.FindChrome)
    $status.playwright=(Test-Path -LiteralPath (Join-Path $root 'node_modules\playwright-core\package.json') -PathType Leaf)
    $p=Get-EloCommunitySecretsPresent $root
    $status.secrets=@{communityUser=[bool]$p.ELO_COMMUNITY_USER;communityPassword=[bool]$p.ELO_COMMUNITY_PASSWORD;openaiKey=[bool]$p.OPENAI_API_KEY;anthropicKey=[bool]$p.ANTHROPIC_API_KEY}
    $aiFile=Join-Path $root 'config\ai.json'
    if (Test-Path -LiteralPath $aiFile -PathType Leaf) {
        try {
            $ai=[IO.File]::ReadAllText($aiFile) | ConvertFrom-Json
            $prov=[string]$ai.provider; $model=[string]$ai.model; $base=[string]$ai.baseUrl
            if (@('openai','anthropic','ollama') -ccontains $prov -and $model -cmatch '^[A-Za-z0-9._:\-/]{1,100}$') { $status.ai=@{provider=$prov;model=$model;baseUrl=$(if ($base -cmatch '^https?://[^\s"<>]{1,200}$') { $base } else { '' })} }
        } catch { }
    }
    return $status
}
function Assert-EloCommunityText {
    param($Value,[string]$Pattern,[int]$Max,[string]$Code)
    if ($null -eq $Value) { return '' }
    $s=[string]$Value
    if ($s.Length -gt $Max -or $s -match '[\x00-\x1f\x7f]' -or ($Pattern -and $s -cnotmatch $Pattern)) { Stop-EloRequest 400 $Code }
    return $s
}
function Get-EloCommunityEnvironment {
    # Only values the person typed for THIS run; anything empty is left to the helper's own secrets file.
    param($Body)
    $env2=@{}
    $map=@{user='ELO_COMMUNITY_USER';password='ELO_COMMUNITY_PASSWORD'}
    foreach ($k in $map.Keys) { $v=Assert-EloCommunityText ([string]$Body.$k).Trim() $null 300 'invalid_parameters'; if ($v) { $env2[$map[$k]]=$v } }
    $key=Assert-EloCommunityText ([string]$Body.apiKey).Trim() $null 400 'invalid_parameters'
    if ($key) { $prov=[string]$Body.provider; if ($prov -ceq 'openai') { $env2['OPENAI_API_KEY']=$key } elseif ($prov -ceq 'anthropic') { $env2['ANTHROPIC_API_KEY']=$key } }
    return $env2
}
function Get-EloCommunityAiArguments {
    param($Body,[bool]$RequireModel)
    $prov=[string]$Body.provider
    if (@('openai','anthropic','ollama') -cnotcontains $prov) { Stop-EloRequest 400 'invalid_parameters' }
    $arguments=@('--provider',$prov)
    $model=Assert-EloCommunityText $Body.model '^[A-Za-z0-9._:\-/]{1,100}$' 100 'invalid_parameters'
    if ($RequireModel -and -not $model) { Stop-EloRequest 400 'missing_parameter' }
    if ($model) { $arguments+=@('--model',$model) }
    $base=Assert-EloCommunityText $Body.baseUrl $null 200 'invalid_parameters'
    if ($base) {
        if ($base -cnotmatch '^(https://[A-Za-z0-9.\-]+|http://(127\.0\.0\.1|localhost))(:[0-9]{1,5})?(/[A-Za-z0-9._~\-/]*)?$') { Stop-EloRequest 400 'invalid_parameters' }
        $arguments+=@('--base-url',$base)
    }
    return ,$arguments
}
function Get-EloCommunityTool {
    param($Session)
    $root=& $Session.Adapters.CommunityRoot
    if (-not $root) { Stop-EloRequestDetail 409 'community_unavailable' 'helper_not_found' }
    $node=& $Session.Adapters.FindNode
    if (-not $node) { Stop-EloRequestDetail 409 'community_unavailable' 'node_not_found' }
    return @{Root=$root;Node=$node;Cli=(Join-Path $root 'bin\elo-community.js')}
}
function Remove-EloCommunitySecrets {
    param([string]$Text,$Environment)
    $clean=[string]$Text
    foreach ($v in @($Environment.Values)) { if ($v -and ([string]$v).Length -ge 4) { $clean=$clean.Replace([string]$v,'[redacted]') } }
    return $clean
}
function Get-EloCommunityModels {
    param($Session,$Body)
    $tool=Get-EloCommunityTool $Session
    $arguments=@(('"'+$tool.Cli+'"'),'models')+(Get-EloCommunityAiArguments $Body $false)
    $environment=Get-EloCommunityEnvironment $Body
    Write-EloLog $Session "Community: listing models of '$($Body.provider)'."
    try { $r=& $Session.Adapters.RunProcess $tool.Node ($arguments -join ' ') $environment $tool.Root 40 }
    catch { Stop-EloRequestDetail 502 'community_failed' (ConvertTo-EloUpdateCode ([string]$_.Exception.Message)) }
    if ($r.ExitCode -ne 0) {
        $msg=Remove-EloCommunitySecrets (([string]$r.Error+[string]$r.Output) -replace '(?s)^.*?elo-community: ','') $environment
        $code='models_failed'; if ($msg -match 'ai_key_missing') { $code='ai_key_missing' } elseif ($msg -match 'ai_http_(\d{3})') { $code='ai_http_'+$Matches[1] } elseif ($msg -match 'ai_network_error') { $code='ai_network_error' }
        Stop-EloRequestDetail 502 'community_failed' $code
    }
    $json=@(([string]$r.Output -split "`r?`n") | Where-Object { $_ -match '^\{.*\}\s*$' } | Select-Object -Last 1)
    if ($json.Count -ne 1) { Stop-EloRequestDetail 502 'community_failed' 'models_unreadable' }
    try { $parsed=$json[0] | ConvertFrom-Json } catch { Stop-EloRequestDetail 502 'community_failed' 'models_unreadable' }
    $models=@(@($parsed.models) | Where-Object { [string]$_ -cmatch '^[A-Za-z0-9._:\-/]{1,100}$' } | Select-Object -First 300 | ForEach-Object { [string]$_ })
    return @{models=$models;current=$(if ($parsed.current) { [string]$parsed.current } else { '' })}
}
function Start-EloCommunityJob {
    param($Session,[string]$Kind,$Body)
    # The protocol carries flat strings only: consent is the exact text yes.
    if ([string]$Body.consent -cne 'yes') { Stop-EloRequest 400 'consent_required' }
    $job=$Session.CommunityJob
    if ($job -and $job.Process -and -not $job.Process.HasExited) { Stop-EloRequest 409 'community_busy' }
    $tool=Get-EloCommunityTool $Session
    $stamp=(& $Session.Adapters.Clock).ToString('yyyyMMddHHmmss')
    if ($Kind -ceq 'refine') { $outDir=Resolve-EloCommunityRunDir ([string]$Body.run) }
    else { $outDir=Join-Path (Join-Path (Get-EloQuarantineRoot) 'drafts') $stamp }
    $null=[IO.Directory]::CreateDirectory($outDir)
    $logFile=Join-Path $outDir 'run.log'
    $environment=@{}
    if ($Kind -ceq 'run') {
        $since=Assert-EloCommunityText $Body.since '^([0-9]{1,4}[dwmy]|[0-9]{4}-[0-9]{2}-[0-9]{2})$' 12 'invalid_parameters'
        if (-not $since) { Stop-EloRequest 400 'missing_parameter' }
        if ([string]$Body.max -cnotmatch '^[0-9]{1,2}$') { Stop-EloRequest 400 'invalid_parameters' }
        $max=[int]$Body.max; if ($max -lt 1 -or $max -gt 50) { Stop-EloRequest 400 'invalid_parameters' }
        $arguments=@(('"'+$tool.Cli+'"'),'run','--since',$since,'--max',[string]$max)+(Get-EloCommunityAiArguments $Body $true)
        $environment=Get-EloCommunityEnvironment $Body
    } elseif ($Kind -ceq 'refine') {
        if ([string]$Body.article -cnotmatch '^[0-9]{1,2}$') { Stop-EloRequest 400 'invalid_parameters' }
        $hint=[string]$Body.hint; if ($hint.Length -gt 4000 -or $hint -match '[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]') { Stop-EloRequest 400 'invalid_parameters' }
        $research=([string]$Body.research -ceq 'yes')
        if (-not $research -and -not $hint.Trim()) { Stop-EloRequest 400 'missing_parameter' }
        $arguments=@(('"'+$tool.Cli+'"'),'refine','--run',('"'+$outDir+'"'),'--article',[string][int]$Body.article)+(Get-EloCommunityAiArguments $Body $true)
        if ($hint.Trim()) { $hintFile=Join-Path $outDir ('hint-'+$stamp+'.txt'); [IO.File]::WriteAllText($hintFile,$hint,(New-Object Text.UTF8Encoding($false))); $arguments+=@('--hint-file',('"'+$hintFile+'"')) }
        if ($research) { $arguments+='--research' }
        $environment=Get-EloCommunityEnvironment $Body
    } else {
        $arguments=@(('"'+$tool.Cli+'"'),'setup')
    }
    $arguments+=@('--yes')
    if ($Kind -cne 'refine') { $arguments+=@('--out',('"'+$outDir+'"')) }
    $arguments+=@('--log',('"'+$logFile+'"'))
    Write-EloLog $Session "Community: starting '$Kind' (output in $outDir)."
    try { $process=& $Session.Adapters.StartProcess $tool.Node ($arguments -join ' ') $environment $tool.Root }
    catch { Stop-EloRequestDetail 502 'community_failed' 'process_start_failed' }
    $Session.CommunityJob=@{Kind=$Kind;Process=$process;OutDir=$outDir;LogFile=$logFile;Started=(& $Session.Adapters.Clock);Environment=$environment;Reported=$false}
}
function Get-EloCommunityFailureHint {
    # Plain-language cause for the codes the helper reports (never contains a credential).
    param([string]$Code)
    switch -Regex ($Code) {
        '^ai_http_401$' { return @{en='The AI provider rejected the API key (HTTP 401). Check the key typed in the field, or empty the field to use the key saved in secrets.local.env or the environment.';de='Der KI-Anbieter hat den API-Schluessel abgelehnt (HTTP 401). Den eingegebenen Schluessel pruefen oder das Feld leeren, um den in secrets.local.env bzw. der Umgebung gespeicherten zu verwenden.';es='El proveedor de IA rechazo la clave de API (HTTP 401). Revisa la clave escrita en el campo o vacia el campo para usar la guardada en secrets.local.env o en el entorno.'} }
        '^ai_http_429$' { return @{en='The AI provider limits the requests (HTTP 429). Wait a moment and try again.';de='Der KI-Anbieter begrenzt die Anfragen (HTTP 429). Kurz warten und erneut versuchen.';es='El proveedor de IA limita las peticiones (HTTP 429). Espera un momento y reintenta.'} }
        '^ai_http_(400|404)$' { return @{en='The AI provider does not accept the request or the model. Load the model list and choose one your account offers.';de='Der KI-Anbieter akzeptiert Anfrage oder Modell nicht. Modellliste laden und ein Modell Ihres Kontos waehlen.';es='El proveedor de IA no acepta la peticion o el modelo. Carga la lista de modelos y elige uno de tu cuenta.'} }
        '^ai_key_missing$' { return @{en='No API key: type one in the field or save it as OPENAI_API_KEY / ANTHROPIC_API_KEY in secrets.local.env.';de='Kein API-Schluessel: im Feld eingeben oder als OPENAI_API_KEY / ANTHROPIC_API_KEY in secrets.local.env speichern.';es='Falta la clave de API: escribela en el campo o guardala como OPENAI_API_KEY / ANTHROPIC_API_KEY en secrets.local.env.'} }
        '^ai_network_error$' { return @{en='The AI provider could not be reached. Check the network, the proxy and the base URL.';de='Der KI-Anbieter ist nicht erreichbar. Netzwerk, Proxy und Basis-URL pruefen.';es='No se pudo contactar con el proveedor de IA. Revisa la red, el proxy y la URL base.'} }
        'login_failed' { return @{en='The ELO Community rejected the user name or password.';de='Die ELO Community hat Benutzername oder Passwort abgelehnt.';es='La ELO Community rechazo el usuario o la contrasena.'} }
        'credentials_missing' { return @{en='Type your ELO Community user and password, or save them in secrets.local.env.';de='ELO-Community-Benutzer und -Passwort eingeben oder in secrets.local.env speichern.';es='Escribe tu usuario y contrasena de ELO Community o guardalos en secrets.local.env.'} }
        '^dependency_missing$' { return @{en='The helper is not installed yet: confirm and press Install the helper first.';de='Der Helfer ist noch nicht installiert: zuerst bestaetigen und Helfer installieren.';es='El asistente aun no esta instalado: confirma y pulsa Instalar el asistente.'} }
        '^research_unsupported$' { return @{en='Web research needs OpenAI or Anthropic. With Ollama paste a solution text instead.';de='Webrecherche braucht OpenAI oder Anthropic. Mit Ollama stattdessen einen Loesungstext einfuegen.';es='La investigacion web necesita OpenAI o Anthropic. Con Ollama pega un texto con la solucion.'} }
    }
    return $null
}
function ConvertTo-EloCommunitySummary {
    # Reads analysis-summary.json written by the helper and returns a bounded, sanitized list for the UI.
    param([string]$RunDir)
    $file=Join-Path $RunDir 'analysis-summary.json'
    $out=@()
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { return @() }
    # Windows PowerShell 5.1 returns a JSON array as ONE object: enumerate it explicitly.
    try { $parsed=[IO.File]::ReadAllText($file) | ConvertFrom-Json; $items=@($parsed | ForEach-Object { $_ }) } catch { return @() }
    $clip={ param($v,[int]$n) $s=[string]$v; $s=($s -replace '[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]',' '); if ($s.Length -gt $n) { $s.Substring(0,$n) } else { $s } }
    foreach ($a in @($items | Select-Object -First 60)) {
        $url=[string]$a.url; if ($url -cnotmatch '^https://community\.elo\.com/[^\s"<>]{0,380}$') { $url='' }
        $status=[string]$a.status; if (@('drafted','not-a-report','rejected','error') -cnotcontains $status) { $status='error' }
        $sev=[string]$a.severity; if (@('high','medium','low') -cnotcontains $sev) { $sev='' }
        $summary=$null
        if ($a.summary -and $a.summary.en) { $summary=@{en=(& $clip $a.summary.en 900);de=(& $clip $(if ($a.summary.de) { $a.summary.de } else { $a.summary.en }) 900)}; if ($a.summary.es) { $summary.es=(& $clip $a.summary.es 900) } }
        $solutions=@(@($a.solutionsReported) | Where-Object { $_ } | Select-Object -First 5 | ForEach-Object { $k=[string]$_.kind; if (@('update','mitigation','workaround','none') -cnotcontains $k) { $k='none' }; @{kind=$k;summary=(& $clip $_.summary 300)} })
        $out+=@{index=[int]$a.index;url=$url;title=(& $clip $a.title 300);date=(& $clip $a.date 10);status=$status;error=(& $clip $a.error 200);severity=$sev;severityReason=(& $clip $a.severityReason 500)
            summary=$summary;javaRelated=[bool]($a.javaRelated -eq $true);scriptWorthwhile=[bool]($a.scriptWorthwhile -eq $true);scriptReason=(& $clip $a.scriptReason 400);solutions=@($solutions);draftId=(& $clip $a.draftId 64);issues=[int]$a.issues}
    }
    return $out
}
function Test-EloCommunityDraft {
    # Validates a draft catalog with the app's own validator and replays its simulations (never touches the machine).
    param([string]$RunDir)
    $file=Join-Path $RunDir 'draft-vulndb.json'
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { return @{valid=$false;error='draft_missing';entries=@()} }
    try { $db=Read-EloVulnDbFile $file } catch { return @{valid=$false;error=(ConvertTo-EloUpdateCode ([string]$_.Exception.Message));entries=@()} }
    $entries=@()
    foreach ($v in @($db.vulnerabilities | Select-Object -First 50)) {
        $sim=$null; try { $sim=Invoke-EloVulnSimulation $v $db } catch { $sim=@{Passed=$false;Reason='simulation_failed'} }
        $entries+=@{id=[string]$v.id;status=[string]$v.status;passed=[bool]$sim.Passed;detected=[string]$sim.Status;reason=[string]$sim.Reason}
    }
    return @{valid=$true;error='';entries=@($entries)}
}
function Resolve-EloCommunityRunDir {
    # A run folder is only ever one of the timestamped folders below the quarantine drafts folder.
    param([string]$Stamp)
    if ($Stamp -cnotmatch '^[0-9]{14}$') { Stop-EloRequest 400 'invalid_parameters' }
    $dir=Join-Path (Join-Path (Get-EloQuarantineRoot) 'drafts') $Stamp
    if (-not (Test-Path -LiteralPath (Join-Path $dir 'articles.json') -PathType Leaf)) { Stop-EloRequest 409 'community_run_missing' }
    return $dir
}
function Get-EloCommunityJobState {
    param($Session)
    $job=$Session.CommunityJob
    if (-not $job) { return @{state='idle';kind='';log=@();drafts=@();articles=@();runId='';outDir=''} }
    $state='running'
    if ($job.Process.HasExited) {
        if ($job.Cancelled) { $state='cancelled' } elseif ($job.Process.ExitCode -eq 0) { $state='completed' } else { $state='failed' }
        if (-not $job.Reported) { $job.Reported=$true; Write-EloLog $Session "Community: '$($job.Kind)' $state."; $Session.BackupsCache=$null }
    }
    $log=@()
    if (Test-Path -LiteralPath $job.LogFile -PathType Leaf) {
        try {
            $fs=[IO.File]::Open($job.LogFile,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
            try { $len=[int][Math]::Min($fs.Length,20000); $null=$fs.Seek(-$len,[IO.SeekOrigin]::End); $buf=New-Object byte[] $len; $null=$fs.Read($buf,0,$len); $text=[Text.Encoding]::UTF8.GetString($buf) } finally { $fs.Dispose() }
            $log=@(($text -split "`r?`n") | Where-Object { $_.Trim() } | Select-Object -Last 40 | ForEach-Object { $l=Remove-EloCommunitySecrets $_ $job.Environment; $l.Substring(0,[Math]::Min(300,$l.Length)) })
        } catch { }
    }
    $drafts=@()
    $draftFile=Join-Path $job.OutDir 'draft-vulndb.json'
    $articles=@(); if (($state -ceq 'completed' -or $state -ceq 'failed') -and $job.Kind -cin @('run','refine')) { $articles=@(ConvertTo-EloCommunitySummary $job.OutDir) }
    if ($state -ceq 'completed' -and $job.Kind -cin @('run','refine') -and (Test-Path -LiteralPath $draftFile -PathType Leaf)) {
        try {
            $db=[IO.File]::ReadAllText($draftFile) | ConvertFrom-Json
            foreach ($e in @($db.vulnerabilities | Select-Object -First 50)) {
                $issues=@($e.review.issues)
                $title=[string]$e.title.en; if ($title.Length -gt 200) { $title=$title.Substring(0,200) }
                $drafts+=@{id=[string]$e.id;severity=[string]$e.severity;title=$title;solutionReported=(@($issues | Where-Object { $_ -match 'No solution reported' }).Count -eq 0);simulation=[bool]$e.simulation;issues=$issues.Count;detects=([string]$e.detection.method -ceq 'version-table' -or ([string]$e.detection.rule.vulnerablePattern -cne '(?!)'))}
            }
        } catch { $drafts=@() }
    }
    return @{state=$state;kind=[string]$job.Kind;log=@($log);drafts=@($drafts);articles=@($articles);runId=(Split-Path -Leaf ([string]$job.OutDir));outDir=[string]$job.OutDir}
}
function Invoke-EloCommunityApi {
    param($Session,$Request)
    if ($Request.Target -ceq '/api/community/status') { return (Get-EloCommunityStatus $Session) }
    if ($Request.Target -ceq '/api/community/job') { return (Get-EloCommunityJobState $Session) }
    switch -CaseSensitive ($Request.Target) {
        '/api/community/models' {
            $body=ConvertFrom-EloBody $Request.Body -Required @('provider') -Optional @('apiKey','baseUrl','model')
            return (Get-EloCommunityModels $Session $body)
        }
        '/api/community/setup' {
            $body=ConvertFrom-EloBody $Request.Body -Required @('consent')
            Start-EloCommunityJob $Session 'setup' $body
            return @{ok=$true}
        }
        '/api/community/run' {
            $body=ConvertFrom-EloBody $Request.Body -Required @('consent','since','max','provider','model') -Optional @('user','password','apiKey','baseUrl')
            Start-EloCommunityJob $Session 'run' $body
            return @{ok=$true}
        }
        '/api/community/access' {
            $body=ConvertFrom-EloBody $Request.Body -Required @('consent') -Optional @('user','password')
            if ([string]$body.consent -cne 'yes') { Stop-EloRequest 400 'consent_required' }
            $tool=Get-EloCommunityTool $Session
            $environment=Get-EloCommunityEnvironment $body
            Write-EloLog $Session 'Community: testing the sign-in.'
            try { $r=& $Session.Adapters.RunProcess $tool.Node ((@(('"'+$tool.Cli+'"'),'access','--yes')) -join ' ') $environment $tool.Root 120 }
            catch { Stop-EloRequestDetail 502 'community_failed' (ConvertTo-EloUpdateCode ([string]$_.Exception.Message)) }
            $msg=Remove-EloCommunitySecrets (([string]$r.Error+[string]$r.Output)) $environment
            if ($r.ExitCode -ne 0) {
                $code='access_failed'; if ($msg -match 'login_failed') { $code='login_failed' } elseif ($msg -match 'credentials_missing') { $code='credentials_missing' } elseif ($msg -match 'dependency_missing') { $code='dependency_missing' }
                Stop-EloRequestDetail 502 'community_failed' $code
            }
            $json=@(([string]$r.Output -split "`r?`n") | Where-Object { $_ -match '^\{.*\}\s*$' } | Select-Object -Last 1)
            if ($json.Count -ne 1) { Stop-EloRequestDetail 502 'community_failed' 'access_unreadable' }
            try { $parsed=$json[0] | ConvertFrom-Json } catch { Stop-EloRequestDetail 502 'community_failed' 'access_unreadable' }
            return @{ok=[bool]($parsed.ok -eq $true);articlesOnPage=[int]$parsed.articlesOnPage}
        }
        '/api/community/refine' {
            $body=ConvertFrom-EloBody $Request.Body -Required @('consent','run','article','provider','model') -Optional @('hint','research','apiKey','baseUrl')
            Start-EloCommunityJob $Session 'refine' $body
            return @{ok=$true}
        }
        '/api/community/validate' {
            $body=ConvertFrom-EloBody $Request.Body -Required @('run')
            return (Test-EloCommunityDraft (Resolve-EloCommunityRunDir ([string]$body.run)))
        }
        '/api/community/cancel' {
            $null=ConvertFrom-EloBody $Request.Body
            $job=$Session.CommunityJob
            if ($job -and $job.Process -and -not $job.Process.HasExited) { $job.Cancelled=$true; try { $job.Process.Kill() } catch { }; Write-EloLog $Session 'Community: cancelled.' }
            return @{ok=$true}
        }
    }
    Stop-EloRequest 404 'unknown_route'
}
function Invoke-EloApi {
    param($Session,$Request)
    Assert-EloBoundary $Session $Request
    if (-not (Test-EloSecret ([string]$Request.Headers['X-Session-Token']) $Session.Token)) { Stop-EloRequest 401 'authentication_required' }
    $get=@('/api/status','/api/results','/api/community/status','/api/community/job'); $post=@('/api/scan','/api/cancel','/api/preview','/api/action','/api/report','/api/self-update','/api/community/models','/api/community/setup','/api/community/run','/api/community/cancel','/api/community/access','/api/community/refine','/api/community/validate')
    if ($Request.Target -cnotin ($get+$post)) { Stop-EloRequest 404 'unknown_route' }
    if (($Request.Target -cin $get -and $Request.Method -cne 'GET') -or ($Request.Target -cin $post -and $Request.Method -cne 'POST')) { Stop-EloRequest 405 'method_rejected' }
    Update-EloScanWorker $Session
    if ($Request.Target -clike '/api/community/*') {
        if ($Request.Method -ceq 'POST' -and $Request.Headers['Content-Type'] -cnotin @('application/json','application/json; charset=utf-8')) { Stop-EloRequest 415 'json_required' }
        if ($Request.Method -ceq 'GET' -and $Request.Body.Length -ne 0) { Stop-EloRequest 400 'unexpected_body' }
        return (Invoke-EloCommunityApi $Session $Request)
    }
    if ($Request.Method -ceq 'GET') {
        if ($Request.Body.Length -ne 0) { Stop-EloRequest 400 'unexpected_body' }
        if ($Request.Target -ceq '/api/status') { return @{state=$Session.State} }
        if ($Session.RecoveryRequired) { Stop-EloRequest 500 'rollback_failed_manual_recovery_required' }
        if ($Session.LastError) { Stop-EloRequest $Session.LastError.Status $Session.LastError.Code }
        $payload=@{results=@($Session.Results);security=(Get-EloSecurityMetadata);vulnerabilities=@(Get-EloVulnerabilityInfo);backups=@(Get-EloBackupList $Session);environment=(Get-EloEnvironmentMitigation $Session)}
        if ($Session.Online) { $payload.online=Get-EloOnlineView $Session.Online }
        return $payload
    }
    if ($Request.Headers['Content-Type'] -cnotin @('application/json','application/json; charset=utf-8')) { Stop-EloRequest 415 'json_required' }
    switch -CaseSensitive ($Request.Target) {
        '/api/self-update' {
            $body=ConvertFrom-EloBody $Request.Body -Required @('version')
            if ($body.version -cnotmatch '^[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}$') { Stop-EloRequest 400 'invalid_version' }
            return (Invoke-EloSelfUpdate $Session $body.version)
        }
        '/api/report' {
            $body=ConvertFrom-EloBody $Request.Body -Required @('language')
            if ($body.language -cnotin @('en','de','es')) { Stop-EloRequest 400 'invalid_language' }
            return (Get-EloSessionReportBundle $Session $body.language)
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
            if ($preview -and $result.warnings) { $result.warnings=@(@($result.warnings) | ForEach-Object { Add-EloSpanish $_ }) }
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
# Spanish (castellano) for messages the backend builds in English and German. Static texts are looked up by their
# English text; the dynamic ones (service lists) are matched by pattern. The UI falls back to English when a text has no es.
$script:EloSpanishStatic=@{
    'This runtime is not classified as vulnerable by the catalog (for example another vendor). The temporary mitigation is allowed anyway: the option is probed with this exact java.exe first and nothing is written if that fails. It still applies machine-wide.'='Este runtime no está clasificado como vulnerable por el catálogo (por ejemplo, otro fabricante). La mitigación temporal se permite igualmente: la opción se prueba antes con este java.exe exacto y no se escribe nada si falla. Sigue aplicándose a toda la máquina.'
    'Existing JVMs are NOT protected. No restart is performed. Windows services may retain an old environment even after restart; a verified PrintFlagsFinal probe is not proof of service protection. Coordinate supported ELO configuration with your administrator.'='Las JVM existentes NO quedan protegidas. No se reinicia nada. Los servicios de Windows pueden conservar un entorno antiguo incluso tras reiniciar; una prueba PrintFlagsFinal verificada no demuestra la protección del servicio. Coordina con tu administrador la configuración compatible de ELO.'
    'ELO compatibility with this runtime is NOT verified; the update can affect ELO support. Confirming accepts this risk.'='La compatibilidad de ELO con este runtime NO está verificada; la actualización puede afectar al soporte de ELO. Al confirmar aceptas este riesgo.'
    'The download is limited to the vendor''s official release host and its published SHA256. Installing the vendor package with its installer remains the preferred long-term fix.'='La descarga se limita al host oficial de versiones del fabricante y a su SHA256 publicado. Instalar el paquete del fabricante con su instalador sigue siendo la solución preferible a largo plazo.'
    'No running service or process uses this runtime right now. If the ELO Tomcat services run on it, stop them first (ELO will be unavailable) or the restore is refused.'='Ningún servicio ni proceso en ejecución usa ahora este runtime. Si los servicios Tomcat de ELO lo usan, deténlos antes (ELO no estará disponible) o la restauración se rechaza.'
    'Access was denied. Check elevation and filesystem/registry permissions; no protection is claimed. Do not bypass access controls.'='Acceso denegado. Revisa la elevación y los permisos de archivos/registro; no se afirma ninguna protección. No eludas los controles de acceso.'
    'Mitigation requires an elevated administrator session. Read-only scans do not require elevation; inaccessible locations can make assessment incomplete.'='La mitigación requiere una sesión de administrador elevada. Los escaneos de solo lectura no la necesitan; las ubicaciones inaccesibles pueden dejar la valoración incompleta.'
    'Manual recovery is required before another change. Restore the preview backup and verify it; opening a new session alone does not restore the environment.'='Hace falta recuperación manual antes de otro cambio. Restaura la copia de la vista previa y verifícala; abrir una sesión nueva por sí solo no restaura el entorno.'
    'Verification failed; the exact previous environment value and type were restored and read back. No protection is claimed.'='La verificación falló; se restauraron y releyeron el valor anterior exacto del entorno y su tipo. No se afirma ninguna protección.'
    'The scan encountered inaccessible/skipped locations or traversal limits. Results are not a complete assessment. Select a narrower accessible local root; review permissions without bypassing access controls.'='El escaneo encontró ubicaciones inaccesibles u omitidas o límites de recorrido. Los resultados no son una valoración completa. Elige una carpeta local accesible más estrecha y revisa los permisos sin eludir los controles de acceso.'
    'The selected local directory is missing or inaccessible. Select an accessible directory and check permissions.'='La carpeta local seleccionada no existe o no es accesible. Elige una carpeta accesible y revisa los permisos.'
    'Automatic runtime update is unavailable: provenance, ELO compatibility, validated backups, reversible replacement and rollback guarantees are not implemented and verified. Nothing was downloaded or replaced.'='La actualización automática del runtime no está disponible: no están implementadas ni verificadas la procedencia, la compatibilidad con ELO, las copias validadas, la sustitución reversible ni las garantías de reversión. No se descargó ni sustituyó nada.'
    'The ELO Community helper is not available here (it needs the tools\community folder next to the tool and Node.js). The patch tool itself is unaffected.'='El asistente de ELO Community no está disponible aquí (necesita la carpeta tools\community junto a la herramienta y Node.js). La herramienta de parches no se ve afectada.'
    'A community job is already running. Wait for it or cancel it.'='Ya hay un trabajo de la comunidad en curso. Espera a que termine o cancélalo.'
    'Confirm that extra software may be installed and that your ELO Community credentials are used.'='Confirma que puede instalarse software adicional y que se usan tus credenciales de ELO Community.'
    'This runtime is already the newest release of its branch. Nothing to update.'='Este runtime ya es la última versión de su rama. No hay nada que actualizar.'
    'No backup from this session exists for this runtime. Restore manually from a backup ZIP using the commands in the technical report.'='No existe una copia de esta sesión para este runtime. Restaura manualmente desde un ZIP de copia con los comandos del informe técnico.'
}
function Add-EloSpanish {
    param($Item)
    if ($Item -isnot [hashtable] -or -not $Item.ContainsKey('en') -or $Item.ContainsKey('es')) { return $Item }
    $en=[string]$Item.en
    if ($script:EloSpanishStatic.ContainsKey($en)) { $Item.es=$script:EloSpanishStatic[$en]; return $Item }
    return $Item
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
    switch ($code) {
        'community_unavailable' { $warnings+=@{en='The ELO Community helper is not available here (it needs the tools\community folder next to the tool and Node.js). The patch tool itself is unaffected.';de='Der ELO-Community-Helfer ist hier nicht verfuegbar (er braucht den Ordner tools\community neben dem Werkzeug und Node.js). Das Patch-Werkzeug selbst ist nicht betroffen.'} }
        'community_busy' { $warnings+=@{en='A community job is already running. Wait for it or cancel it.';de='Ein Community-Auftrag laeuft bereits. Abwarten oder abbrechen.'} }
        'consent_required' { $warnings+=@{en='Confirm that extra software may be installed and that your ELO Community credentials are used.';de='Bestaetigen, dass zusaetzliche Software installiert werden darf und Ihre ELO-Community-Zugangsdaten verwendet werden.'} }
    }
    $detail=''; if ($cursor -and $cursor.Data.Contains('Detail')) { $detail=' ['+[string]$cursor.Data['Detail']+']' }
    switch ($code) {
        'community_failed' {
            $hint=Get-EloCommunityFailureHint ([string]$cursor.Data['Detail'])
            if ($hint) { $warnings+=$hint }
            else { $warnings+=@{en="The community helper failed.$detail Check the backend window for details; credentials are never shown.";de="Der Community-Helfer ist fehlgeschlagen.$detail Details im Backend-Fenster pruefen; Zugangsdaten werden nie angezeigt."} }
        }
        'community_run_missing' { $warnings+=@{en='That run folder no longer exists. Run the analysis again.';de='Dieser Lauf-Ordner existiert nicht mehr. Analyse erneut ausfuehren.';es='Esa carpeta de ejecucion ya no existe. Vuelve a ejecutar el analisis.'} }
        'tool_update_failed' { $warnings+=@{en="The tool update failed.$detail The tool file is unchanged.";de="Die Aktualisierung des Werkzeugs ist fehlgeschlagen.$detail Die Datei des Werkzeugs ist unveraendert.";es="Falló la actualización de la herramienta.$detail El archivo de la herramienta no ha cambiado."} }
        'tool_update_unavailable' { $warnings+=@{en='This tool update cannot be applied now. Wait for a running scan or restart the tool.';de='Diese Aktualisierung kann jetzt nicht angewendet werden. Laufenden Scan abwarten oder das Werkzeug neu starten.';es='Esta actualización no se puede aplicar ahora. Espera a que termine el escaneo o reinicia la herramienta.'} }
        'update_not_needed' { $warnings+=@{en='This runtime is already the newest release of its branch. Nothing to update.';de='Diese Runtime ist bereits die neueste Version ihres Branches. Nichts zu aktualisieren.'} }
        'no_backup_for_target' { $warnings+=@{en='No backup from this session exists for this runtime. Restore manually from a backup ZIP using the commands in the technical report.';de='Fuer diese Runtime existiert in dieser Sitzung kein Backup. Manuell aus einem Backup-ZIP wiederherstellen; Befehle stehen im technischen Bericht.'} }
        'restore_failed_no_change' { $warnings+=@{en="The restore was rejected before the runtime was swapped.$detail The current runtime is unchanged.";de="Die Wiederherstellung wurde abgelehnt, bevor die Runtime getauscht wurde.$detail Die aktuelle Runtime ist unveraendert."} }
        'update_preview_refused' { $warnings+=@{en="The runtime update cannot be offered for this JVM (only Eclipse Temurin or Azul Zulu on Windows, no other process using it, writable, with enough disk space and a published newer release).$detail Nothing was downloaded or changed.";de="Das Runtime-Update kann fuer diese JVM nicht angeboten werden (nur Eclipse Temurin oder Azul Zulu unter Windows, von keinem anderen Prozess verwendet, beschreibbar, genug Speicherplatz und eine veroeffentlichte neuere Version).$detail Nichts wurde heruntergeladen oder geaendert."} }
        'update_rejected_no_change' { $warnings+=@{en="The update was rejected before the runtime was replaced.$detail The original runtime is unchanged.";de="Das Update wurde abgelehnt, bevor die Runtime ersetzt wurde.$detail Die urspruengliche Runtime ist unveraendert."} }
        'update_failed_rolled_back' { $warnings+=@{en="The new runtime failed validation.$detail The original runtime was restored and verified; the failed runtime and the backup ZIP were kept.";de="Die neue Runtime bestand die Pruefung nicht.$detail Die urspruengliche Runtime wurde wiederhergestellt und geprueft; fehlgeschlagene Runtime und Backup-ZIP bleiben erhalten."} }
        'update_manual_recovery_required' { $warnings+=@{en="Automatic restore failed.$detail Further actions are locked. Restore manually from the backup ZIP using the commands in the technical report.";de="Automatische Wiederherstellung fehlgeschlagen.$detail Weitere Aktionen sind gesperrt. Manuell aus dem Backup-ZIP wiederherstellen; Befehle stehen im technischen Bericht."} }
    }
    if ($detail -cmatch '\[runtime_in_use_by_') { $warnings+=@{en="A process that does not belong to an active service is using this Java runtime.$detail Close it and try again.";de="Ein Prozess ohne aktiven Dienst verwendet diese Java-Runtime.$detail Beenden und erneut versuchen.";es="Un proceso que no pertenece a un servicio activo está usando este runtime de Java.$detail Ciérralo y vuelve a intentarlo."} }
    if ($detail -cmatch '\[service_(stuck_stop_pending|stop_timeout):') { $warnings+=@{en="A service did not stop in time.$detail The tool never kills processes: check the service log, end it manually or reboot the server, then try again.";de="Ein Dienst wurde nicht rechtzeitig beendet.$detail Das Werkzeug beendet nie Prozesse zwangsweise: Dienstprotokoll pruefen, manuell beenden oder Server neu starten und erneut versuchen.";es="Un servicio no se detuvo a tiempo.$detail La herramienta nunca mata procesos: revisa el log del servicio, ciérralo a mano o reinicia el servidor y vuelve a intentarlo."} }
    return @{Status=$status;Body=@{error=$code;warnings=@($warnings | ForEach-Object { Add-EloSpanish $_ })}}
}
function New-EloLoopbackListener {
    param([ValidateRange(0,65535)][int]$Port=0)
    $listener=New-Object Net.Sockets.TcpListener([Net.IPAddress]::Parse('127.0.0.1'),$Port)
    try { $listener.Start(8); return $listener }
    catch { $listener.Stop(); Stop-EloRequest 503 'loopback_bind_failed' }
}
function New-EloPreferredListener {
    # A stable loopback port keeps the browser origin (http://127.0.0.1:<port>) the same between runs, so data the page
    # keeps in localStorage (the encrypted saved keys) is found again. If that port is busy, fall back to a free one.
    param([ValidateRange(0,65535)][int]$Port=0,[ValidateRange(0,65535)][int]$PreferredPort=0)
    if ($Port -eq 0 -and $PreferredPort -gt 0) {
        try { return (New-EloLoopbackListener -Port $PreferredPort) } catch { }
    }
    return (New-EloLoopbackListener -Port $Port)
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
        [ValidateRange(0,65535)][int]$Port=0,[switch]$OpenBrowser,[switch]$NoBrowser,[scriptblock]$LaunchHandler,[ValidateRange(0,65535)][int]$PreferredPort=0)
    if ($NoBrowser -and $OpenBrowser) { Stop-EloRequest 422 'conflicting_launch_options' }
    if ($NoBrowser -and -not $LaunchHandler) { Stop-EloRequest 422 'no_browser_requires_private_launch_handler' }
    $listener=New-EloPreferredListener -Port $Port -PreferredPort $PreferredPort
    $session=$null
    try {
        $Port=$listener.LocalEndpoint.Port
        $session=New-EloServerSession -Port $Port -UiHtml $UiHtml -ScanSource $ScanSource
        if (Get-Command Get-EloOnlineState -CommandType Function -ErrorAction SilentlyContinue) {
            # Once per start, before the page loads: a newer release, and the shared catalog when none is installed.
            Write-EloLog $session 'Checking GitHub for a newer release (ELO_PATCH_NO_UPDATE_CHECK=1 disables this).'
            $session.Online=Get-EloOnlineState -CurrentVersion (Get-EloToolVersion $UiHtml) -Disabled:($env:ELO_PATCH_NO_UPDATE_CHECK -ceq '1')
            $session.Online.Installed=''
            Write-EloLog $session (Format-EloCatalogNotice $session.Online)
            if ($session.Online.Available) { Write-EloLog $session "A newer version of the tool is available: $($session.Online.Latest) (running $($session.Online.Current))." }
        }
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
