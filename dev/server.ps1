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
        if ($item.Status -ceq 'PotentiallyVulnerable' -and $item.Vendor -ceq 'Temurin') { $status='vulnerable' }
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
    $report=New-EloTechnicalReport -ResourceCollector $Session.Adapters.Resources -OptionsCollector $Session.Adapters.ReportOptions -JvmEvidence $Session.ReportJvms -Actions $Session.ReportActions
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
