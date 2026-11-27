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
      'Quiescence is checked fail-closed (no process or service with the runtime loaded, exclusive open of java binaries); every active ELO service is stopped only with explicit confirmation, restarted afterwards and checked for loading. ELO compatibility is never assumed.')
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
    # Active services and other processes that have the runtime loaded: their image
    # or any loaded module lives below the runtime directory. Read-only; protected
    # processes whose modules cannot be listed are skipped (and cannot be proven idle).
    param([string]$Path)
    $prefix=[IO.Path]::GetFullPath($Path).TrimEnd('\')+'\'
    $services=@{}
    foreach ($service in @(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop)) {
        if (@(Get-EloActiveServiceMap @($service)).Count -eq 1) { $services[[int]$service.ProcessId]=$service }
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
function Get-EloActiveServiceMap {
    # Every service that still owns a process. A service in Stop Pending (or any other
    # pending/paused state) is still a service, never a foreign process.
    param($Services)
    return @($Services | Where-Object { [int]$_.ProcessId -gt 0 -and [string]$_.State -cne 'Stopped' })
}
function Select-EloStackServices {
    # The active ELO services: named ELO*, or installed below the ELO folder that holds the
    # runtime. A drive root is never used as that folder.
    param($Services,[string]$EloRoot)
    $prefix=''
    if ($EloRoot -and $EloRoot.TrimEnd('\') -cnotmatch '^[A-Za-z]:$') { $prefix=$EloRoot.TrimEnd('\')+'\' }
    return @(Get-EloActiveServiceMap $Services | Where-Object {
        $image=([string]$_.PathName).TrimStart('"')
        ([string]$_.Name -match '^ELO([-_ ]|$)') -or ($prefix -and $image.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase))
    })
}
function Get-EloServiceOrder {
    # ELO-Basis hosts what the other ELO services depend on: it stops last and starts first.
    param([string[]]$Names,[switch]$Start)
    $unique=@($Names | Where-Object { $_ } | Select-Object -Unique)
    $basis=@($unique | Where-Object { $_ -match '(?i)^ELO[-_ ]Basis' }); $others=@($unique | Where-Object { $_ -notmatch '(?i)^ELO[-_ ]Basis' })
    if ($Start) { return @($basis+$others) }
    return @($others+$basis)
}
function Get-EloAffectedServices {
    # What a runtime change has to stop: whatever has the runtime loaded plus every active ELO service.
    param([string]$Path)
    $users=Get-EloRuntimeUsers $Path
    $all=@(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop)
    $found=@{}; foreach ($service in $users.Services) { $found[[string]$service.Name]=$service }
    foreach ($service in @(Select-EloStackServices $all ([IO.Path]::GetDirectoryName($Path.TrimEnd('\'))))) {
        if (-not $found.ContainsKey([string]$service.Name)) { $found[[string]$service.Name]=@{Name=[string]$service.Name;DisplayName=[string]$service.DisplayName;ProcessId=[int]$service.ProcessId} }
    }
    $states=@{}; foreach ($service in $all) { $states[[string]$service.Name]=[string]$service.State }
    $services=@(Get-EloServiceOrder @($found.Keys | Sort-Object) | ForEach-Object { $item=$found[$_]; $item.State=$states[$_]; $item })
    return @{Services=$services;Processes=$users.Processes}
}
function Stop-EloOneService {
    # One stop request, never a process kill. A Stop Pending service is only waited for.
    param([string]$Name,[hashtable]$Control)
    $pending=([string](& $Control.Status $Name) -ceq 'StopPending')
    if (-not $pending) { $null=& $Control.Stop $Name }
    if (-not (& $Control.WaitStopped $Name)) {
        if ($pending) { throw ('service_stuck_stop_pending:'+$Name) }
        throw ('service_stop_timeout:'+$Name)
    }
}
function Test-EloServicesLoaded {
    # Loaded = Running with every previously listening port listening again, and still so
    # after the settle time. Returns the names of the services that did not load.
    param([hashtable]$Expected,[scriptblock]$Probe,[scriptblock]$Clock,[scriptblock]$Sleep,[int]$TimeoutSeconds=300,[int]$SettleSeconds=20)
    $failing={
        foreach ($name in @($Expected.Keys | Sort-Object)) {
            $sample=& $Probe $name
            if ([string]$sample.Status -cne 'Running' -or @($Expected[$name] | Where-Object { @($sample.Ports) -notcontains $_ }).Count -gt 0) { $name }
        }
    }
    $begin=& $Clock
    while ($true) {
        $failed=@(& $failing)
        if ($failed.Count -eq 0) { break }
        if (((& $Clock)-$begin) -ge $TimeoutSeconds) { return $failed }
        $null=& $Sleep 5
    }
    $null=& $Sleep $SettleSeconds
    return @(& $failing)
}
function Get-EloServiceSample {
    # Status of one service and the fixed (non-ephemeral) TCP ports its process tree listens on.
    param([string]$Name)
    $service=Get-CimInstance -ClassName Win32_Service -Filter ("Name='"+$Name.Replace("'","''")+"'") -ErrorAction Stop
    if (-not $service) { return @{Status='Missing';Ports=@()} }
    $status=([string]$service.State) -replace ' ',''
    if ([int]$service.ProcessId -le 0) { return @{Status=$status;Ports=@()} }
    $tree=@{}; $tree[[int]$service.ProcessId]=$true
    $all=@(Get-CimInstance -ClassName Win32_Process -ErrorAction Stop)
    do { $added=$false; foreach ($process in $all) { if ($tree.ContainsKey([int]$process.ParentProcessId) -and -not $tree.ContainsKey([int]$process.ProcessId)) { $tree[[int]$process.ProcessId]=$true; $added=$true } } } while ($added)
    $ports=@(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { $tree.ContainsKey([int]$_.OwningProcess) -and [int]$_.LocalPort -lt 49152 } | ForEach-Object { [int]$_.LocalPort } | Sort-Object -Unique)
    return @{Status=$status;Ports=$ports}
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
    $input=[IO.File]::OpenRead($Backup); $zip=$null; $quiesced=$false; $aclExact=$true; $outcome=$null
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
        $outcome=@{Restored=$true;Replaced=$(if ($moved) { $replaced } else { $null });AclExact=$aclExact;ServiceError=$null}
        return $outcome
    } finally {
        if ($zip) { $zip.Dispose() }; $input.Dispose()
        # $outcome is the object already returned: a failed restart or load check is added to it.
        if ($quiesced -and $Resume) { try { $null=& $Resume } catch { if ($outcome) { $outcome.ServiceError=$_.Exception.Message } } }
    }
}
function New-EloWindowsUpdateAdapters {
    param([Parameter(Mandatory=$true)][string]$ApprovedRoot,[Parameter(Mandatory=$true)][string]$Runtime,[switch]$AllowServiceStop)
    # Factory itself performs no IO. Only direct, explicitly invoked adapter calls
    # can do work. Engine production gate remains closed regardless of injection.
    $state=@{Root=$ApprovedRoot;Runtime=$Runtime;Original=$null;Staged=$null;FailedPath=$null;Stopped=(New-Object 'System.Collections.Generic.List[string]');Ports=@{};AllowServiceStop=[bool]$AllowServiceStop}
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
        # Opt-in (the user confirmed the services listed in the preview). Every active ELO
        # service and every service using this runtime is stopped; Resume starts them again
        # on success and on failure alike, then checks that they loaded.
        $adapters.Quiesce={ param($Paths)
            $users=Get-EloAffectedServices $Paths.Runtime
            if ($users.Processes.Count -gt 0) { throw 'runtime_in_use_by_process' }
            # Listening ports are recorded before anything stops: they are the load check afterwards.
            foreach ($user in $users.Services) { $state.Ports[[string]$user.Name]=@((Get-EloServiceSample $user.Name).Ports) }
            $control=@{
                Status={ param($n) [string](Get-Service -Name $n -ErrorAction Stop).Status }
                Stop={ param($n) Stop-Service -Name $n -Force -NoWait -ErrorAction Stop }
                WaitStopped={ param($n) try { (Get-Service -Name $n -ErrorAction Stop).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(180)); $true } catch [System.ServiceProcess.TimeoutException] { $false } }
            }
            foreach ($name in @(Get-EloServiceOrder @($users.Services | ForEach-Object { [string]$_.Name }))) {
                $service=Get-Service -Name $name -ErrorAction Stop
                if ([string]$service.Status -ceq 'Stopped') { if (-not $state.Stopped.Contains($name)) { $state.Stopped.Add($name) }; continue }
                foreach ($dependent in @($service.DependentServices | Where-Object { $_.Status -ne 'Stopped' })) {
                    if (-not $state.Stopped.Contains([string]$dependent.Name)) { $state.Stopped.Add([string]$dependent.Name) }
                    Stop-EloOneService ([string]$dependent.Name) $control
                }
                if (-not $state.Stopped.Contains($name)) { $state.Stopped.Add($name) }
                Stop-EloOneService $name $control
            }
            if (-not (Test-EloRuntimeQuiescent $Paths.Runtime)) { throw 'runtime_still_in_use_after_service_stop' }
            @($state.Stopped)
        }.GetNewClosure()
        $adapters.Resume={ param($Paths,$Stopped)
            $failed=New-Object 'System.Collections.Generic.List[string]'
            $expected=@{}
            foreach ($name in @(Get-EloServiceOrder @($state.Stopped) -Start)) {
                try {
                    $service=Get-Service -Name $name -ErrorAction Stop
                    if ($service.Status -ne 'Running') { Start-Service -Name $name -ErrorAction Stop; $service.WaitForStatus('Running',[TimeSpan]::FromSeconds(180)) }
                    $expected[$name]=@($state.Ports[$name] | Where-Object { $null -ne $_ })
                } catch { $failed.Add($name) }
            }
            $state.Stopped.Clear(); $state.Ports.Clear()
            if ($failed.Count -gt 0) { throw ('service_restart_failed:'+($failed -join '+')) }
            if ($expected.Count -gt 0) {
                $watch=[Diagnostics.Stopwatch]::StartNew()
                $unhealthy=@(Test-EloServicesLoaded -Expected $expected -Probe { param($n) Get-EloServiceSample $n } -Clock { $watch.Elapsed.TotalSeconds }.GetNewClosure() -Sleep { param($seconds) Start-Sleep -Seconds $seconds })
                if ($unhealthy.Count -gt 0) { throw ('service_unhealthy:'+($unhealthy -join '+')) }
            }
        }.GetNewClosure()
    }
    return $adapters
}
