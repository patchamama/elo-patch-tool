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

function Get-EloUpdateGaps {
    @('Official API metadata for Temurin jdk-17.0.21.1+2 windows/x64/hotspot/jdk is recorded; final redirect hosts/URL, actual archive format/layout and expansion bounds remain unverified; executable allowlist empty.',
      'Windows adapters lack disposable filesystem/process integration proof; ZIP manifest covers owner/group/DACL but not SACLs, and ZIP fallback restoration is manual.',
      'Exclusive runtime quiescence and race-free filesystem boundaries are not established; no service control is performed.')
}
function New-EloUpdateContext {
    param([hashtable]$Adapters=@{}, [switch]$Simulation)
    # Context is trusted backend state, not a wire representation.
    return @{ Adapters=$Adapters; Simulation=[bool]$Simulation; Preview=$null; Busy=$false; RecoveryRequired=$false }
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
    if (-not $Context.Simulation) { throw ('production_update_disabled: ' + ((Get-EloUpdateGaps) -join ' ')) }
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
    foreach ($key in @('Vendor','Architecture')) {
        if ([string]$Detected[$key] -cne [string]$Package[$key]) { throw "package_identity_mismatch:$key" }
    }
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
    $packageCopy=@{}; foreach ($key in @('Vendor','Branch','Architecture','Version','Uri','Sha256')) { $packageCopy[$key]=[string]$Package[$key] }
    $detected=Invoke-EloUpdateAdapter $Context Inspect @($pathsCopy.Runtime)
    $compatible=Assert-EloUpdateEvidence $Context $detected $packageCopy
    Assert-EloUpdatePreflight $Context $pathsCopy
    $now=Invoke-EloUpdateAdapter $Context Clock
    if ($now -isnot [datetime]) { throw 'invalid_clock' }
    $branchChange=([string]$detected.Branch -cne $packageCopy.Branch)
    $confirmation=[guid]::NewGuid().ToString('N')
    $branchConfirmation=''; if ($branchChange) { $branchConfirmation=[guid]::NewGuid().ToString('N') }
    $identity=@{}; foreach ($key in @('Vendor','Branch','Architecture','Fingerprint')) { $identity[$key]=[string]$detected[$key] }
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
        # Recheck the original after potentially slow backup/download/probe.
        $latest=Invoke-EloUpdateAdapter $Context Inspect @($paths.Runtime)
        foreach ($key in @('Vendor','Branch','Architecture','Fingerprint')) { if ([string]$latest[$key] -cne $preview.Detected[$key]) { throw 'target_changed' } }
        # A failed rename may have partially succeeded. Always attempt restoration.
        $mutationAttempted=$true
        $null=Invoke-EloUpdateAdapter $Context Preserve @($paths)
        $null=Invoke-EloUpdateAdapter $Context Replace @($paths)
        Assert-EloUpdateTrue (Invoke-EloUpdateAdapter $Context ValidateInstalled @($paths,$package)) 'installed_validation_failed'
        return @{ Status='SimulatedSuccess'; Backup=$paths.Backup; Old=$paths.Old; RecoveryRequired=$false; ServicesRestarted=$false }
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
        return @{ Status=$status; Error=$failure; RestoreError=$restoreFailure; RecoveryRequired=$Context.RecoveryRequired;
            Backup=$(if ($preview) { $preview.Paths.Backup }); Old=$(if ($preview) { $preview.Paths.Old }); ServicesRestarted=$false }
    } finally { if ($locked) { $Context.Busy=$false } }
}

# Parent-verified documentation: https://adoptium.net/installation/ci-scripts
# describes the binary redirect and final URL + .sha256.txt mechanism. It does
# NOT establish any exact release, redirect host, ZIP layout or supported package.
# Additional official metadata was independently fetched by the parent and supplied
# verbatim as task evidence. Record ONLY the reported fields below, without
# inferring IMPLEMENTOR, archive structure, final URL/hosts or ELO support.
# This getter performs no request and returns new informational data each call.
function Get-EloTemurinMetadataEvidence {
    return @{
        Scope='OfficialApiMetadataOnly'
        Verification='Parent independently fetched official API; package and checksum-link contents not fetched by this worker.'
        Source='https://api.adoptium.net/v3/assets/version/17.0.21.1%2B2?architecture=x64&image_type=jdk&os=windows&vendor=eclipse'
        ApiVendor='eclipse'
        ReleaseName='jdk-17.0.21.1+2'
        OS='windows'
        Architecture='x64'
        JvmImplementation='hotspot'
        ImageType='jdk'
        Uri='https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.21.1%2B2/OpenJDK17U-jdk_x64_windows_hotspot_17.0.21.1_2.zip'
        Sha256='eafba0944f777abdc74d5aad16049c9b5a1275b6ce99e2939ba9f7f3e6f08c87'
        Size=[long]191150540
        ChecksumUri='https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.21.1%2B2/OpenJDK17U-jdk_x64_windows_hotspot_17.0.21.1_2.zip.sha256.txt'
    }
}
# Separate executable policy: metadata getter above is deliberately NOT consumed
# here. Before any promotion, independently verify the entire redirect chain and
# final HTTPS hosts/URL, actual archive format, root and expansion bounds. Existing
# runtime IMPLEMENTOR/release/PE mapping and all filesystem/process guarantees also
# need proof. A .zip URL suffix is NOT archive-format evidence. Do not populate this
# list from HTTP/API/client parameters or treat this metadata as ELO approval.
function Get-EloVerifiedTemurinReleases { @() }
function Get-EloPinnedTemurinRelease {
    param($Package)
    foreach ($record in @(Get-EloVerifiedTemurinReleases)) {
        if ($record.Vendor -cne 'Eclipse Adoptium' -or $record.Format -cne 'zip') { continue }
        $matches=$true
        foreach ($key in @('Vendor','Version','Branch','Architecture','Uri','Sha256')) {
            if ([string]$record[$key] -cne [string]$Package[$key]) { $matches=$false }
        }
        if ($matches) { return $record }
    }
    throw 'no_independently_verified_exact_temurin_release'
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
function Invoke-EloPinnedDownload {
    param($Package,[string]$Destination)
    $record=Get-EloPinnedTemurinRelease $Package # ALWAYS before network or file creation
    $uri=Assert-EloHttpsHost $record.Uri $record.AllowedHosts
    $final=$null
    # Disable implicit redirects, cookies, proxies, credentials and decompression.
    # TLS is per-request; never mutate machine/process ServicePointManager settings.
    for ($hop=0; $hop -le 5; $hop++) {
        $request=[Net.HttpWebRequest]::Create($uri)
        $request.AllowAutoRedirect=$false; $request.Proxy=$null; $request.UseDefaultCredentials=$false
        $request.Timeout=30000; $request.ReadWriteTimeout=30000
        if (-not $request.PSObject.Properties['SslProtocols']) { throw 'per_request_tls_unavailable' }
        $request.SslProtocols=[Security.Authentication.SslProtocols]::Tls12
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
            if ($code -ne 200 -or $response.ContentLength -le 0 -or $response.ContentLength -gt $record.MaxArchiveBytes -or
                $response.ResponseUri.AbsoluteUri -cne $record.FinalUri) { throw 'unverified_response_or_length' }
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
    if (-not $final -or (Get-FileHash -LiteralPath $Destination -Algorithm SHA256 -ErrorAction Stop).Hash -ine $record.Sha256) { throw 'download_checksum_mismatch' }
    # The hash must have been independently pinned from the published checksum.
    # No inference from a .zip suffix or content-type is used as format evidence.
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
    if ($base.Length -le 3 -or -not $full.StartsWith($base+'\',[StringComparison]::OrdinalIgnoreCase)) { throw 'outside_approved_boundary' }
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
        $items.Add([pscustomobject][ordered]@{Name=$relative;Directory=[bool]$item.PSIsContainer;Length=$length;Hash=$hash;Sddl=$sddl;Attributes=[int]$item.Attributes;Ticks=$item.LastWriteTimeUtc.Ticks})
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
    $record=Get-EloPinnedTemurinRelease $Package
    Initialize-EloZip
    $null=Assert-EloWindowsBoundary $Root $Paths.Stage
    if (Test-Path -LiteralPath $Paths.Stage) { throw 'staging_already_exists' }
    if ((Get-FileHash -LiteralPath $Paths.Download -Algorithm SHA256 -ErrorAction Stop).Hash -ine $record.Sha256) { throw 'archive_checksum_mismatch' }
    $input=[IO.File]::OpenRead($Paths.Download); $zip=$null
    try {
        $zip=New-Object IO.Compression.ZipArchive($input,[IO.Compression.ZipArchiveMode]::Read,$true)
        $null=Assert-EloArchiveEntries $zip.Entries $record.ArchiveRoot $record.MaxExpandedBytes
        $null=[IO.Directory]::CreateDirectory($Paths.Stage)
        foreach ($entry in $zip.Entries) {
            $relative=$entry.FullName.Substring($record.ArchiveRoot.Length+1)
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
function Get-EloTemurinIdentity {
    param([string]$Path)
    $release=Join-Path $Path 'release'; $java=Join-Path $Path 'bin\java.exe'
    if ((Get-Item -LiteralPath $release -ErrorAction Stop).Length -gt 65536) { throw 'release_size_limit' }
    $values=@{}
    foreach ($line in [IO.File]::ReadAllLines($release)) {
        if ($line -cmatch '^(IMPLEMENTOR|JAVA_VERSION|JAVA_RUNTIME_VERSION|OS_ARCH|OS_NAME)="([^"\x00-\x1f]*)"$') {
            if ($values.ContainsKey($Matches[1])) { throw 'duplicate_release_key' }; $values[$Matches[1]]=$Matches[2]
        }
    }
    if ($values.IMPLEMENTOR -cne 'Eclipse Adoptium' -or $values.OS_NAME -cne 'Windows' -or
        -not $values.JAVA_RUNTIME_VERSION) { throw 'unrecognized_temurin_identity' }
    $versionMatch=[regex]::Match([string]$values.JAVA_VERSION,'^(\d+)\.')
    if (-not $versionMatch.Success) { throw 'unrecognized_temurin_identity' }
    $branch=$versionMatch.Groups[1].Value
    $stream=[IO.File]::OpenRead($java); $reader=New-Object IO.BinaryReader($stream)
    try {
        if ($reader.ReadUInt16() -ne 23117) { throw 'java_not_pe' }
        $stream.Position=60; $offset=$reader.ReadInt32()
        if ($offset -lt 64 -or $offset -gt $stream.Length-6) { throw 'invalid_pe_offset' }
        $stream.Position=$offset; if ($reader.ReadUInt32() -ne 17744) { throw 'invalid_pe_signature' }
        $machine=$reader.ReadUInt16()
    } finally { $reader.Dispose(); $stream.Dispose() }
    $arch=''; if ($machine -eq 34404 -and $values.OS_ARCH -ceq 'amd64') { $arch='x64' }
    if ($machine -eq 43620 -and $values.OS_ARCH -ceq 'aarch64') { $arch='ARM64' }
    if (-not $arch) { throw 'unsupported_or_inconsistent_architecture' }
    return @{Vendor=$values.IMPLEMENTOR;Branch=$branch;Architecture=$arch;Version=$values.JAVA_RUNTIME_VERSION}
}
function Invoke-EloBoundedJavaVersion {
    param([string]$Path,$Package)
    $identity=Get-EloTemurinIdentity $Path
    foreach ($key in @('Vendor','Branch','Architecture','Version')) { if ($identity[$key] -cne $Package[$key]) { throw 'java_identity_mismatch' } }
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
        if (-not $process.WaitForExit(1000) -or $process.ExitCode -ne 0 -or -not $text.ToString().Contains($Package.Version)) { throw 'java_version_probe_failed' }
        return $true
    } finally {
        try { if ($started -and -not $process.HasExited) { $process.Kill(); $null=$process.WaitForExit(2000) } }
        finally { $process.Dispose() }
    }
}
function New-EloWindowsUpdateAdapters {
    param([Parameter(Mandatory=$true)][string]$ApprovedRoot,[Parameter(Mandatory=$true)][string]$Runtime)
    # Factory itself performs no IO. Only direct, explicitly invoked adapter calls
    # can do work. Engine production gate remains closed regardless of injection.
    $state=@{Root=$ApprovedRoot;Runtime=$Runtime;Original=$null;Staged=$null;FailedPath=$null}
    return @{
        Clock={ [DateTime]::UtcNow }
        Admin={
            $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
            try { (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
            finally { $identity.Dispose() }
        }
        Inspect={ param($Path)
            if ($Path -cne $state.Runtime) { throw 'runtime_not_explicitly_selected' }
            $manifest=Get-EloRuntimeManifest $state.Root $Path
            $identity=Get-EloTemurinIdentity $Path; $identity.Fingerprint=$manifest.Fingerprint
            $state.Original=$manifest; $identity
        }.GetNewClosure()
        Evidence={ param($Detected,$Package)
            $record=Get-EloPinnedTemurinRelease $Package
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
            # Cannot infer writable rights or exclusive quiescence from ACLs or a
            # process-list snapshot. These gates stay FALSE, never restart services.
            @{SafePaths=$true;Quiescent=$false;Permissions=$false;Space=($drive.AvailableFreeSpace -gt (6*$manifest.Bytes+1GB))}
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
            $record=Get-EloPinnedTemurinRelease $Package
            (Get-FileHash -LiteralPath $Paths.Download -Algorithm SHA256 -ErrorAction Stop).Hash -ieq $record.Sha256
        }
        Stage={ param($Package,$Paths)
            Expand-EloPinnedArchive $state.Root $Package $Paths
            $state.Staged=Get-EloRuntimeManifest $state.Root $Paths.Stage
        }.GetNewClosure()
        Probe={ param($Path,$Package) Invoke-EloBoundedJavaVersion $Path $Package }
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
                (Invoke-EloBoundedJavaVersion $Paths.Runtime $Package)
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
}
