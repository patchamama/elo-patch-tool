# Windows PowerShell 5.1; deterministic mocks only. No live ELO or network access.
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/update.ps1"
function Assert-UpdateTest($Condition, $Message) { if (-not $Condition) { throw "ASSERT: $Message" } }
function New-UpdateFixture {
    $state = @{ Events=New-Object 'System.Collections.Generic.List[string]'; Fail=''; Admin=$true; Now=[datetime]'2026-01-01T00:00:00Z'; Installed='old'; Old=$false; Backup=$false; Stage=$false; Identity='original'; Branch='17'; Verified=$true }
    $adapters = @{
        Clock={ $state.Now }.GetNewClosure()
        Admin={ $state.Admin }.GetNewClosure()
        Inspect={ param($Path) @{ Vendor='FixtureVendor'; Branch='17'; Architecture='x64'; Fingerprint=$state.Identity } }.GetNewClosure()
        Evidence={ param($Detected,$Package) @{ Official=$state.Verified; Compatibility=$state.Verified; PublishedHash=$state.Verified } }.GetNewClosure()
        Preflight={ param($Paths) $state.Events.Add('preflight'); @{ SafePaths=$true; Quiescent=$true; Permissions=$true; Space=$true } }.GetNewClosure()
        Backup={ param($Paths) $state.Events.Add('backup'); if ($state.Fail -eq 'backup') { throw 'backup failure' }; $state.Backup=$true }.GetNewClosure()
        VerifyBackup={ param($Paths,$Detected) $state.Events.Add('verify-backup'); return ($state.Backup -and $state.Fail -ne 'verify-backup') }.GetNewClosure()
        Download={ param($Package,$Paths) $state.Events.Add('download'); if ($state.Fail -eq 'download') { throw 'download failure' } }.GetNewClosure()
        VerifyPackage={ param($Package,$Paths) $state.Events.Add('verify-package'); return ($state.Fail -ne 'checksum') }.GetNewClosure()
        Stage={ param($Package,$Paths) $state.Events.Add('copy'); if ($state.Fail -eq 'copy') { throw 'copy failure' }; $state.Stage=$true }.GetNewClosure()
        Probe={ param($Path,$Package) $state.Events.Add('probe'); return ($state.Fail -ne 'probe') }.GetNewClosure()
        Preserve={ param($Paths) $state.Events.Add('preserve'); if ($state.Fail -eq 'preserve') { throw 'preserve failure' }; $state.Installed=''; $state.Old=$true }.GetNewClosure()
        Replace={ param($Paths) $state.Events.Add('replace'); $state.Installed='partial'; if ($state.Fail -eq 'replacement') { throw 'replacement failure' }; $state.Installed='new' }.GetNewClosure()
        ValidateInstalled={ param($Paths,$Package) $state.Events.Add('validate'); return ($state.Fail -notin @('installed','restore','verify-restored')) }.GetNewClosure()
        Restore={ param($Paths) $state.Events.Add('restore'); if ($state.Fail -eq 'restore') { throw 'restore failure' }; $state.Installed='old' }.GetNewClosure()
        VerifyRestored={ param($Paths,$Detected) $state.Events.Add('verify-restored'); return ($state.Installed -eq 'old' -and $state.Fail -ne 'verify-restored') }.GetNewClosure()
    }
    $package = @{ Vendor='FixtureVendor'; Branch='17'; Architecture='x64'; Version='17.0.99'; Uri='https://fixture.invalid/runtime.zip'; Sha256=('a'*64) }
    $paths = @{ Runtime='C:\Fixture with spaces\runtime'; Old='C:\Fixture with spaces\runtime.old'; Stage='C:\Fixture with spaces\staging'; Backup='C:\Fixture with spaces\backup.zip'; Download='C:\Fixture with spaces\package.zip' }
    $context = New-EloUpdateContext -Adapters $adapters -Simulation
    return @{ State=$state; Context=$context; Package=$package; Paths=$paths }
}
function New-FixturePreview($Fixture) { New-EloUpdatePreview -Context $Fixture.Context -Paths $Fixture.Paths -Package $Fixture.Package }
function Invoke-FixtureUpdate($Fixture,$Preview) { Invoke-EloRuntimeUpdate -Context $Fixture.Context -Confirmation $Preview.Confirmation -BranchConfirmation $Preview.BranchConfirmation -CompatibilityConfirmation $Preview.CompatibilityConfirmation }
function Assert-PreviewRejected($Fixture,$Code) {
    $message=''; $before=$Fixture.State.Installed; $backupBefore=$Fixture.State.Backup
    try { $null=New-FixturePreview $Fixture } catch { $message=$_.Exception.Message }
    Assert-UpdateTest ($message -like "*$Code*") "expected preview rejection $Code, got $message"
    Assert-UpdateTest ($Fixture.State.Installed -eq $before -and $Fixture.State.Backup -eq $backupBefore) 'no writes on preview rejection'
}
$f=New-UpdateFixture
$f.Package.Branch='21'; $f.Package.Version='21.0.9'
$branchRejected=$false
try { $null=New-FixturePreview $f } catch { $branchRejected=$_.Exception.Message -like '*package_identity_mismatch:Branch*' }
Assert-UpdateTest ($branchRejected -and -not $f.State.Backup) 'different Java major must be rejected before backup'
$f=New-UpdateFixture
$p=New-FixturePreview $f
$r=Invoke-FixtureUpdate $f $p
Assert-UpdateTest ($r.Status -eq 'SimulatedSuccess') 'successful transaction'
Assert-UpdateTest ($f.State.Backup -and $f.State.Old -and $f.State.Installed -eq 'new') 'backup and old runtime retained'
Assert-UpdateTest (($f.State.Events -join ',') -eq 'preflight,preflight,backup,verify-backup,download,verify-package,copy,probe,preserve,replace,validate') 'ordered safety checks'
Assert-UpdateTest ((Invoke-FixtureUpdate $f $p).Status -eq 'Rejected') 'confirmation cannot be replayed'
Write-Output 'PASS: ordered simulated transaction, paths with spaces, retained recovery artifacts, replay rejection'
foreach ($failure in @('backup','verify-backup','download','checksum','copy','probe')) {
    $f=New-UpdateFixture; $p=New-FixturePreview $f; $f.State.Fail=$failure
    $r=Invoke-FixtureUpdate $f $p
    Assert-UpdateTest ($r.Status -eq 'Rejected' -and $f.State.Installed -eq 'old') "$failure leaves original untouched"
    Assert-UpdateTest (-not $f.State.Events.Contains('preserve') -and -not $f.State.Events.Contains('restore')) "$failure never replaces/restores original"
    Write-Output "PASS: $failure fails before runtime mutation"
}
foreach ($failure in @('preserve','replacement','installed','restore','verify-restored')) {
    $f=New-UpdateFixture; $p=New-FixturePreview $f; $f.State.Fail=$failure
    $r=Invoke-FixtureUpdate $f $p
    if ($failure -in @('restore','verify-restored')) {
        Assert-UpdateTest ($r.Status -eq 'ManualRecoveryRequired' -and $r.RecoveryRequired -and $r.RestoreError) "$failure reports manual recovery"
        Assert-PreviewRejected $f 'manual_recovery_required'
    } else {
        Assert-UpdateTest ($r.Status -eq 'RolledBack' -and $f.State.Installed -eq 'old') "$failure rolls back"
    }
    Assert-UpdateTest ($f.State.Backup -and $f.State.Events.Contains('restore')) "$failure retains ZIP and attempts restore"
    Write-Output "PASS: $failure rollback/recovery behavior"
}
foreach ($case in @('missing','wrong','expired','clock-backwards','changed','admin','new-preview')) {
    $f=New-UpdateFixture
    $p=New-FixturePreview $f
    switch ($case) {
        missing { $p.Confirmation='' }
        wrong { $p.Confirmation='wrong' }
        expired { $f.State.Now=$f.State.Now.AddMinutes(5) }
        clock-backwards { $f.State.Now=$f.State.Now.AddSeconds(-1) }
        changed { $f.State.Identity='changed' }
        admin { $f.State.Admin=$false }
        new-preview { $null=New-FixturePreview $f }
    }
    $r=Invoke-FixtureUpdate $f $p
    Assert-UpdateTest ($r.Status -eq 'Rejected' -and -not $f.State.Backup) "$case confirmation gate"
    Write-Output "PASS: $case gate"
}
foreach ($case in @('vendor','architecture','http','checksum','provenance','unknown','overlap','traversal','volume','zip','admin','production')) {
    $f=New-UpdateFixture; $code=''
    switch ($case) {
        vendor { $f.Package.Vendor='Other'; $code='package_identity_mismatch' }
        architecture { $f.Package.Architecture='x86'; $code='package_identity_mismatch' }
        http { $f.Package.Uri='http://fixture.invalid/runtime.zip'; $code='official_https_required' }
        checksum { $f.Package.Sha256=''; $code='incomplete_package_identity' }
        provenance { $f.State.Verified=$false; $code='unverified_evidence' }
        unknown { $f.State.Identity='unknown'; $code='unknown_detected_identity' }
        overlap { $f.Paths.Stage=$f.Paths.Runtime+'\stage'; $code='overlapping_paths' }
        traversal { $f.Paths.Stage='C:\fixture\..\stage'; $code='unsafe_path' }
        volume { $f.Paths.Stage='D:\stage'; $code='same_volume_required' }
        zip { $f.Paths.Backup='C:\fixture\backup.txt'; $code='backup_zip_required' }
        admin { $f.State.Admin=$false; $code='administrator_required' }
        production { $f.Context.Simulation=$false; $code='production_update_disabled' }
    }
    Assert-PreviewRejected $f $code
    Write-Output "PASS: $case preview rejection"
}
foreach ($check in @('SafePaths','Quiescent','Permissions','Space')) {
    $f=New-UpdateFixture
    $checks=@{SafePaths=$true;Quiescent=$true;Permissions=$true;Space=$true}; $checks[$check]=$false
    $f.Context.Adapters.Preflight={ param($Paths) $checks }.GetNewClosure()
    Assert-PreviewRejected $f 'preflight_failed'
    Write-Output "PASS: preflight $check"
}
# Caller mutation of the original request cannot retarget a confirmed transaction.
$f=New-UpdateFixture; $p=New-FixturePreview $f
$f.Package.Uri='http://untrusted.invalid/'; $f.Paths.Runtime='C:\Other runtime'
Assert-UpdateTest ((Invoke-FixtureUpdate $f $p).Status -eq 'SimulatedSuccess') 'preview holds copied request'
# Neither the module nor harness may perform top-level operational work.
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile("$PSScriptRoot/update.ps1",[ref]$tokens,[ref]$errors)
Assert-UpdateTest ($errors.Count -eq 0) 'PowerShell module parses'
foreach ($statement in $ast.EndBlock.Statements) {
    Assert-UpdateTest ($statement -is [Management.Automation.Language.FunctionDefinitionAst]) 'module has only top-level function definitions'
}
Assert-UpdateTest ((Get-EloUpdateGaps).Count -eq 3) 'explicit production gaps'
Write-Output 'PASS: copied preview, parse, no top-level effects, explicit fail-closed production gaps'
# Compatibility is a warning requiring its own explicit approval, not proof of support.
$f=New-UpdateFixture
$f.Context.Adapters.Evidence={ param($Detected,$Package) @{Official=$true; PublishedHash=$true; Compatibility=$false} }
$p=New-FixturePreview $f
Assert-UpdateTest ($p.Warning -like '*compatibility not confirmed*' -and $p.CompatibilityConfirmation) 'unconfirmed compatibility preview'
$r=Invoke-EloRuntimeUpdate -Context $f.Context -Confirmation $p.Confirmation
Assert-UpdateTest ($r.Error -eq 'compatibility_confirmation_required' -and -not $f.State.Backup) 'compatibility acknowledgement required'
$p=New-FixturePreview $f
Assert-UpdateTest ((Invoke-FixtureUpdate $f $p).Status -eq 'SimulatedSuccess') 'explicit compatibility warning approval'
Assert-UpdateTest (@(Get-EloVerifiedTemurinReleases).Count -eq 0) 'no invented verified releases'
Write-Output 'PASS: compatibility warning approval and empty verified-release allowlist'
function Assert-UpdateThrows([scriptblock]$Action,[string]$Code) {
    $message=''; try { $null=& $Action } catch { $message=$_.Exception.Message }
    Assert-UpdateTest ($message -like "*$Code*") "expected $Code, got $message"
}
$hash='a'*64
Assert-UpdateTest ((ConvertFrom-EloPublishedChecksum ($hash+'  runtime.zip')) -ceq $hash) 'documented checksum first token'
foreach ($text in @('bad',($hash+"`n"+$hash),('x'+$hash),('a'*63))) {
    Assert-UpdateThrows { ConvertFrom-EloPublishedChecksum $text } 'invalid_published_checksum'
}
$hosts=@('fixture.invalid') # TEST POLICY ONLY, not a production allowlist
Assert-UpdateTest ((Assert-EloHttpsHost 'https://fixture.invalid/runtime' $hosts).Host -eq 'fixture.invalid') 'exact HTTPS host accepted'
foreach ($address in @('http://fixture.invalid/a','https://fixture.invalid.attacker.invalid/a','https://user@fixture.invalid/a','https://fixture.invalid:444/a','https://fixture.invalid/a#fragment','https://127.0.0.1/a')) {
    Assert-UpdateThrows { Assert-EloHttpsHost $address $hosts } 'unverified_https_host'
}
# Real download rejects unknown release before opening a connection OR output.
Assert-UpdateThrows { Invoke-EloPinnedDownload @{Vendor='Eclipse Adoptium'} 'Z:\NEVER-CREATE.zip' } 'no_independently_verified'
Write-Output 'PASS: published-checksum grammar, HTTPS allowlist, network fail-closed before IO'
function New-ZipPolicyEntry([string]$Name,[long]$Length=1,[long]$Attributes=0) {
    @{FullName=$Name;Length=$Length;ExternalAttributes=$Attributes}
}
$entries=@((New-ZipPolicyEntry 'verified-root/bin/java.exe'))
Assert-UpdateTest ((Assert-EloArchiveEntries $entries 'verified-root') -eq 1) 'safe pinned ZIP layout'
foreach ($bad in @('verified-root/../outside','verified-root/C:/outside','verified-root/CON.txt','verified-root/name.','verified-root//empty','verified-root/dir\outside','other-root/file','/absolute/file')) {
    $badEntries=@($entries[0],(New-ZipPolicyEntry $bad))
    Assert-UpdateThrows { Assert-EloArchiveEntries $badEntries 'verified-root' } 'unsafe_archive_entry'
}
Assert-UpdateThrows { Assert-EloArchiveEntries @($entries[0],(New-ZipPolicyEntry 'verified-root/BIN/JAVA.EXE')) 'verified-root' } 'duplicate_archive_entry'
Assert-UpdateThrows { Assert-EloArchiveEntries @($entries[0],(New-ZipPolicyEntry 'verified-root/link' 1 (40960L -shl 16))) 'verified-root' } 'archive_link_or_device'
Assert-UpdateThrows { Assert-EloArchiveEntries $entries 'verified-root' 0 } 'archive_size_limit'
Assert-UpdateThrows { Assert-EloArchiveEntries $entries 'verified-root' 100 0 } 'unsafe_archive_entry'
Assert-UpdateThrows { Assert-EloArchiveEntries @((New-ZipPolicyEntry 'verified-root/readme')) 'verified-root' } 'archive_java_missing'
Assert-UpdateThrows { Assert-EloArchiveEntries @($entries[0],(New-ZipPolicyEntry 'verified-root/bin')) 'verified-root' } 'archive_file_directory_collision'
Write-Output 'PASS: ZIP traversal, alternate streams, reserved names, duplicates, links, collisions and size/count limits'
# Exercise the actual ZIP verifier with in-memory archives, never filesystem fixtures.
Initialize-EloZip
$payload=[Text.Encoding]::UTF8.GetBytes('disposable JVM fixture, not executable')
$payloadStream=New-Object IO.MemoryStream(,$payload)
try { $payloadHash=Get-EloStreamHash $payloadStream } finally { $payloadStream.Dispose() }
$manifest=@{Json='{"fixture":"memory only","acl":"mock"}';Entries=@(@{Name='bin/java.exe';Directory=$false;Length=$payload.Length;Hash=$payloadHash})}
foreach ($case in @('valid','corrupt-content','corrupt-manifest','missing','extra','duplicate')) {
    $memory=New-Object IO.MemoryStream; $zip=$null
    try {
        $zip=New-Object IO.Compression.ZipArchive($memory,[IO.Compression.ZipArchiveMode]::Create,$true)
        $entry=$zip.CreateEntry('manifest.json'); $stream=$entry.Open()
        try {
            $value=$manifest.Json; if ($case -eq 'corrupt-manifest') { $value='wrong' }
            $bytes=[Text.Encoding]::UTF8.GetBytes($value); $stream.Write($bytes,0,$bytes.Length)
        } finally { $stream.Dispose() }
        if ($case -ne 'missing') {
            $entry=$zip.CreateEntry('tree/bin/java.exe'); $stream=$entry.Open()
            try {
                $bytes=$payload; if ($case -eq 'corrupt-content') { $bytes=[Text.Encoding]::UTF8.GetBytes('CORRUPTED') }
                $stream.Write($bytes,0,$bytes.Length)
            } finally { $stream.Dispose() }
        }
        if ($case -in @('extra','duplicate')) {
            $name='unexpected'; if ($case -eq 'duplicate') { $name='tree/bin/java.exe' }
            $null=$zip.CreateEntry($name)
        }
        $zip.Dispose(); $zip=$null; $memory.Position=0
        $zip=New-Object IO.Compression.ZipArchive($memory,[IO.Compression.ZipArchiveMode]::Read,$true)
        Assert-UpdateTest ((Test-EloBackupArchive $zip $manifest) -eq ($case -eq 'valid')) "real memory ZIP verification: $case"
    } finally { if ($zip) { $zip.Dispose() }; $memory.Dispose() }
}
# Creating adapters has no filesystem/network/process effects, even for nonexistent paths.
$windows=New-EloWindowsUpdateAdapters -ApprovedRoot 'Z:\NOT-REAL' -Runtime 'Z:\NOT-REAL\runtime'
Assert-UpdateTest ($windows.Count -eq 16) 'concrete Windows adapter surface'
$context=New-EloUpdateContext -Adapters $windows
$result=Invoke-EloRuntimeUpdate -Context $context -Confirmation 'not-approved'
Assert-UpdateTest ($result.Status -eq 'Rejected' -and $result.Error -like 'production_update_disabled*') 'production engine blocks before Windows adapters'
Write-Output 'PASS: actual memory ZIP verification (valid/corrupt/missing/extra/duplicate), inert Windows factory, production gate'
# Official metadata supplied and independently fetched by parent: no network here.
$evidence=Get-EloTemurinMetadataEvidence
Assert-UpdateTest ($evidence.Source -ceq 'https://api.adoptium.net/v3/assets/version/17.0.21.1%2B2?architecture=x64&image_type=jdk&os=windows&vendor=eclipse') 'exact official metadata source'
Assert-UpdateTest ($evidence.ApiVendor -ceq 'eclipse' -and $evidence.ReleaseName -ceq 'jdk-17.0.21.1+2' -and
    $evidence.OS -ceq 'windows' -and $evidence.Architecture -ceq 'x64' -and $evidence.JvmImplementation -ceq 'hotspot' -and $evidence.ImageType -ceq 'jdk') 'verified API identity only'
Assert-UpdateTest ($evidence.Uri -ceq 'https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.21.1%2B2/OpenJDK17U-jdk_x64_windows_hotspot_17.0.21.1_2.zip') 'exact package URL, not a constructed latest URL'
Assert-UpdateTest ($evidence.Sha256 -ceq 'eafba0944f777abdc74d5aad16049c9b5a1275b6ce99e2939ba9f7f3e6f08c87' -and
    $evidence.Size -eq 191150540 -and $evidence.ChecksumUri -ceq ($evidence.Uri+'.sha256.txt')) 'verified API checksum, size and checksum link'
Assert-UpdateTest ($evidence.Scope -ceq 'OfficialApiMetadataOnly' -and -not $evidence.ContainsKey('Vendor') -and
    -not $evidence.ContainsKey('Format') -and -not $evidence.ContainsKey('ArchiveRoot') -and
    -not $evidence.ContainsKey('AllowedHosts') -and -not $evidence.ContainsKey('FinalUri')) 'metadata never invents runtime implementor, format, archive layout or redirect policy'
Assert-UpdateTest (@(Get-EloVerifiedTemurinReleases).Count -eq 0) 'metadata does not promote a release'
Assert-UpdateThrows { Get-EloPinnedTemurinRelease $evidence } 'no_independently_verified'
Assert-UpdateThrows { Invoke-EloPinnedDownload $evidence 'Z:\NEVER-CREATE.zip' } 'no_independently_verified'
# Even correct package identity/hash is insufficient for executable approval.
$candidate=@{Vendor='Eclipse Adoptium';Version='17.0.21.1+2';Branch='17';Architecture=$evidence.Architecture;Uri=$evidence.Uri;Sha256=$evidence.Sha256}
Assert-UpdateThrows { Get-EloPinnedTemurinRelease $candidate } 'no_independently_verified'
$evidence.AllowedHosts=@('github.com'); $evidence.Format='zip'; $evidence.ArchiveRoot='UNPROVEN'; $evidence.Sha256='0'*64
$fresh=Get-EloTemurinMetadataEvidence
Assert-UpdateTest ($fresh.Sha256 -ceq $candidate.Sha256 -and -not $fresh.ContainsKey('AllowedHosts')) 'returned evidence is a fresh copy, not mutable approval state'
Assert-UpdateThrows { Get-EloPinnedTemurinRelease $evidence } 'no_independently_verified'
Assert-UpdateTest (((Get-EloUpdateGaps) -join ' ') -like '*redirect*' -and ((Get-EloUpdateGaps) -join ' ') -notlike '*No exact Temurin release/checksum*') 'gap report recognizes metadata proof without implying binary proof'
Write-Output 'PASS: exact parent-verified API metadata is informational only; no download or production approval'
# Embedded console class is returned in memory only; no runtime is launched here.
$class=Get-EloJavaSelfTestClass
Assert-UpdateTest ($class -is [byte[]] -and $class.Length -gt 100) 'embedded Java class bytes'
Assert-UpdateTest ([BitConverter]::ToString($class,0,4) -ceq 'CA-FE-BA-BE') 'Java class magic'
$first=$class[0]; $class[0]=0
Assert-UpdateTest ((Get-EloJavaSelfTestClass)[0] -eq $first) 'fresh class bytes on each call'
Assert-UpdateTest (Test-EloJavaSelfTestResult 0 "ELO_JAVA_SELF_TEST_OK`n" '') 'exact success marker'
foreach ($sample in @(@(1,"ELO_JAVA_SELF_TEST_OK`n",''),@(0,'',''),@(0,"ELO_JAVA_SELF_TEST_OK`nextra",''),@(0,"ELO_JAVA_SELF_TEST_OK`n",'error'))) {
    Assert-UpdateTest (-not (Test-EloJavaSelfTestResult $sample[0] $sample[1] $sample[2])) 'reject failed or ambiguous self-test output'
}
Write-Output 'PASS: embedded Java class and synthetic result validation; no Java process launched'
# Trusted adapter simulation only: no executable, filesystem or JVM is invoked.
function New-SelfTestAdapter($Mode) {
    $state=@{Time=0;Calls=0;Stopped=$false;Request=$null}
    $adapter=@{
        Clock={ $state.Time }.GetNewClosure()
        Start={ param($request) $state.Request=$request; return 'fixture-handle' }.GetNewClosure()
        Poll={ param($handle) $state.Calls++; $state.Time+=100
            switch ($Mode) {
                success { @{Done=$true;ExitCode=0;Stdout="ELO_JAVA_SELF_TEST_OK`n";Stderr=''} }
                bad { @{Done=$true;ExitCode=1;Stdout='';Stderr='failed'} }
                flood { @{Done=$false;Stdout=('x'*1025);Stderr=''} }
                timeout { @{Done=$false;Stdout='';Stderr=''} }
            }
        }.GetNewClosure()
        Stop={ param($handle) $state.Stopped=$true }.GetNewClosure()
    }
    return @{Adapter=$adapter;State=$state}
}
foreach ($mode in @('success','bad','flood','timeout')) {
    $fixture=New-SelfTestAdapter $mode
    $result=Invoke-EloJavaSelfTest -JavaPath 'C:\trusted JVM\bin\java.exe' -SessionRoot 'C:\fixture root' -Adapter $fixture.Adapter -TimeoutMilliseconds 300 -MaximumOutputCharacters 1024
    Assert-UpdateTest ($result.Success -eq ($mode -eq 'success')) "self-test $mode result"
    Assert-UpdateTest ($fixture.State.Stopped) "self-test $mode closes handle"
    Assert-UpdateTest ($fixture.State.Request.JavaPath -ceq 'C:\trusted JVM\bin\java.exe' -and $fixture.State.Request.ClassBytes -is [byte[]]) 'explicit executable and embedded bytes forwarded'
    Assert-UpdateTest ($fixture.State.Request.SessionPath -match '^C:\\fixture root\\[0-9a-f]{32}$') 'unique isolated session path'
}
$a=New-SelfTestAdapter success; $b=New-SelfTestAdapter success
$first=Invoke-EloJavaSelfTest -JavaPath 'C:\trusted JVM\bin\java.exe' -SessionRoot 'C:\fixture root' -Adapter $a.Adapter
$second=Invoke-EloJavaSelfTest -JavaPath 'C:\trusted JVM\bin\java.exe' -SessionRoot 'C:\fixture root' -Adapter $b.Adapter
Assert-UpdateTest ($first.SessionPath -cne $second.SessionPath) 'distinct session identifiers'
Assert-UpdateThrows { Invoke-EloJavaSelfTest -JavaPath 'java.exe' -SessionRoot 'C:\fixture root' -Adapter (New-SelfTestAdapter success).Adapter } 'absolute_java_path_required'
Assert-UpdateThrows { Invoke-EloJavaSelfTest -JavaPath 'C:\trusted\java.exe' -SessionRoot 'C:\fixture root' -Adapter (New-SelfTestAdapter success).Adapter -TimeoutMilliseconds 0 } 'invalid_self_test_limits'
$slow=New-SelfTestAdapter success
$slowResult=Invoke-EloJavaSelfTest -JavaPath 'C:\trusted\java.exe' -SessionRoot 'C:\fixture root' -Adapter $slow.Adapter -TimeoutMilliseconds 100
Assert-UpdateTest (-not $slowResult.Success -and $slowResult.Reason -eq 'timeout' -and $slow.State.Stopped) 'late successful result rejected'
Write-Output 'PASS: mocked bounded self-test success, failed exit, output limit, timeout and cleanup'
# Disposable filesystem integration only. Never use a discovered or installed JVM.
# Retain every artifact for parent-owned cleanup, including on failure.
$fixtureBase=Join-Path $PSScriptRoot 'update-live-fixtures'
$probe=$fixtureBase
while ($probe) {
    if (Test-Path -LiteralPath $probe) {
        $item=Get-Item -LiteralPath $probe -Force
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'fixture_reparse_boundary' }
    }
    $next=[IO.Path]::GetDirectoryName($probe)
    if ($next -eq $probe) { break }; $probe=$next
}
$fixtureRoot=Join-Path $fixtureBase ([guid]::NewGuid().ToString('N'))
if (Test-Path -LiteralPath $fixtureRoot) { throw 'fixture_collision' }
Write-Output "FIXTURE FOR PARENT CLEANUP: $fixtureRoot"
$null=[IO.Directory]::CreateDirectory($fixtureRoot)
$paths=@{Runtime=(Join-Path $fixtureRoot 'runtime with spaces');Old=(Join-Path $fixtureRoot 'old');Stage=(Join-Path $fixtureRoot 'stage');Backup=(Join-Path $fixtureRoot 'backup.zip');Download=(Join-Path $fixtureRoot 'download.zip')}
$null=[IO.Directory]::CreateDirectory((Join-Path $paths.Runtime 'bin'))
[IO.File]::WriteAllText((Join-Path $paths.Runtime 'bin\java.exe'),'synthetic original; not executable')
$manifest=Get-EloRuntimeManifest $fixtureRoot $paths.Runtime
Write-EloVerifiedBackup $fixtureRoot $paths $manifest
$input=[IO.File]::OpenRead($paths.Backup); $zip=$null
try {
    $zip=New-Object IO.Compression.ZipArchive($input,[IO.Compression.ZipArchiveMode]::Read,$true)
    Assert-UpdateTest (Test-EloBackupArchive $zip $manifest) 'filesystem ZIP contains original manifest and bytes'
} finally { if ($zip) { $zip.Dispose() }; $input.Dispose() }
$backupHash=(Get-FileHash -LiteralPath $paths.Backup -Algorithm SHA256).Hash
$collision=$false
try { Write-EloVerifiedBackup $fixtureRoot $paths $manifest } catch { $collision=$true }
Assert-UpdateTest ($collision -and (Get-FileHash -LiteralPath $paths.Backup -Algorithm SHA256).Hash -ceq $backupHash) 'backup collision preserves existing ZIP'
Assert-UpdateTest ((Get-EloRuntimeManifest $fixtureRoot $paths.Runtime).Fingerprint -ceq $manifest.Fingerprint) 'backup collision leaves original unchanged'
# Inspect/restore require a recognized runtime identity; no real JVM is used.
[IO.File]::WriteAllText((Join-Path $paths.Runtime 'bin\java.exe'),'changed synthetic bytes')
$changed=Get-EloRuntimeManifest $fixtureRoot $paths.Runtime
Assert-UpdateTest ($changed.Fingerprint -cne $manifest.Fingerprint) 'manifest detects changed runtime'
$input=[IO.File]::OpenRead($paths.Backup); $zip=$null
try {
    $zip=New-Object IO.Compression.ZipArchive($input,[IO.Compression.ZipArchiveMode]::Read,$true)
    Assert-UpdateTest (Test-EloBackupArchive $zip $manifest) 'ZIP remains original after runtime changes'
    Assert-UpdateTest (-not (Test-EloBackupArchive $zip $changed)) 'ZIP rejects changed runtime manifest'
} finally { if ($zip) { $zip.Dispose() }; $input.Dispose() }
Write-Output 'PASS: synthetic filesystem ZIP creation, collision, verification and changed-runtime rejection; artifacts retained'
# Minimal inert PE header and release metadata satisfy identity parsing only; the
# synthetic executable is never launched. Exercise actual preserve/restore closures.
$restoreRoot=Join-Path $fixtureRoot 'restore-cases'
$null=[IO.Directory]::CreateDirectory($restoreRoot)
foreach ($case in @('restore','changed-old')) {
    $caseRoot=Join-Path $restoreRoot $case
    $runtime=Join-Path $caseRoot 'runtime'; $old=Join-Path $caseRoot 'old'; $stage=Join-Path $caseRoot 'stage'
    $null=[IO.Directory]::CreateDirectory((Join-Path $runtime 'bin'))
    $pe=New-Object byte[] 128; $pe[0]=0x4d; $pe[1]=0x5a; $pe[60]=64; $pe[64]=0x50; $pe[65]=0x45; $pe[68]=0x64; $pe[69]=0x86
    [IO.File]::WriteAllBytes((Join-Path $runtime 'bin\java.exe'),$pe)
    [IO.File]::WriteAllText((Join-Path $runtime 'release'),"IMPLEMENTOR=`"Eclipse Adoptium`"`r`nJAVA_VERSION=`"17.0.1`"`r`nJAVA_RUNTIME_VERSION=`"17.0.1+1`"`r`nOS_ARCH=`"amd64`"`r`nOS_NAME=`"Windows`"`r`n")
    $adapter=New-EloWindowsUpdateAdapters -ApprovedRoot $fixtureRoot -Runtime $runtime
    $identity=& $adapter.Inspect $runtime
    $p=@{Runtime=$runtime;Old=$old;Stage=$stage}
    & $adapter.Preserve $p
    Assert-UpdateTest ((Test-Path -LiteralPath $old) -and -not (Test-Path -LiteralPath $runtime)) 'preserve renames original'
    $null=[IO.Directory]::CreateDirectory($runtime)
    [IO.File]::WriteAllText((Join-Path $runtime 'failed.txt'),'synthetic failed replacement')
    if ($case -eq 'changed-old') {
        [IO.File]::WriteAllText((Join-Path $old 'extra.txt'),'unexpected modification')
        Assert-UpdateThrows { & $adapter.Restore $p } 'old_runtime_changed_manual_zip_restore_required'
        Assert-UpdateTest ((Test-Path -LiteralPath (Join-Path $runtime 'failed.txt')) -and (Test-Path -LiteralPath (Join-Path $old 'extra.txt'))) 'failed restore retains both trees'
    } else {
        & $adapter.Restore $p
        Assert-UpdateTest (& $adapter.VerifyRestored $p $identity) 'restored manifest matches original'
        $failed=@(Get-ChildItem -LiteralPath $caseRoot -Directory -Filter 'stage.failed-*')
        Assert-UpdateTest ($failed.Count -eq 1 -and (Test-Path -LiteralPath (Join-Path $failed[0].FullName 'failed.txt')) -and -not (Test-Path -LiteralPath $old)) 'failed replacement retained separately'
    }
}
Write-Output 'PASS: synthetic real rename restore and changed-old refusal; no executable launched'
Write-Output 'ALL UPDATE TESTS PASSED (synthetic filesystem and mocks; no production safety claim)'
