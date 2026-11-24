# Windows PowerShell 5.1; deterministic mocks only. No live ELO or network access.
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/update.ps1"
. "$PSScriptRoot/catalog.ps1"
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
# Opt-in service control: stop right before the replacement, restart exactly once, on success AND on failure.
function Add-ServiceControl($Fixture,[string]$QuiesceFails='') {
    $state=$Fixture.State
    $Fixture.Context.Adapters.Quiesce={ param($Paths) $state.Events.Add('quiesce'); if ($QuiesceFails) { throw 'runtime_still_in_use_after_service_stop' }; @('svc') }.GetNewClosure()
    $Fixture.Context.Adapters.Resume={ param($Paths,$Stopped) $state.Events.Add('resume'); if ($state.Fail -eq 'resume') { throw 'service_restart_failed:svc' } }.GetNewClosure()
}
$f=New-UpdateFixture; Add-ServiceControl $f
$r=Invoke-FixtureUpdate $f (New-FixturePreview $f)
Assert-UpdateTest ($r.Status -eq 'SimulatedSuccess' -and $r.ServicesRestarted -and -not $r.ServiceError) 'services restarted after a successful update'
Assert-UpdateTest (($f.State.Events -join ',') -ceq 'preflight,preflight,backup,verify-backup,download,verify-package,copy,probe,quiesce,preserve,replace,validate,resume') 'services are stopped after the probe, right before the replacement, and resumed last'
$f=New-UpdateFixture; Add-ServiceControl $f; $f.State.Fail='installed'
$r=Invoke-FixtureUpdate $f (New-FixturePreview $f)
Assert-UpdateTest ($r.Status -eq 'RolledBack' -and $r.ServicesRestarted -and (@($f.State.Events | Where-Object { $_ -eq 'resume' }).Count -eq 1) -and $f.State.Events.IndexOf('resume') -gt $f.State.Events.IndexOf('verify-restored')) 'services restart once, after the rollback'
$f=New-UpdateFixture; Add-ServiceControl $f -QuiesceFails 'x'
$r=Invoke-FixtureUpdate $f (New-FixturePreview $f)
Assert-UpdateTest ($r.Status -eq 'Rejected' -and $r.Error -like '*runtime_still_in_use*' -and $f.State.Installed -eq 'old' -and $f.State.Events -notcontains 'preserve' -and $f.State.Events -contains 'resume' -and $r.ServicesRestarted) 'failed service stop aborts before any change and still resumes'
$f=New-UpdateFixture; Add-ServiceControl $f; $f.State.Fail='resume'
$r=Invoke-FixtureUpdate $f (New-FixturePreview $f)
Assert-UpdateTest ($r.Status -eq 'SimulatedSuccess' -and -not $r.ServicesRestarted -and $r.ServiceError -like '*service_restart_failed*') 'a failed service restart is reported, not hidden'
$f=New-UpdateFixture
$r=Invoke-FixtureUpdate $f (New-FixturePreview $f)
Assert-UpdateTest ($r.Status -eq 'SimulatedSuccess' -and -not $r.ServicesRestarted -and $f.State.Events -notcontains 'quiesce') 'no service control unless the adapters provide it'
Write-Output 'PASS: opt-in service stop/restart around the replacement'
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
Write-Output 'PASS: compatibility warning approval'
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
Assert-UpdateTest (-not (Test-Path 'Z:\NEVER-CREATE.zip')) 'nothing created for an unverified release'
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
Assert-UpdateTest ($windows.Count -eq 17) 'concrete Windows adapter surface'
$context=New-EloUpdateContext -Adapters $windows
$result=Invoke-EloRuntimeUpdate -Context $context -Confirmation 'not-approved'
Assert-UpdateTest ($result.Status -eq 'Rejected' -and $result.Error -like 'production_update_disabled*') 'production engine blocks before Windows adapters'
$threw=$false; try { $null=New-EloUpdateContext -Adapters @{} -Production } catch { $threw=($_.Exception.Message -ceq 'production_requires_windows_adapters') }
Assert-UpdateTest $threw 'production context refuses caller-supplied adapters'
$threw=$false; try { $null=New-EloUpdateContext -Adapters $windows -Production -Simulation } catch { $threw=($_.Exception.Message -ceq 'production_requires_windows_adapters') }
Assert-UpdateTest $threw 'production and simulation are mutually exclusive'
$prod=New-EloUpdateContext -Adapters $windows -Production
Assert-UpdateTest ($prod.Production -and -not $prod.Simulation) 'production context only for module Windows adapters'
Write-Output 'PASS: actual memory ZIP verification (valid/corrupt/missing/extra/duplicate), inert Windows factory, production gate'
# Version grammar and ordering across Java 8 / 11 / 17 / 21 / 25 formats.
$cases=@{'1.8.0_472-b08'='8.0.472+8';'21.0.1+12-LTS'='21.0.1+12';'17.0.21.1+2'='17.0.21.1+2';'8u472'='8.0.472+0';'25'='25+0';'11.0.33.1+1'='11.0.33.1+1'}
foreach ($key in $cases.Keys) { Assert-UpdateTest ((ConvertTo-EloJavaVersion $key).Text -ceq $cases[$key]) "version grammar $key" }
foreach ($bad in @('','abc','1.2.3.4.5.6','21.0.1; calc','-1')) { Assert-UpdateThrows { ConvertTo-EloJavaVersion $bad } 'unrecognized_java_version' }
function V($x){ ConvertTo-EloJavaVersion $x }
Assert-UpdateTest ((Compare-EloJavaVersion (V '21.0.1+12-LTS') (V '21.0.13.1+2')) -eq -1 -and (Compare-EloJavaVersion (V '21.0.13.1+2') (V '21.0.13.1+2')) -eq 0 -and
    (Compare-EloJavaVersion (V '17.0.21.1+3') (V '17.0.21.1+2')) -eq 1 -and (Compare-EloJavaVersion (V '1.8.0_472-b08') (V '8.0.514+1')) -eq -1 -and (Compare-EloJavaVersion (V '17.0.9') (V '17.0.10')) -eq -1) 'version ordering is numeric, not lexical'
Assert-UpdateTest ((Test-EloSameJavaRelease '21.0.13.1+2-LTS' '21.0.13.1+2') -and (Test-EloSameJavaRelease '1.8.0_514' '8.0.514+1') -and -not (Test-EloSameJavaRelease '21.0.13.1+2' '21.0.12.1+2')) 'same release comparison tolerates missing build numbers'
# Release resolution with canned vendor API answers: plain GA builds only, newest wins, hash from the detail record.
$zuluList='[{"download_url":"https://cdn.azul.com/zulu/bin/zulu21.54.201-ca-crac-jdk21.0.13.1-win_x64.zip","java_version":[21,0,13,1],"name":"zulu21.54.201-ca-crac-jdk21.0.13.1-win_x64.zip","openjdk_build_number":2,"package_uuid":"aaaaaaaa-0000-4000-8000-000000000001"},{"download_url":"https://cdn.azul.com/zulu/bin/zulu21.50.19-ca-jdk21.0.11-win_x64.zip","java_version":[21,0,11],"name":"zulu21.50.19-ca-jdk21.0.11-win_x64.zip","openjdk_build_number":1,"package_uuid":"aaaaaaaa-0000-4000-8000-000000000002"},{"download_url":"https://cdn.azul.com/zulu/bin/zulu21.54.201-ca-jdk21.0.13.1-win_x64.zip","java_version":[21,0,13,1],"name":"zulu21.54.201-ca-jdk21.0.13.1-win_x64.zip","openjdk_build_number":2,"package_uuid":"aaaaaaaa-0000-4000-8000-000000000003"},{"download_url":"https://cdn.azul.com/zulu/bin/zulu21.54.109-ca-fx-jdk21.0.13.0.3-win_x64.zip","java_version":[21,0,13,0,3],"name":"zulu21.54.109-ca-fx-jdk21.0.13.0.3-win_x64.zip","openjdk_build_number":1,"package_uuid":"aaaaaaaa-0000-4000-8000-000000000004"}]'
$zuluDetail='{"name":"zulu21.54.201-ca-jdk21.0.13.1-win_x64.zip","os":"windows","package_uuid":"aaaaaaaa-0000-4000-8000-000000000003","download_url":"https://cdn.azul.com/zulu/bin/zulu21.54.201-ca-jdk21.0.13.1-win_x64.zip","sha256_hash":"14e7a0395df4f09b508d50aa65a858650d59eb8d2221df57b4742d0830f3a3a0","size":211168000}'
$zuluGetter={ param($Uri,$Hosts) if ($Uri -like '*/packages/aaaaaaaa-0000-4000-8000-000000000003') { $zuluDetail } else { $zuluList } }
$zulu=Resolve-EloLatestRelease -Vendor 'Azul Zulu' -Branch '21' -Architecture 'x64' -ImageType 'jdk' -Getter $zuluGetter
Assert-UpdateTest ($zulu.Version -ceq '21.0.13.1+2' -and $zulu.Sha256 -ceq '14e7a0395df4f09b508d50aa65a858650d59eb8d2221df57b4742d0830f3a3a0' -and $zulu.Uri -ceq 'https://cdn.azul.com/zulu/bin/zulu21.54.201-ca-jdk21.0.13.1-win_x64.zip' -and
    $zulu.Vendor -ceq 'Azul Zulu' -and (@($zulu.AllowedHosts) -join ',') -ceq 'cdn.azul.com') 'newest plain Zulu build chosen (no CRaC/FX, not an older one)'
$temurinAnswer='[{"release_name":"jdk-17.0.21.1+2","binary":{"os":"windows","image_type":"jdk","jvm_impl":"hotspot","package":{"link":"https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.21.1%2B2/OpenJDK17U-jdk_x64_windows_hotspot_17.0.21.1_2.zip","checksum":"eafba0944f777abdc74d5aad16049c9b5a1275b6ce99e2939ba9f7f3e6f08c87","size":191150540}},"version":{"openjdk_version":"17.0.21.1+2"}}]'
$temurin=Resolve-EloLatestRelease -Vendor 'Eclipse Adoptium' -Branch '17' -Architecture 'x64' -ImageType 'jdk' -Getter { param($Uri,$Hosts) $temurinAnswer }
Assert-UpdateTest ($temurin.Version -ceq '17.0.21.1+2' -and $temurin.Size -eq 191150540 -and $temurin.Name -ceq 'OpenJDK17U-jdk_x64_windows_hotspot_17.0.21.1_2.zip') 'Temurin latest record validated'
Assert-UpdateThrows { Resolve-EloLatestRelease -Vendor 'Azul Zulu' -Branch '17' -Architecture 'x64' -ImageType 'jdk' -Getter { param($Uri,$Hosts) '[]' } } 'no_release_found'
Assert-UpdateThrows { Resolve-EloLatestRelease -Vendor 'Oracle' -Branch '17' -Architecture 'x64' -Getter { '[]' } } 'unsupported_vendor'
Assert-UpdateThrows { Resolve-EloLatestRelease -Vendor 'Azul Zulu' -Branch '21; calc' -Architecture 'x64' -Getter { '[]' } } 'invalid_release_request'
# Strict, code-defined policy: tampering with any part of a record is refused.
$good=@{Vendor='Azul Zulu';Branch='21';Architecture='x64';ImageType='jdk';Version='21.0.13.1+2';Uri='https://cdn.azul.com/zulu/bin/zulu21.54.201-ca-jdk21.0.13.1-win_x64.zip';Sha256=('a'*64);Size=211168000}
Assert-UpdateTest ((Get-EloPinnedRelease $good).MaxArchiveBytes -gt 211168000) 'valid release record accepted'
$tamper=@{
    Vendor='Oracle';Branch='99x';Architecture='arm32';ImageType='jmod';Version='not-a-version';Sha256=('a'*63);Size=10
    Uri='http://cdn.azul.com/zulu/bin/zulu21.54.201-ca-jdk21.0.13.1-win_x64.zip'
}
foreach ($key in $tamper.Keys) { $bad=@{}+$good; $bad[$key]=$tamper[$key]; Assert-UpdateThrows { Get-EloPinnedRelease $bad } 'no_independently_verified' }
foreach ($uri in @('https://evil.invalid/zulu/bin/zulu21.54.201-ca-jdk21.0.13.1-win_x64.zip','https://cdn.azul.com.evil.invalid/zulu/bin/zulu21.54.201-ca-jdk21.0.13.1-win_x64.zip','https://cdn.azul.com/zulu/bin/zulu21.54.201-ca-jdk21.0.13.1-win_x64.zip?x=1','https://cdn.azul.com/zulu/bin/../evil.zip','https://cdn.azul.com/zulu/bin/zulu21.54.201-ca-jdk21.0.13.1-win_x64.exe','https://cdn.azul.com/zulu/bin/zulu21.54.201-ca-jre21.0.13.1-win_x64.zip')) {
    $bad=@{}+$good; $bad.Uri=$uri; Assert-UpdateThrows { Get-EloPinnedRelease $bad } 'no_independently_verified'
}
$bad=@{}+$good; $bad.Branch='17'; Assert-UpdateThrows { Get-EloPinnedRelease $bad } 'no_independently_verified'
Assert-UpdateThrows { Invoke-EloPinnedDownload $tamper 'Z:\NEVER-CREATE.zip' } 'no_independently_verified'
Assert-UpdateTest (((Get-EloUpdateGaps) -join ' ') -like '*Zulu*' -and ((Get-EloUpdateGaps) -join ' ') -like '*SACL*') 'gap report names supported vendors and the SACL limit'
Write-Output 'PASS: version grammar, latest-release resolution (Zulu, Temurin), strict vendor policy and tamper rejection'# Embedded console class is returned in memory only; no runtime is launched here.
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
# Automatic restore from the backup ZIP (real filesystem, synthetic runtime tree, nothing executed).
$restoreBase=Join-Path $fixtureRoot 'backup-restore'
$null=[IO.Directory]::CreateDirectory($restoreBase)
function New-SyntheticRuntime([string]$Path) {
    $null=[IO.Directory]::CreateDirectory((Join-Path $Path 'bin')); $null=[IO.Directory]::CreateDirectory((Join-Path $Path 'lib\sub')); $null=[IO.Directory]::CreateDirectory((Join-Path $Path 'empty dir'))
    [IO.File]::WriteAllText((Join-Path $Path 'bin\java.exe'),'synthetic executable bytes'); [IO.File]::WriteAllText((Join-Path $Path 'lib\a b.txt'),'alpha')
    [IO.File]::WriteAllBytes((Join-Path $Path 'lib\sub\b.bin'),[byte[]](0..255)); [IO.File]::WriteAllText((Join-Path $Path 'release'),'IMPLEMENTOR="Eclipse Adoptium"')
}
function Get-ContentMap($Root,$Path) { $m=Get-EloRuntimeManifest $Root $Path; $h=@{}; foreach ($e in $m.Entries) { $h[[string]$e.Name]=('{0}|{1}|{2}' -f $e.Directory,$e.Length,$e.Hash) }; $h }
$rt=Join-Path $restoreBase 'java'; New-SyntheticRuntime $rt
$bpaths=@{Runtime=$rt;Backup=(Join-Path $restoreBase 'java.backup.zip')}
$bman=Get-EloRuntimeManifest $restoreBase $rt; Write-EloVerifiedBackup $restoreBase $bpaths $bman
$originalMap=Get-ContentMap $restoreBase $rt
# The "updated" runtime differs completely.
[IO.File]::WriteAllText((Join-Path $rt 'lib\a b.txt'),'tampered'); Remove-Item -LiteralPath (Join-Path $rt 'lib\sub') -Recurse -Force; [IO.File]::WriteAllText((Join-Path $rt 'new.txt'),'new release file')
$order=New-Object 'System.Collections.Generic.List[string]'
$result=Invoke-EloBackupRestore -Root $restoreBase -Runtime $rt -Backup $bpaths.Backup -Stamp '20260101000000' -Quiesce { $order.Add('stop') }.GetNewClosure() -Resume { $order.Add('start') }.GetNewClosure()
$restoredMap=Get-ContentMap $restoreBase $rt
Assert-UpdateTest ($result.Restored -and $restoredMap.Count -eq $originalMap.Count -and -not @($originalMap.Keys | Where-Object { $restoredMap[$_] -cne $originalMap[$_] }).Count) 'restored tree equals the backed-up content (files, empty directory, binary bytes)'
Assert-UpdateTest ((Test-Path -LiteralPath ($rt+'.replaced-20260101000000\new.txt')) -and -not (Test-Path -LiteralPath ($rt+'.restore-20260101000000'))) 'the replaced runtime is kept, the staging directory is consumed'
Assert-UpdateTest (($order -join ',') -ceq 'stop,start') 'services are stopped before the swap and started afterwards'
if ($result.AclExact) { Assert-UpdateTest ((Get-EloRuntimeManifest $restoreBase $rt).Fingerprint -ceq $bman.Fingerprint) 'restored runtime has the exact original fingerprint including ACLs' }
# A tampered backup entry is refused and the current runtime is not touched.
$tampered=Join-Path $restoreBase 'tampered.zip'; Copy-Item -LiteralPath $bpaths.Backup -Destination $tampered
$zipStream=[IO.File]::Open($tampered,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite); $zip=New-Object IO.Compression.ZipArchive($zipStream,[IO.Compression.ZipArchiveMode]::Update)
try { $entry=$zip.GetEntry('tree/lib/a b.txt'); $w=New-Object IO.StreamWriter($entry.Open()); $w.Write('ALPHA'); $w.Dispose() } finally { $zip.Dispose(); $zipStream.Dispose() }
$before=(Get-EloRuntimeManifest $restoreBase $rt).Fingerprint
Assert-UpdateThrows { Invoke-EloBackupRestore -Root $restoreBase -Runtime $rt -Backup $tampered -Stamp '20260101000001' } 'backup_entry_mismatch'
Assert-UpdateTest ((Get-EloRuntimeManifest $restoreBase $rt).Fingerprint -ceq $before -and -not (Test-Path -LiteralPath ($rt+'.replaced-20260101000001'))) 'a refused restore leaves the runtime unchanged'
Assert-UpdateThrows { Invoke-EloBackupRestore -Root $restoreBase -Runtime $rt -Backup (Join-Path $fixtureRoot 'outside.zip') -Stamp '20260101000002' } 'outside_approved_boundary'
Assert-UpdateThrows { Invoke-EloBackupRestore -Root $restoreBase -Runtime $rt -Backup $bpaths.Backup -Stamp '20260101000000' } 'recovery_or_staging_path_exists'
Write-Output 'PASS: automatic restore from the backup ZIP (content, retention, service hooks, tamper and boundary refusal)'
# Runtimes directly below a drive root are allowed: the approved root may be the drive root itself.
$driveRoot=[IO.Path]::GetPathRoot($fixtureRoot)
Assert-UpdateTest ((Assert-EloWindowsBoundary $driveRoot ($driveRoot+'elo-drive-root-probe')) -ieq ($driveRoot+'elo-drive-root-probe')) 'boundary accepts a runtime directly below the drive root'
Assert-UpdateThrows { Assert-EloWindowsBoundary $driveRoot 'D:\other' } 'outside_approved_boundary'
Assert-UpdateThrows { Assert-EloWindowsBoundary ($driveRoot+'x') ($driveRoot+'y') } 'outside_approved_boundary'
Assert-EloUpdatePaths @{Runtime=($driveRoot+'java');Old=($driveRoot+'java.old-1');Stage=($driveRoot+'java.stage-1');Backup=($driveRoot+'java.backup-1.zip');Download=($driveRoot+'java.download-1.zip')}
Write-Output 'PASS: drive-root runtimes'
Write-Output 'ALL UPDATE TESTS PASSED (synthetic filesystem and mocks; no production safety claim)'
