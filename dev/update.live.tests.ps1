# OPT-IN live test (Windows PowerShell 5.1, administrator, network, ~1.5 GB of transfer/disk).
# Run only on a disposable test machine: ELO_LIVE_UPDATE_TEST=1 powershell -File dev\update.live.tests.ps1
# It downloads OLD runtimes (Eclipse Temurin 17.0.2, Azul Zulu 17.0.19, Azul Zulu 8.0.492) into a scratch
# directory under %TEMP% and drives the server API with the REAL adapters and the REAL vendor APIs:
# the newest release of each branch is resolved and installed (backup ZIP, download, self-test, swap),
# the old runtime is restored from the backup ZIP, and a forced validation failure is rolled back.
# It never touches an installed runtime or a service. The scratch directory is deleted at the end.
$ErrorActionPreference = 'Stop'
if ($env:ELO_LIVE_UPDATE_TEST -ne '1') { Write-Output 'SKIP: set ELO_LIVE_UPDATE_TEST=1 to run the live update test'; return }
. "$PSScriptRoot\vulndb.ps1"; . "$PSScriptRoot\update.ps1"; . "$PSScriptRoot\catalog.ps1"; . "$PSScriptRoot\scan.ps1"; . "$PSScriptRoot\server.ps1"; . "$PSScriptRoot\report.ps1"
function Assert-Live($Condition, $Message) { if (-not $Condition) { throw "ASSERT: $Message" }; Write-Host "PASS: $Message" }
$work = Join-Path ([IO.Path]::GetTempPath()) ('elo-live-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory $work
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
Add-Type -AssemblyName System.IO.Compression.FileSystem
function Get-OldRuntimeZip($Name, $Uri, $Sha256) {
    $zip = Join-Path $work ($Name + '.zip')
    (New-Object Net.WebClient).DownloadFile($Uri, $zip)
    Assert-Live ((Get-FileHash $zip -Algorithm SHA256).Hash -ieq $Sha256) "old runtime $Name matches the vendor hash"
    return $zip
}
function New-LiveRoot($Zip, $Name) {
    $root = Join-Path $work $Name; $null = New-Item -ItemType Directory $root
    [IO.Compression.ZipFile]::ExtractToDirectory($Zip, $root)
    $top = @(Get-ChildItem $root -Directory)
    if ($top.Count -ne 1) { throw 'unexpected archive layout' }
    Rename-Item $top[0].FullName 'java'
    return $root
}
function New-LiveSession($Root) {
    $s = New-EloServerSession -Port 54999 -UiHtml 'live' -ScanSource 'live'
    $java = Join-Path $Root 'java\bin\java.exe'
    $identity = Get-EloRuntimeIdentity (Join-Path $Root 'java')
    $s.State = 'completed'
    $s.Targets = @{ live1 = [pscustomobject]@{ Location = $java; Status = 'Inconclusive'; Vendor = $identity.Vendor; FullVersion = $identity.Version } }
    $s.ReportJvms = @(@{ Version = $identity.Version; Verified = $true; ExecutionVerified = $true; Vendor = 'Unknown'; Classification = 'Unknown' })
    $s.ReportIndexes = @{ live1 = 1 }
    return $s
}
function Call($S, $Route, $Body) {
    $h = @{ Host = '127.0.0.1:54999'; 'X-Session-Token' = $S.Token; Origin = $S.Origin; 'Content-Type' = 'application/json' }
    Invoke-EloApi $S ([pscustomobject]@{ Method = 'POST'; Target = $Route; Headers = $h; Body = $Body; Remote = '127.0.0.1' })
}
function Get-JavaVersion($Root) {
    $previous = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try { return (& (Join-Path $Root 'java\bin\java.exe') -version 2>&1 | Out-String) } finally { $ErrorActionPreference = $previous }
}
function Invoke-LiveUpdate($Session) {
    $preview = Call $Session '/api/preview' '{"actionId":"update-runtime","resultId":"live1"}'
    $null = Call $Session '/api/action' ('{"actionId":"update-runtime","resultId":"live1","previewId":"' + $preview.previewId + '"}')
    return $preview
}
function Test-Branch($Label, $Zip, $ExpectedVendor, $ExpectedBranch, $OldMarker, $ImageType) {
    $root = New-LiveRoot $Zip $Label
    $before = Get-EloRuntimeIdentity (Join-Path $root 'java')
    Assert-Live ($before.Vendor -ceq $ExpectedVendor -and $before.Branch -ceq $ExpectedBranch -and $before.ImageType -ceq $ImageType) "$Label identity read from the release file ($($before.Version))"
    $latest = Resolve-EloLatestRelease -Vendor $before.Vendor -Branch $before.Branch -Architecture $before.Architecture -ImageType $before.ImageType
    Assert-Live ((Compare-EloJavaVersion (ConvertTo-EloJavaVersion $before.Version) (ConvertTo-EloJavaVersion $latest.Version)) -lt 0) "$Label : a newer release of the same branch exists ($($latest.Version))"
    $s = New-LiveSession $root
    $preview = Call $s '/api/preview' '{"actionId":"update-runtime","resultId":"live1"}'
    Assert-Live ($preview.summary.en.Contains($latest.Version) -and -not (Test-Path (Join-Path $root 'java.old*'))) "$Label : preview names the newest release and changes nothing"
    $null = Call $s '/api/action' ('{"actionId":"update-runtime","resultId":"live1","previewId":"' + $preview.previewId + '"}')
    $after = Get-EloRuntimeIdentity (Join-Path $root 'java')
    Assert-Live ((Test-EloSameJavaRelease $after.Version $latest.Version) -and $after.Vendor -ceq $before.Vendor -and $after.ImageType -ceq $before.ImageType) "$Label : installed runtime is now $($after.Version)"
    Assert-Live (-not (Get-JavaVersion $root).Contains($OldMarker)) "$Label : java -version no longer reports the old version"
    Assert-Live ((@(Get-ChildItem $root -Filter 'java.backup-*.zip').Count -eq 1) -and (@(Get-ChildItem $root -Directory -Filter 'java.old-*').Count -eq 1)) "$Label : backup ZIP and old runtime are kept"
    # Automatic restore from the backup ZIP through the API.
    $rp = Call $s '/api/preview' '{"actionId":"restore-backup","resultId":"live1"}'
    $null = Call $s '/api/action' ('{"actionId":"restore-backup","resultId":"live1","previewId":"' + $rp.previewId + '"}')
    $restored = Get-EloRuntimeIdentity (Join-Path $root 'java')
    Assert-Live ($restored.Version -ceq $before.Version -and (Get-JavaVersion $root).Contains($OldMarker)) "$Label : automatic restore brought back $($restored.Version)"
    Assert-Live (@(Get-ChildItem $root -Directory -Filter 'java.replaced-*').Count -eq 1) "$Label : the updated runtime is kept next to the restored one"
    $s.Adapters.Resources = { @{ ServerName = 'LIVE'; WindowsVersion = '10.0'; WindowsBuild = '20348'; TotalRamBytes = 8GB; Disks = @(@{ Name = 'C:'; TotalBytes = 100GB; FreeBytes = 40GB }) } }
    $html = Get-EloSessionReportHtml $s 'en'
    Assert-Live ($html.Contains($latest.Version) -and $html.Contains('java.backup-')) "$Label : technical report lists the update and backup"
    return $root
}
try {
    $temurinZip = Get-OldRuntimeZip 'temurin17' 'https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.2%2B8/OpenJDK17U-jdk_x64_windows_hotspot_17.0.2_8.zip' 'd083479ca927dce2f586f779373d895e8bf668c632505740279390384edf03fa'
    $root = Test-Branch 'temurin17' $temurinZip 'Eclipse Adoptium' '17' 'version "17.0.2"' 'jdk'

    # Forced validation failure: real rollback (Temurin 17 scratch runtime).
    $root = New-LiveRoot $temurinZip 'rollback'; $s = New-LiveSession $root
    $realFactory = $s.Adapters.NewUpdateContext
    $s.Adapters.NewUpdateContext = { param($R, $T, $Stop) $c = & $realFactory $R $T $Stop; $c.Adapters.ValidateInstalled = { param($a, $b) $false }; $c }.GetNewClosure()
    $preview = Call $s '/api/preview' '{"actionId":"update-runtime","resultId":"live1"}'
    $code = ''
    try { $null = Call $s '/api/action' ('{"actionId":"update-runtime","resultId":"live1","previewId":"' + $preview.previewId + '"}') } catch { $code = $_.Exception.Message }
    Assert-Live ($code -ceq 'update_failed_rolled_back') 'forced validation failure reports a rollback'
    Assert-Live ((Get-JavaVersion $root).Contains('version "17.0.2"') -and @(Get-ChildItem $root -Directory -Filter 'java.stage-*.failed-*').Count -eq 1) 'original runtime restored; failed runtime retained'

    # Azul Zulu: a JDK of branch 17 and the old Java 8 layout.
    $d17 = (New-Object Net.WebClient).DownloadString('https://api.azul.com/metadata/v1/zulu/packages/?java_version=17&os=windows&arch=x64&archive_type=zip&java_package_type=jdk&latest=true&release_status=ga&availability_types=CA&page_size=100') | ConvertFrom-Json
    $old17 = @($d17 | ForEach-Object { $_ }) | Where-Object { $_.name -ceq 'zulu17.66.19-ca-jdk17.0.19-win_x64.zip' } | Select-Object -First 1
    $detail17 = (New-Object Net.WebClient).DownloadString('https://api.azul.com/metadata/v1/zulu/packages/' + $old17.package_uuid) | ConvertFrom-Json
    $zulu17Zip = Get-OldRuntimeZip 'zulu17' $detail17.download_url $detail17.sha256_hash
    $null = Test-Branch 'zulu17' $zulu17Zip 'Azul Zulu' '17' 'version "17.0.19"' 'jdk'

    $d8 = (New-Object Net.WebClient).DownloadString('https://api.azul.com/metadata/v1/zulu/packages/?java_version=8&os=windows&arch=x64&archive_type=zip&java_package_type=jdk&latest=true&release_status=ga&availability_types=CA&page_size=100') | ConvertFrom-Json
    $old8 = @($d8 | ForEach-Object { $_ }) | Where-Object { $_.name -ceq 'zulu8.94.0.17-ca-jdk8.0.492-win_x64.zip' } | Select-Object -First 1
    $detail8 = (New-Object Net.WebClient).DownloadString('https://api.azul.com/metadata/v1/zulu/packages/' + $old8.package_uuid) | ConvertFrom-Json
    $zulu8Zip = Get-OldRuntimeZip 'zulu8' $detail8.download_url $detail8.sha256_hash
    $null = Test-Branch 'zulu8' $zulu8Zip 'Azul Zulu' '8' 'version "1.8.0_492"' 'jdk'
    Write-Output 'ALL LIVE UPDATE TESTS PASSED'
} finally {
    $full = [IO.Path]::GetFullPath($work)
    if ($full.StartsWith([IO.Path]::GetFullPath([IO.Path]::GetTempPath()), [StringComparison]::OrdinalIgnoreCase) -and (Split-Path -Leaf $full) -like 'elo-live-*') {
        Remove-Item -LiteralPath $full -Recurse -Force -ErrorAction SilentlyContinue
    }
}
