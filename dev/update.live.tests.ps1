# OPT-IN live test (Windows PowerShell 5.1, administrator, network, ~600 MB of disk).
# Run only on a disposable test machine: ELO_LIVE_UPDATE_TEST=1 powershell -File dev\update.live.tests.ps1
# It downloads Eclipse Temurin 17.0.2+8 (old, vulnerable) into a scratch directory under
# %TEMP%, then drives the server API with the REAL adapters: preview, confirmed update
# (backup, pinned download, staging, Java self-test, replacement), a forced validation
# failure with real rollback, and the restore commands from the report. It never touches
# any installed runtime. The scratch directory is deleted at the end (this test's own).
$ErrorActionPreference = 'Stop'
if ($env:ELO_LIVE_UPDATE_TEST -ne '1') { Write-Output 'SKIP: set ELO_LIVE_UPDATE_TEST=1 to run the live update test'; return }
. "$PSScriptRoot\update.ps1"; . "$PSScriptRoot\scan.ps1"; . "$PSScriptRoot\server.ps1"; . "$PSScriptRoot\report.ps1"
function Assert-Live($Condition, $Message) { if (-not $Condition) { throw "ASSERT: $Message" }; Write-Output "PASS: $Message" }
$work = Join-Path ([IO.Path]::GetTempPath()) ('elo-live-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory $work
try {
    $oldZip = Join-Path $work 'old.zip'
    $oldUri = 'https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.2%2B8/OpenJDK17U-jdk_x64_windows_hotspot_17.0.2_8.zip'
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    (New-Object Net.WebClient).DownloadFile($oldUri, $oldZip)
    Assert-Live ((Get-FileHash $oldZip -Algorithm SHA256).Hash -ieq 'd083479ca927dce2f586f779373d895e8bf668c632505740279390384edf03fa') 'old Temurin 17.0.2+8 hash matches the vendor value'
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    function New-LiveRoot($Name) {
        $root = Join-Path $work $Name; $null = New-Item -ItemType Directory $root
        [IO.Compression.ZipFile]::ExtractToDirectory($oldZip, $root)
        Rename-Item (Join-Path $root 'jdk-17.0.2+8') 'java'
        return $root
    }
    function New-LiveSession($Root) {
        $s = New-EloServerSession -Port 54999 -UiHtml 'live' -ScanSource 'live'
        $java = Join-Path $Root 'java\bin\java.exe'
        $s.State = 'completed'
        $s.Targets = @{ live1 = [pscustomobject]@{ Location = $java; Status = 'PotentiallyVulnerable'; Vendor = 'Temurin'; FullVersion = '17.0.2+8' } }
        $s.ReportJvms = @(@{ Version = '17.0.2+8'; Verified = $true; ExecutionVerified = $true; Vendor = 'Temurin'; VendorVerified = $true; Classification = 'PotentiallyVulnerable'; ClassificationVerified = $true; EvidenceCode = 'AdvisoryRangeMatch' })
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

    # 1. Successful update through the API.
    $root = New-LiveRoot 'ok'; $s = New-LiveSession $root
    $preview = Call $s '/api/preview' '{"actionId":"update-runtime","resultId":"live1"}'
    Assert-Live ($preview.summary.en.Contains('17.0.21.1+2') -and -not (Test-Path (Join-Path $root 'java.old*'))) 'preview names the target version and changes nothing'
    $null = Call $s '/api/action' ('{"actionId":"update-runtime","resultId":"live1","previewId":"' + $preview.previewId + '"}')
    Assert-Live ((Get-JavaVersion $root).Contains('17.0.21.1')) 'java -version reports 17.0.21.1 after the update'
    Assert-Live ((@(Get-ChildItem $root -Filter 'java.backup-*.zip').Count -eq 1) -and (@(Get-ChildItem $root -Directory -Filter 'java.old-*').Count -eq 1)) 'backup ZIP and old runtime are kept'
    $s.Adapters.Resources = { @{ ServerName = 'LIVE'; WindowsVersion = '10.0'; WindowsBuild = '20348'; TotalRamBytes = 8GB; Disks = @(@{ Name = 'C:'; TotalBytes = 100GB; FreeBytes = 40GB }) } }
    $html = Get-EloSessionReportHtml $s 'en'
    Assert-Live ($html.Contains('17.0.21.1+2') -and $html.Contains('Expand-Archive') -and $html.Contains('java.backup-')) 'report lists the update, backup ZIP and restore commands'

    # 2. Restore from the backup ZIP using the documented PowerShell commands.
    $zip = (Get-ChildItem $root -Filter 'java.backup-*.zip').FullName
    $runtime = Join-Path $root 'java'; $dest = $runtime + '.restore'
    Remove-Item -LiteralPath $runtime -Recurse -Force
    Expand-Archive -LiteralPath $zip -DestinationPath $dest
    Move-Item -LiteralPath (Join-Path $dest 'tree') -Destination $runtime
    Assert-Live ((Get-JavaVersion $root).Contains('17.0.2')) 'documented restore commands bring back Temurin 17.0.2'

    # 3. Forced validation failure: real rollback.
    $root = New-LiveRoot 'rollback'; $s = New-LiveSession $root
    $realFactory = $s.Adapters.NewUpdateContext
    $s.Adapters.NewUpdateContext = { param($R, $T) $c = & $realFactory $R $T; $c.Adapters.ValidateInstalled = { param($a, $b) $false }; $c }.GetNewClosure()
    $preview = Call $s '/api/preview' '{"actionId":"update-runtime","resultId":"live1"}'
    $code = ''
    try { $null = Call $s '/api/action' ('{"actionId":"update-runtime","resultId":"live1","previewId":"' + $preview.previewId + '"}') } catch { $code = $_.Exception.Message }
    Assert-Live ($code -ceq 'update_failed_rolled_back') 'forced validation failure reports a rollback'
    Assert-Live ((Get-JavaVersion $root).Contains('17.0.2') -and @(Get-ChildItem $root -Directory -Filter 'java.stage-*.failed-*').Count -eq 1) 'original runtime restored; failed runtime retained'
    Write-Output 'ALL LIVE UPDATE TESTS PASSED'
} finally {
    $full = [IO.Path]::GetFullPath($work)
    if ($full.StartsWith([IO.Path]::GetFullPath([IO.Path]::GetTempPath()), [StringComparison]::OrdinalIgnoreCase) -and (Split-Path -Leaf $full) -like 'elo-live-*') {
        Remove-Item -LiteralPath $full -Recurse -Force -ErrorAction SilentlyContinue
    }
}
