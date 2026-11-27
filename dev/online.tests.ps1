# Windows PowerShell 5.1; a simulated GitHub only. No network access and no real tool file is touched.
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\vulndb.ps1"
. "$PSScriptRoot\catalog.ps1"
. "$PSScriptRoot\update.ps1"
$script:Passed = 0
function Assert($Condition, $Message) { if (-not $Condition) { throw "FAIL: $Message" }; $script:Passed++ }
function Assert-Throws([scriptblock]$Work, [string]$Code) {
    try { $null = & $Work } catch { if ($_.Exception.Message -like "*$Code*") { $script:Passed++; return }; throw "FAIL: expected $Code, got $($_.Exception.Message)" }
    throw "FAIL: expected $Code"
}
$root = Join-Path ([IO.Path]::GetTempPath()) ('elo-online-test-' + [guid]::NewGuid().ToString('N'))
$null = [IO.Directory]::CreateDirectory($root)
try {
    $utf8 = New-Object Text.UTF8Encoding($false)
    function Get-Hash([byte[]]$Bytes) { $sha = [Security.Cryptography.SHA256]::Create(); try { ([BitConverter]::ToString($sha.ComputeHash($Bytes)) -replace '-', '').ToLowerInvariant() } finally { $sha.Dispose() } }
    $packagedText = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'vulndb.json'))
    $newerText = $packagedText -replace '"updated": "[0-9-]+"', '"updated": "2099-01-01"'
    function New-ToolText($Version) { "@echo off`r`nrem tool`r`n<span id=`"appVersion`" class=`"version`">v$Version</span>`r`n" }
    # A simulated release: the API document, the assets and their checksum file.
    function New-FakeGitHub($Tag, $Catalog, $Bat, [hashtable]$Override = @{}) {
        $base = "https://github.com/patchamama/elo-patch-tool/releases/download/$Tag/"
        $files = @{ 'vulndb.json' = $utf8.GetBytes($Catalog); 'ELO-Patch-Tools.bat' = $utf8.GetBytes($Bat) }
        $sums = ($files.Keys | ForEach-Object { (Get-Hash $files[$_]) + ' *' + $_ }) -join "`n"
        $files['SHA256SUMS.txt'] = $utf8.GetBytes($sums)
        foreach ($key in $Override.Keys) { $files[$key] = $utf8.GetBytes([string]$Override[$key]) }
        $api = @{ tag_name = $Tag; draft = $false; prerelease = $false; assets = @($files.Keys | ForEach-Object { @{ name = $_; browser_download_url = $base + $_ } }) } | ConvertTo-Json -Depth 5
        $log = New-Object 'System.Collections.Generic.List[string]'
        $fetch = { param($Url, $MaxBytes)
            $log.Add($Url)
            if ($Url -ceq 'https://api.github.com/repos/patchamama/elo-patch-tool/releases/latest') { return , $utf8.GetBytes($api) }
            if ($Url.StartsWith($base) -and $files.ContainsKey($Url.Substring($base.Length))) { return , $files[$Url.Substring($base.Length)] }
            throw 'download_failed' }.GetNewClosure()
        return @{ Fetch = $fetch; Log = $log; Api = $api }
    }

    # --- versions and release identity
    $gh = New-FakeGitHub 'v1.5.0' $newerText (New-ToolText '1.5.0')
    $release = Get-EloLatestToolRelease -Fetch $gh.Fetch
    Assert ($release.Version -ceq '1.5.0' -and $release.Assets.Count -eq 3) 'the latest release and its assets are read'
    Assert ((Get-EloToolVersion '<span id="appVersion" class="version">v1.4.2</span>') -ceq '1.4.2') 'the running version is read from the packaged page'
    Assert ((Test-EloNewerVersion '1.10.0' '1.9.9') -and -not (Test-EloNewerVersion '1.4.0' '1.4.0') -and -not (Test-EloNewerVersion '1.3.9' '1.4.0')) 'versions compare numerically'
    $evil = @{ Fetch = { param($Url, $MaxBytes) , $utf8.GetBytes('{"tag_name":"v9.0.0","assets":[{"name":"ELO-Patch-Tools.bat","browser_download_url":"https://evil.example/ELO-Patch-Tools.bat"}]}') }.GetNewClosure() }
    Assert ((Get-EloLatestToolRelease -Fetch $evil.Fetch).Assets.Count -eq 0) 'assets outside the repository release path are ignored'
    foreach ($bad in @('{"tag_name":"latest","assets":[]}', '{"tag_name":"v2.0.0","prerelease":true,"assets":[]}', 'not json')) {
        Assert-Throws { Get-EloLatestToolRelease -Fetch { param($Url, $MaxBytes) , $utf8.GetBytes($bad) }.GetNewClosure() } 'release_unreadable'
    }
    Assert-Throws { Get-EloReleaseAsset -Release $release -Name 'ELO-Patch-Tools.bat' -Fetch (New-FakeGitHub 'v1.5.0' $newerText 'x' @{ 'ELO-Patch-Tools.bat' = 'tampered' }).Fetch } 'checksum_mismatch'
    Assert-Throws { Assert-EloGitHubAddress 'https://evil.example/x' } 'unverified_https_host'
    Assert-Throws { Assert-EloGitHubAddress 'http://github.com/x' } 'unverified_https_host'

    # --- catalog
    $none = Join-Path $root 'programdata-empty'
    function Use-Catalog($GitHub, $Version = '1.4.0', $ProgramData = $none) {
        $script:EloVulnCache = $null
        Use-EloOnlineCatalog -Release (Get-EloLatestToolRelease -Fetch $GitHub.Fetch) -CurrentVersion $Version -Fetch $GitHub.Fetch -ProgramDataRoot $ProgramData
    }
    $state = Use-Catalog (New-FakeGitHub 'v1.5.0' $newerText 'x')
    Assert ($state.Source -ceq 'downloaded' -and $state.Updated -ceq '2099-01-01' -and (Get-EloVulnDb).updated -ceq '2099-01-01') 'without an installed catalog the release catalog is used'
    $state = Use-Catalog (New-FakeGitHub 'v1.3.0' $newerText 'x')
    Assert ($state.Source -ceq 'packaged' -and $state.Reason -ceq 'release_older_than_tool') 'a release older than the running tool is not used'
    $state = Use-Catalog (New-FakeGitHub 'v1.5.0' ($packagedText -replace '"updated": "[0-9-]+"', '"updated": "2000-01-01"') 'x')
    Assert ($state.Source -ceq 'packaged' -and $state.Reason -ceq 'catalog_older_than_packaged') 'an older catalog is not used'
    # A downloaded catalog can only ADD entries: packaged detection and actions stay exactly as packaged.
    . "$PSScriptRoot\scan.ps1"
    function New-Catalog([scriptblock]$Edit) { $db = $newerText | ConvertFrom-Json; & $Edit $db; $db | ConvertTo-Json -Depth 30 }
    function Get-Verdict($Build) { (Get-EloJavaClassification -Evidence "OpenJDK Runtime Environment Temurin-$Build (build $Build)" -Rules (Get-EloScanRules (Get-EloVulnDb))).Status }
    $hostile = @{
        'a vulnerable build listed as fixed' = { param($d) $d.vulnerabilities[0].detection.vendors.Temurin.fixed = @('17.0.2+8') }
        'vendors replaced' = { param($d) $d.vulnerabilities[0].detection.vendors = [pscustomobject]@{ Nobody = $d.vulnerabilities[0].detection.vendors.Temurin } }
        'a retired entry' = { param($d) $d.vulnerabilities[0].status = 'retired' }
        'a renamed entry' = { param($d) $d.vulnerabilities[0].id = 'CVE-2099-000001' }
    }
    foreach ($name in $hostile.Keys) {
        $state = Use-Catalog (New-FakeGitHub 'v1.5.0' (New-Catalog $hostile[$name]) 'x')
        $kept = @((Get-EloVulnDb).vulnerabilities | Where-Object { $_.id -ceq 'CVE-2026-114938' })
        Assert ($kept.Count -eq 1 -and $kept[0].status -ceq 'active' -and (Get-Verdict '17.0.2+8') -ceq 'PotentiallyVulnerable') "packaged detection survives $name"
    }
    function New-AddedEntry($ProbeArgs) {
        New-Catalog { param($d)
            $extra = $d.vulnerabilities[0] | ConvertTo-Json -Depth 30 | ConvertFrom-Json
            $extra.id = 'CVE-2099-000002'; $extra.detection.probes[0].args = $ProbeArgs; $extra.advisories = @()
            $d.vulnerabilities = @($d.vulnerabilities[0], $extra) }.GetNewClosure()
    }
    $state = Use-Catalog (New-FakeGitHub 'v1.5.0' (New-AddedEntry @('-version')) 'x')
    $added = @((Get-EloVulnDb).vulnerabilities | Where-Object { $_.id -ceq 'CVE-2099-000002' })
    Assert ($state.Source -ceq 'downloaded' -and $added.Count -eq 1) 'a new vulnerability is added'
    Assert (@($added[0].actions | Where-Object { $_.type -ceq 'jvm-option' }).Count -eq 0 -and @((Get-EloVulnDb).vulnerabilities[0].actions | Where-Object { $_.type -ceq 'jvm-option' }).Count -eq 1) 'a downloaded entry can never write a machine option'
    foreach ($unsafe in @(@('-XX:OnOutOfMemoryError=logoff.exe', '-Xmx2m', '-version'), @('-XX:OnError=calc', '-version'), @('-agentlib:x', '-version'), @('-Dfoo=bar', '-version'))) {
        $state = Use-Catalog (New-FakeGitHub 'v1.5.0' (New-AddedEntry $unsafe) 'x')
        Assert ($state.Source -ceq 'packaged' -and $state.Reason -ceq 'catalog_unsafe_probe') "a downloaded probe may not pass $($unsafe[0]) to java"
    }
    # The page rejects the WHOLE results payload when one catalog value breaks its contract, which would hide the
    # packaged findings: a downloaded catalog with such an entry is not used.
    function New-ExtraEntry([scriptblock]$Edit) {
        New-Catalog { param($d)
            $extra = $d.vulnerabilities[0] | ConvertTo-Json -Depth 30 | ConvertFrom-Json
            $extra.id = 'CVE-2099-000003'; $extra.detection.probes[0].args = @('-version'); $extra.verifiedOn = '2026-11-01'
            $extra.advisories = @($extra.advisories[0]); $extra.advisories[0].id = 'extra-advisory'
            & $Edit $extra
            $d.vulnerabilities = @($d.vulnerabilities[0], $extra) }.GetNewClosure()
    }
    $state = Use-Catalog (New-FakeGitHub 'v1.5.0' (New-ExtraEntry { param($e) }) 'x')
    Assert ($state.Source -ceq 'downloaded') 'a well-formed added entry is accepted'
    $breaking = @{
        'an advisory link with a fragment' = { param($e) $e.advisories[0].url = 'https://example.org/cpu.html#AppendixJAVA' }
        'an advisory link with a query' = { param($e) $e.advisories[0].url = 'https://example.org/cpu?x=1' }
        'an advisory link with dot segments' = { param($e) $e.advisories[0].url = 'https://example.org/a/../b' }
        'a reused advisory id' = { param($e) $e.advisories[0].id = 'temurin-november-2026' }
        'an advisory id with a dot' = { param($e) $e.advisories[0].id = 'a.b' }
        'too many advisories' = { param($e) $first = $e.advisories[0]; $e.advisories = @(1..13 | ForEach-Object { $c = $first | ConvertTo-Json -Depth 5 | ConvertFrom-Json; $c.id = "extra-$_"; $c }) }
        'a long advisory title' = { param($e) $e.advisories[0].title.en = 'x' * 300 }
        'a future verification date' = { param($e) $e.verifiedOn = '2099-01-01' }
        'a malformed verification date' = { param($e) $e.verifiedOn = '01.11.2026' }
        'a long alias' = { param($e) $e.aliases = @('x' * 65) }
        'an id ending in a newline' = { param($e) $e.id = "CVE-2026-114938`n" }
    }
    foreach ($name in $breaking.Keys) {
        $state = Use-Catalog (New-FakeGitHub 'v1.5.0' (New-ExtraEntry $breaking[$name]) 'x')
        Assert ($state.Source -ceq 'packaged' -and @((Get-EloVulnDb).vulnerabilities).Count -eq 1) "a catalog with $name is not used (got $($state.Source) $($state.Reason))"
    }
    $many = New-Catalog { param($d) $first = $d.vulnerabilities[0]; $d.vulnerabilities = @(@($first) + @(1..32 | ForEach-Object { $c = $first | ConvertTo-Json -Depth 30 | ConvertFrom-Json; $c.id = "CVE-2099-$(100000+$_)"; $c.detection.probes[0].args = @('-version'); $c.advisories = @(); $c })) }
    Assert ((Use-Catalog (New-FakeGitHub 'v1.5.0' $many 'x')).Source -ceq 'packaged') 'more vulnerabilities than the page accepts are not used'
    $state = Use-Catalog (New-FakeGitHub 'v1.5.0' '{"schemaVersion":1}' 'x')
    Assert ($state.Source -ceq 'packaged') 'an invalid catalog falls back to the packaged one'
    $state = Use-Catalog (New-FakeGitHub 'v1.5.0' $newerText 'x' @{ 'vulndb.json' = $newerText + ' ' })
    Assert ($state.Source -ceq 'packaged' -and $state.Reason -ceq 'checksum_mismatch' -and (Get-EloVulnDb).updated -cne '2099-01-01') 'a catalog with a wrong checksum is not used'
    $installedRoot = Join-Path $root 'programdata'; $null = [IO.Directory]::CreateDirectory((Join-Path $installedRoot 'ELO-Patch-Tools'))
    [IO.File]::WriteAllText((Join-Path $installedRoot 'ELO-Patch-Tools\vulndb.json'), $packagedText)
    $gh = New-FakeGitHub 'v1.5.0' $newerText 'x'
    $state = Use-Catalog $gh '1.4.0' $installedRoot
    Assert ($state.Source -ceq 'installed' -and @($gh.Log | Where-Object { $_ -like '*vulndb.json' }).Count -eq 0) 'an installed catalog wins and nothing is downloaded'

    # --- the whole check never fails the tool
    $script:EloVulnCache = $null
    $info = Get-EloOnlineState -CurrentVersion '1.4.0' -Fetch { param($Url, $MaxBytes) throw 'download_failed' } -ProgramDataRoot $none
    Assert ($info.Checked -eq $false -and $info.Available -eq $false -and $info.Catalog.Source -ceq 'packaged') 'offline: the packaged catalog is used and no update is offered'
    $script:EloVulnCache = $null
    $gh = New-FakeGitHub 'v1.5.0' $newerText 'x'
    $info = Get-EloOnlineState -CurrentVersion '1.4.0' -Fetch $gh.Fetch -ProgramDataRoot $none
    Assert ($info.Checked -and $info.Available -and $info.Latest -ceq '1.5.0') 'a newer release is detected'
    $gh = New-FakeGitHub 'v1.5.0' $newerText 'x'
    $info = Get-EloOnlineState -CurrentVersion '1.4.0' -Fetch $gh.Fetch -ProgramDataRoot $none -Disabled
    Assert ($info.Checked -eq $false -and $info.Catalog.Reason -ceq 'online_check_disabled' -and $gh.Log.Count -eq 0) 'the opt-out makes no request at all'

    # --- self-update of the .bat
    $tool = Join-Path $root 'tool folder & name'; $null = [IO.Directory]::CreateDirectory($tool)
    $bat = Join-Path $tool 'ELO-Patch-Tools.bat'; [IO.File]::WriteAllText($bat, (New-ToolText '1.4.0'))
    $original = [IO.File]::ReadAllText($bat)
    function Install($GitHub, $Version = '1.4.0', $Expected = '1.5.0') { Install-EloToolUpdate -BatPath $bat -CurrentVersion $Version -ExpectedVersion $Expected -Fetch $GitHub.Fetch -Clock { [datetime]'2026-11-27T10:00:00' } }
    Assert-Throws { Install (New-FakeGitHub 'v1.5.0' $newerText (New-ToolText '1.5.0') @{ 'ELO-Patch-Tools.bat' = 'tampered' }) } 'checksum_mismatch'
    Assert-Throws { Install (New-FakeGitHub 'v1.5.0' $newerText (New-ToolText '1.4.9')) } 'downloaded_tool_invalid'
    Assert-Throws { Install (New-FakeGitHub 'v1.5.0' $newerText 'not a batch file') } 'downloaded_tool_invalid'
    Assert-Throws { Install (New-FakeGitHub 'v1.6.0' $newerText (New-ToolText '1.6.0')) } 'release_changed'
    Assert-Throws { Install (New-FakeGitHub 'v1.4.0' $newerText (New-ToolText '1.4.0')) '1.4.0' '1.4.0' } 'tool_update_not_needed'
    Assert ([IO.File]::ReadAllText($bat) -ceq $original -and @(Get-ChildItem -LiteralPath $tool).Count -eq 1) 'a refused update leaves the tool and its folder unchanged'
    $done = Install (New-FakeGitHub 'v1.5.0' $newerText (New-ToolText '1.5.0'))
    Assert ([IO.File]::ReadAllText($bat) -ceq (New-ToolText '1.5.0') -and $done.Version -ceq '1.5.0') 'the verified new version replaces the tool'
    Assert ([IO.File]::ReadAllText($done.Backup) -ceq $original -and $done.Backup -like '*.backup-20261127100000' -and @(Get-ChildItem -LiteralPath $tool).Count -eq 2) 'the previous tool is kept as a backup and no temporary file remains'
    Assert-Throws { Install-EloToolUpdate -BatPath (Join-Path $tool 'missing.bat') -CurrentVersion '1.4.0' -ExpectedVersion '1.5.0' -Fetch $gh.Fetch } 'tool_path_unavailable'
} finally {
    $full = [IO.Path]::GetFullPath($root)
    if ($full.StartsWith([IO.Path]::GetFullPath([IO.Path]::GetTempPath()), [StringComparison]::OrdinalIgnoreCase) -and (Split-Path -Leaf $full) -like 'elo-online-test-*') { Remove-Item -LiteralPath $full -Recurse -Force -ErrorAction SilentlyContinue }
}
Write-Output "PASS: $script:Passed online catalog and self-update assertions"
