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
    $state = Use-Catalog (New-FakeGitHub 'v1.5.0' ($newerText -replace 'CVE-2026-114938', 'CVE-2099-000001') 'x')
    Assert ($state.Source -ceq 'packaged' -and $state.Reason -ceq 'catalog_drops_vulnerability') 'a catalog may not drop a packaged vulnerability'
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
