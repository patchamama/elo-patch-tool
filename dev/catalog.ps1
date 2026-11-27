# Embeddable Windows PowerShell 5.1 module: dot-sourcing defines functions ONLY.
# Release catalog for runtime updates. The newest GA release of a Java branch is
# resolved at preview time from the vendor's OFFICIAL metadata API over HTTPS
# (Azul Zulu: api.azul.com; Eclipse Temurin: api.adoptium.net). The package URI and
# SHA256 returned by the API are then validated against a STRICT per-vendor policy
# (host allowlist, URL shape, size bounds) before anything is downloaded. The policy
# lives here, never in the API response, an HTTP client or the UI.
# Supported: Windows, branches 8/11/17/21/25 and any other numeric branch the vendor
# publishes, architectures x86/x64/ARM64, images jdk/jre, plain GA builds (no CRaC/FX).

function Get-EloVendorPolicy {
    return @{
        'Azul Zulu' = @{
            ApiHosts = @('api.azul.com'); DownloadHosts = @('cdn.azul.com')
            PathPattern = '^/zulu/bin/zulu[0-9.]+-ca-(jdk|jre)[0-9.]+-win_(x64|i686|aarch64)\.zip$'
        }
        'Eclipse Adoptium' = @{
            ApiHosts = @('api.adoptium.net'); DownloadHosts = @('github.com', 'release-assets.githubusercontent.com')
            PathPattern = '^/adoptium/temurin[0-9]+-binaries/releases/download/[A-Za-z0-9._%+-]+/OpenJDK[0-9]+U-(jdk|jre)_(x64|x86-32|aarch64)_windows_hotspot_[A-Za-z0-9._%+-]+\.zip$'
        }
    }
}
function ConvertTo-EloJavaVersion {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { throw 'unrecognized_java_version' }
    $s = $Text.Trim(); $build = 0
    if ($s -cmatch '^(.*?)\+(\d+)(?:-.*)?$') { $s = $Matches[1]; $build = [int]$Matches[2] }
    elseif ($s -cmatch '^(.*?)-b(\d+)$') { $s = $Matches[1]; $build = [int]$Matches[2] }
    else { $s = $s -creplace '-[A-Za-z].*$', '' }
    if ($s -cmatch '^1\.(\d+)\.(\d+)_(\d+)$') { $numbers = @([int]$Matches[1], [int]$Matches[2], [int]$Matches[3]) }
    elseif ($s -cmatch '^(\d+)u(\d+)$') { $numbers = @([int]$Matches[1], 0, [int]$Matches[2]) }
    elseif ($s -cmatch '^\d+(\.\d+){0,4}$') { $numbers = @($s.Split('.') | ForEach-Object { [int]$_ }) }
    else { throw 'unrecognized_java_version' }
    foreach ($n in $numbers) { if ($n -lt 0 -or $n -gt 100000) { throw 'unrecognized_java_version' } }
    return @{ Numbers = $numbers; Build = $build; Branch = [string]$numbers[0]; Text = (($numbers -join '.') + '+' + $build) }
}
function Compare-EloJavaVersion {
    # -1 when $Left is older than $Right, 0 when equal, 1 when newer.
    param([Parameter(Mandatory = $true)]$Left, [Parameter(Mandatory = $true)]$Right)
    $length = [Math]::Max($Left.Numbers.Count, $Right.Numbers.Count)
    for ($i = 0; $i -lt $length; $i++) {
        $a = 0; if ($i -lt $Left.Numbers.Count) { $a = $Left.Numbers[$i] }
        $b = 0; if ($i -lt $Right.Numbers.Count) { $b = $Right.Numbers[$i] }
        if ($a -ne $b) { if ($a -lt $b) { return -1 } else { return 1 } }
    }
    if ($Left.Build -ne $Right.Build) { if ($Left.Build -lt $Right.Build) { return -1 } else { return 1 } }
    return 0
}
function ConvertFrom-EloJsonArray {
    # Windows PowerShell 5.1 returns a JSON array as ONE object; always enumerate it.
    param([string]$Text)
    $parsed = ConvertFrom-Json $Text
    return @($parsed | ForEach-Object { $_ })
}
function Invoke-EloCatalogGet {
    # Bounded HTTPS GET to an allowlisted vendor API host: no redirects, no cookies,
    # 2 MiB cap, 20 s timeout, TLS 1.2 enabled only for the duration of the request.
    param([Parameter(Mandatory = $true)][string]$Uri, [Parameter(Mandatory = $true)][string[]]$AllowedHosts)
    $target = Assert-EloHttpsHost $Uri $AllowedHosts
    $previous = [Net.ServicePointManager]::SecurityProtocol
    [Net.ServicePointManager]::SecurityProtocol = $previous -bor [Net.SecurityProtocolType]::Tls12
    $response = $null
    try {
        $request = [Net.HttpWebRequest]::Create($target)
        $request.AllowAutoRedirect = $false; $request.UseDefaultCredentials = $false
        $request.Timeout = 20000; $request.ReadWriteTimeout = 20000; $request.UserAgent = 'ELO-Patch-Tools'
        $response = $request.GetResponse()
        if ([int]$response.StatusCode -ne 200) { throw 'catalog_http_status' }
        $stream = $response.GetResponseStream(); $buffer = New-Object byte[] 8192
        $memory = New-Object IO.MemoryStream
        try {
            while (($count = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                $memory.Write($buffer, 0, $count)
                if ($memory.Length -gt 2MB) { throw 'catalog_response_too_large' }
            }
            return [Text.Encoding]::UTF8.GetString($memory.ToArray())
        } finally { $memory.Dispose(); $stream.Dispose() }
    } finally { if ($response) { $response.Dispose() }; [Net.ServicePointManager]::SecurityProtocol = $previous }
}
function Assert-EloReleaseRecord {
    # Strict validation of a resolved release. The vendor policy, not the record,
    # decides which hosts and URL shapes are acceptable. Returns a normalized copy.
    param([Parameter(Mandatory = $true)]$Record)
    $policies = Get-EloVendorPolicy
    $vendor = [string]$Record.Vendor
    if (-not $policies.ContainsKey($vendor)) { throw 'unsupported_vendor' }
    $policy = $policies[$vendor]
    if ([string]$Record.Branch -cnotmatch '^\d{1,2}$') { throw 'invalid_release_branch' }
    if ([string]$Record.Architecture -cnotin @('x86', 'x64', 'ARM64')) { throw 'invalid_release_architecture' }
    if ([string]$Record.ImageType -cnotin @('jdk', 'jre')) { throw 'invalid_release_image_type' }
    $version = ConvertTo-EloJavaVersion ([string]$Record.Version)
    if ($version.Branch -cne [string]$Record.Branch) { throw 'release_branch_mismatch' }
    if ([string]$Record.Sha256 -cnotmatch '^[a-fA-F0-9]{64}$') { throw 'invalid_release_checksum' }
    [long]$size = 0
    if (-not [long]::TryParse([string]$Record.Size, [ref]$size) -or $size -lt 1MB -or $size -gt 800MB) { throw 'invalid_release_size' }
    $uri = Assert-EloHttpsHost ([string]$Record.Uri) $policy.DownloadHosts
    if ($uri.AbsolutePath -cnotmatch $policy.PathPattern -or $uri.Query) { throw 'unverified_release_uri' }
    $null = $uri.AbsolutePath -cmatch $policy.PathPattern
    $expectedImage = $Matches[1]
    $name = $uri.AbsolutePath.Substring($uri.AbsolutePath.LastIndexOf('/') + 1)
    if ($expectedImage -cne [string]$Record.ImageType) { throw 'release_image_mismatch' }
    return @{
        Vendor = $vendor; Branch = [string]$Record.Branch; Architecture = [string]$Record.Architecture; ImageType = [string]$Record.ImageType
        Version = $version.Text; Uri = $uri.AbsoluteUri; Sha256 = ([string]$Record.Sha256).ToLowerInvariant(); Size = $size
        Format = 'zip'; AllowedHosts = @($policy.DownloadHosts); Name = $name
        MaxArchiveBytes = [long]($size + 1MB); MaxExpandedBytes = [long]2GB
    }
}
function Get-EloZuluRelease {
    param([string]$Branch, [string]$Architecture, [string]$ImageType, [scriptblock]$Getter)
    $apiArch = @{ x64 = 'x64'; x86 = 'x86'; ARM64 = 'arm' }[$Architecture]
    $suffix = @{ x64 = 'win_x64'; x86 = 'win_i686'; ARM64 = 'win_aarch64' }[$Architecture]
    $list = 'https://api.azul.com/metadata/v1/zulu/packages/?java_version=' + $Branch + '&os=windows&arch=' + $apiArch +
        '&archive_type=zip&java_package_type=' + $ImageType + '&latest=true&release_status=ga&availability_types=CA&page_size=100'
    $items = ConvertFrom-EloJsonArray (& $Getter $list @('api.azul.com'))
    $best = $null; $bestVersion = $null
    foreach ($item in $items) {
        $name = [string]$item.name
        # Plain builds only: no CRaC, no JavaFX bundle.
        if ($name -cnotmatch ('^zulu[0-9.]+-ca-' + $ImageType + '[0-9.]+-' + $suffix + '\.zip$')) { continue }
        if (@($item.java_version).Count -lt 1 -or [string]$item.java_version[0] -cne $Branch) { continue }
        $candidate = ConvertTo-EloJavaVersion (((@($item.java_version) | ForEach-Object { [string]$_ }) -join '.') + '+' + [int]$item.openjdk_build_number)
        if ($null -eq $best -or (Compare-EloJavaVersion $candidate $bestVersion) -gt 0) { $best = $item; $bestVersion = $candidate }
    }
    if ($null -eq $best) { throw 'no_release_found' }
    $detail = (& $Getter ('https://api.azul.com/metadata/v1/zulu/packages/' + [string]$best.package_uuid) @('api.azul.com')) | ConvertFrom-Json
    if ([string]$best.package_uuid -cnotmatch '^[0-9a-f-]{36}$' -or [string]$detail.name -cne [string]$best.name -or
        [string]$detail.package_uuid -cne [string]$best.package_uuid -or [string]$detail.os -cne 'windows') { throw 'catalog_detail_mismatch' }
    return @{ Vendor = 'Azul Zulu'; Branch = $Branch; Architecture = $Architecture; ImageType = $ImageType; Version = $bestVersion.Text
        Uri = [string]$detail.download_url; Sha256 = [string]$detail.sha256_hash; Size = [long]$detail.size }
}
function Get-EloTemurinRelease {
    param([string]$Branch, [string]$Architecture, [string]$ImageType, [scriptblock]$Getter)
    $apiArch = @{ x64 = 'x64'; x86 = 'x32'; ARM64 = 'aarch64' }[$Architecture]
    $uri = 'https://api.adoptium.net/v3/assets/latest/' + $Branch + '/hotspot?architecture=' + $apiArch + '&image_type=' + $ImageType + '&os=windows&vendor=eclipse'
    $items = ConvertFrom-EloJsonArray (& $Getter $uri @('api.adoptium.net'))
    $best = $null; $bestVersion = $null
    foreach ($item in $items) {
        if ([string]$item.binary.os -cne 'windows' -or [string]$item.binary.image_type -cne $ImageType -or [string]$item.binary.jvm_impl -cne 'hotspot') { continue }
        $candidate = ConvertTo-EloJavaVersion ([string]$item.version.openjdk_version)
        if ($candidate.Branch -cne $Branch) { continue }
        if ($null -eq $best -or (Compare-EloJavaVersion $candidate $bestVersion) -gt 0) { $best = $item; $bestVersion = $candidate }
    }
    if ($null -eq $best) { throw 'no_release_found' }
    $package = $best.binary.package
    return @{ Vendor = 'Eclipse Adoptium'; Branch = $Branch; Architecture = $Architecture; ImageType = $ImageType; Version = $bestVersion.Text
        Uri = [string]$package.link; Sha256 = [string]$package.checksum; Size = [long]$package.size }
}
function Resolve-EloLatestRelease {
    # Newest GA release of the SAME vendor, branch, architecture and image type.
    param([Parameter(Mandatory = $true)][string]$Vendor, [Parameter(Mandatory = $true)][string]$Branch,
        [Parameter(Mandatory = $true)][string]$Architecture, [string]$ImageType = 'jdk',
        [scriptblock]$Getter = { param($Uri, $Hosts) Invoke-EloCatalogGet $Uri $Hosts })
    if ($Branch -cnotmatch '^\d{1,2}$' -or $Architecture -cnotin @('x86', 'x64', 'ARM64') -or $ImageType -cnotin @('jdk', 'jre')) { throw 'invalid_release_request' }
    $raw = $null
    switch ($Vendor) {
        'Azul Zulu' { $raw = Get-EloZuluRelease $Branch $Architecture $ImageType $Getter }
        'Eclipse Adoptium' { $raw = Get-EloTemurinRelease $Branch $Architecture $ImageType $Getter }
        default { throw 'unsupported_vendor' }
    }
    return Assert-EloReleaseRecord $raw
}

# ---- Online: the latest release of this tool on GitHub, its shared catalog and the self-update. Only
# GitHub HTTPS hosts are contacted, redirects are followed by hand, every asset is checked against the
# release's SHA256SUMS.txt, and no information about the server is sent. The checksum detects a damaged
# or altered download; it cannot protect against a compromised repository account.
$script:EloToolRepository = 'patchamama/elo-patch-tool'
$script:EloGitHubHosts = @('api.github.com', 'github.com', 'objects.githubusercontent.com', 'release-assets.githubusercontent.com')

function Assert-EloGitHubAddress {
    param([string]$Address)
    $uri = $null
    if (-not [Uri]::TryCreate($Address, [UriKind]::Absolute, [ref]$uri) -or $uri.Scheme -cne 'https' -or -not $uri.IsDefaultPort -or $uri.UserInfo -or
        $uri.HostNameType -ne [UriHostNameType]::Dns -or $script:EloGitHubHosts -cnotcontains $uri.DnsSafeHost.ToLowerInvariant()) { throw 'unverified_https_host' }
    return $uri
}
function Invoke-EloGitHubFetch {
    # Real network adapter: bytes of one GitHub resource, size-bounded, short time-outs.
    param([string]$Url, [int]$MaxBytes = 1MB, [int]$TimeoutMilliseconds = 6000)
    $previous = [Net.ServicePointManager]::SecurityProtocol
    [Net.ServicePointManager]::SecurityProtocol = $previous -bor [Net.SecurityProtocolType]::Tls12
    try {
        $uri = Assert-EloGitHubAddress $Url
        for ($hop = 0; $hop -le 5; $hop++) {
            $request = [Net.HttpWebRequest]::Create($uri)
            $request.AllowAutoRedirect = $false; $request.UseDefaultCredentials = $false
            $request.UserAgent = 'elo-patch-tool'
            $request.Timeout = $TimeoutMilliseconds; $request.ReadWriteTimeout = $TimeoutMilliseconds
            $response = $null
            try {
                $response = $request.GetResponse()
                $status = [int]$response.StatusCode
                if (@(301, 302, 303, 307, 308) -contains $status) {
                    $next = $null
                    if (-not [Uri]::TryCreate($uri, [string]$response.Headers['Location'], [ref]$next)) { throw 'download_failed' }
                    $uri = Assert-EloGitHubAddress $next.AbsoluteUri
                    continue
                }
                if ($status -ne 200) { throw 'download_failed' }
                $stream = $response.GetResponseStream(); $memory = New-Object IO.MemoryStream
                $buffer = New-Object byte[] 65536; $watch = [Diagnostics.Stopwatch]::StartNew()
                while (($count = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                    if ($memory.Length + $count -gt $MaxBytes -or $watch.Elapsed.TotalSeconds -gt 120) { throw 'download_limit' }
                    $memory.Write($buffer, 0, $count)
                }
                return , $memory.ToArray()
            } finally { if ($response) { $response.Dispose() } }
        }
        throw 'download_failed'
    } finally { [Net.ServicePointManager]::SecurityProtocol = $previous }
}
function Get-EloToolVersion {
    # The version shown in the packaged page is the single version of the running tool.
    param([string]$Html)
    if ($Html -cmatch 'id="appVersion" class="version">v([0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4})<') { return $Matches[1] }
    return ''
}
function Test-EloNewerVersion {
    param([string]$Candidate, [string]$Current)
    try { return ([version]$Candidate) -gt ([version]$Current) } catch { return $false }
}
function Get-EloLatestToolRelease {
    param([scriptblock]$Fetch = { param($Url, $MaxBytes) Invoke-EloGitHubFetch $Url $MaxBytes })
    $bytes = & $Fetch ('https://api.github.com/repos/' + $script:EloToolRepository + '/releases/latest') 1MB
    try { $data = [Text.Encoding]::UTF8.GetString([byte[]]$bytes) | ConvertFrom-Json } catch { throw 'release_unreadable' }
    if ($data.draft -or $data.prerelease -or [string]$data.tag_name -cnotmatch '^v([0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4})$') { throw 'release_unreadable' }
    $version = $Matches[1]
    $prefix = 'https://github.com/' + $script:EloToolRepository + '/releases/download/v' + $version + '/'
    $assets = @{}
    foreach ($asset in @($data.assets)) {
        $name = [string]$asset.name
        # Only the exact download path of this release is accepted, never an address from elsewhere.
        if (@('ELO-Patch-Tools.bat', 'vulndb.json', 'SHA256SUMS.txt') -ccontains $name -and [string]$asset.browser_download_url -ceq ($prefix + $name)) { $assets[$name] = $prefix + $name }
    }
    return @{ Version = $version; Assets = $assets }
}
function Get-EloReleaseAsset {
    param($Release, [string]$Name, [scriptblock]$Fetch, [int]$MaxBytes = 1MB)
    if (-not $Release.Assets.ContainsKey($Name) -or -not $Release.Assets.ContainsKey('SHA256SUMS.txt')) { throw 'release_asset_missing' }
    $sums = [Text.Encoding]::UTF8.GetString([byte[]](& $Fetch $Release.Assets['SHA256SUMS.txt'] 64KB))
    $expected = [regex]::Match($sums, '(?m)^([a-fA-F0-9]{64})[ \t]+\*?' + [regex]::Escape($Name) + '[ \t]*\r?$')
    if (-not $expected.Success) { throw 'checksum_missing' }
    $bytes = [byte[]](& $Fetch $Release.Assets[$Name] $MaxBytes)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $actual = ([BitConverter]::ToString($sha.ComputeHash($bytes)) -replace '-', '') } finally { $sha.Dispose() }
    if ($actual -ine $expected.Groups[1].Value) { throw 'checksum_mismatch' }
    return , $bytes
}
function Test-EloPageText {
    param($Value, [int]$Max)
    foreach ($lang in @('en', 'de', 'es')) {
        $text = $Value.$lang
        if ($lang -ceq 'es' -and -not $text) { continue }
        if ($text -isnot [string] -or $text.Trim().Length -lt 1 -or $text.Length -gt $Max -or $text -match '[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]') { return $false }
    }
    return $true
}
function Test-EloPageContract {
    # What the web page requires of catalog data (validVuln and validSecurity in ui.html). It rejects the whole
    # results payload on one bad value, so a downloaded catalog must meet it. Keep both sides in step.
    param($Db)
    $active = @(Get-EloActiveVulnerabilities $Db)
    if ($active.Count -gt 32) { return $false }
    $advisoryIds = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    $today = [datetime]::UtcNow.ToString('yyyy-MM-dd')
    foreach ($v in $active) {
        if ([string]$v.id -cnotmatch '\A[A-Za-z0-9._-]{3,64}\z' -or @('high', 'medium', 'low') -cnotcontains [string]$v.severity) { return $false }
        if (([string](@($v.aliases) | Select-Object -First 1)).Length -gt 64) { return $false }
        foreach ($field in @('title', 'problem', 'solution')) { if (-not (Test-EloPageText $v.$field 2048)) { return $false } }
        $actions = @($v.actions)
        if ($actions.Count -gt 16) { return $false }
        foreach ($a in $actions) {
            if ([string]$a.id -cnotmatch '\A[a-z0-9-]{1,32}\z') { return $false }
            if ($a.label -and -not (Test-EloPageText $a.label 256)) { return $false }
        }
        if ($v.verifiedOn) {
            $date = [datetime]::MinValue
            if ([string]$v.verifiedOn -cnotmatch '\A20[0-9]{2}-[0-9]{2}-[0-9]{2}\z' -or -not [datetime]::TryParseExact([string]$v.verifiedOn, 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$date) -or [string]::CompareOrdinal([string]$v.verifiedOn, $today) -gt 0) { return $false }
        }
        foreach ($adv in @($v.advisories | Where-Object { $_ })) {
            $url = [string]$adv.url
            # A plain https link only: no credentials, port, query, fragment, dot segments or encoded characters.
            if ($url.Length -gt 512 -or $url -cnotmatch '\Ahttps://[a-z0-9]([a-z0-9.-]*[a-z0-9])?/[A-Za-z0-9._~/-]*\z' -or $url -cmatch '/\.{1,2}(/|\z)') { return $false }
            if ([string]$adv.id -cnotmatch '\A[A-Za-z0-9_-]{1,128}\z' -or -not $advisoryIds.Add([string]$adv.id)) { return $false }
            if (-not (Test-EloPageText $adv.title 256)) { return $false }
        }
    }
    if ($advisoryIds.Count -gt 16) { return $false }
    if ($advisoryIds.Count -gt 0 -and @($active | Where-Object { $_.verifiedOn }).Count -eq 0) { return $false }
    return $true
}
function Merge-EloOnlineCatalog {
    # A downloaded catalog can only ADD vulnerabilities. Every packaged entry stays exactly as packaged, so
    # a release can never change or switch off built-in detection. An added entry may only run java with the
    # read-only options below and can never write a machine option.
    param($Packaged, $Remote)
    $allowed = @('-version', '-XX:+PrintFlagsFinal', '-XX:+UnlockDiagnosticVMOptions', '-XshowSettings:properties', '-XshowSettings:vm')
    $known = @($Packaged.vulnerabilities | ForEach-Object { [string]$_.id })
    $added = @($Remote.vulnerabilities | Where-Object { $known -notcontains [string]$_.id })
    foreach ($entry in $added) {
        $probes = @($entry.detection.probes)
        foreach ($probe in $probes) {
            if (@($probe.args | Where-Object { $allowed -cnotcontains [string]$_ }).Count -gt 0 -or @($probe.args) -cnotcontains '-version') { throw 'catalog_unsafe_probe' }
        }
        $entry.actions = @($entry.actions | Where-Object { [string]$_.type -cne 'jvm-option' })
    }
    $merged = $Packaged | ConvertTo-Json -Depth 40 | ConvertFrom-Json
    $merged.updated = [string]$Remote.updated
    $merged.vulnerabilities = @(@($merged.vulnerabilities) + $added)
    if (@(Test-EloVulnDb $merged).Count -gt 0) { throw 'catalog_invalid_after_merge' }
    if (-not (Test-EloPageContract $merged)) { throw 'catalog_page_contract' }
    return $merged
}
function Use-EloOnlineCatalog {
    # With no installed catalog, the new entries of the latest release's catalog are added for this session
    # (memory only). It must come from a release at least as new as the tool, be at least as recent as the
    # packaged one and pass the same validation; see Merge-EloOnlineCatalog for what it may change.
    param($Release, [string]$CurrentVersion, [scriptblock]$Fetch, [string]$ProgramDataRoot = $env:ProgramData)
    $packaged = Read-EloVulnDbFile (Join-Path $PSScriptRoot 'vulndb.json')
    $installed = Get-EloVulnDbPath $ProgramDataRoot
    if ($installed -cne (Join-Path $PSScriptRoot 'vulndb.json')) {
        try { $db = Read-EloVulnDbFile $installed; return @{ Source = 'installed'; Updated = [string]$db.updated; Reason = '' } } catch { }
    }
    $result = @{ Source = 'packaged'; Updated = [string]$packaged.updated; Reason = '' }
    $temp = $null
    try {
        if (Test-EloNewerVersion $CurrentVersion $Release.Version) { throw 'release_older_than_tool' }
        $bytes = Get-EloReleaseAsset -Release $Release -Name 'vulndb.json' -Fetch $Fetch
        $temp = Join-Path ([IO.Path]::GetTempPath()) ('elo-catalog-' + [guid]::NewGuid().ToString('N') + '.json')
        [IO.File]::WriteAllBytes($temp, $bytes)
        $db = Read-EloVulnDbFile $temp
        if ([string]$db.updated -cnotmatch '^\d{4}-\d{2}-\d{2}$' -or [string]::CompareOrdinal([string]$db.updated, [string]$packaged.updated) -lt 0) { throw 'catalog_older_than_packaged' }
        $db = Merge-EloOnlineCatalog -Packaged $packaged -Remote $db
        $script:EloVulnCache = $db
        $result = @{ Source = 'downloaded'; Updated = [string]$db.updated; Reason = '' }
    } catch {
        $code = [string]$_.Exception.Message
        if ($code -cmatch '^([a-z_]{1,64})') { $result.Reason = $Matches[1] } else { $result.Reason = 'download_failed' }
    } finally { if ($temp -and (Test-Path -LiteralPath $temp)) { Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue } }
    return $result
}
function Get-EloOnlineState {
    # One check per run. It never throws: offline or broken answers leave the packaged catalog in use.
    param([string]$CurrentVersion, [scriptblock]$Fetch = { param($Url, $MaxBytes) Invoke-EloGitHubFetch $Url $MaxBytes },
        [string]$ProgramDataRoot = $env:ProgramData, [switch]$Disabled)
    $state = @{ Checked = $false; Current = $CurrentVersion; Latest = ''; Available = $false; Catalog = @{ Source = 'packaged'; Updated = ''; Reason = '' } }
    try {
        $current = Read-EloVulnDbFile (Get-EloVulnDbPath $ProgramDataRoot)
        $state.Catalog.Updated = [string]$current.updated
        if ((Get-EloVulnDbPath $ProgramDataRoot) -cne (Join-Path $PSScriptRoot 'vulndb.json')) { $state.Catalog.Source = 'installed' }
    } catch { }
    if ($Disabled) { $state.Catalog.Reason = 'online_check_disabled'; return $state }
    try { $release = Get-EloLatestToolRelease -Fetch $Fetch } catch { $state.Catalog.Reason = 'github_unreachable'; return $state }
    $state.Checked = $true; $state.Latest = $release.Version
    $state.Available = (Test-EloNewerVersion $release.Version $CurrentVersion)
    try { $state.Catalog = Use-EloOnlineCatalog -Release $release -CurrentVersion $CurrentVersion -Fetch $Fetch -ProgramDataRoot $ProgramDataRoot } catch { $state.Catalog.Reason = 'download_failed' }
    return $state
}
function Format-EloCatalogNotice {
    param($State)
    $text = 'Vulnerability catalog: ' + $State.Catalog.Source + ' (updated ' + $State.Catalog.Updated + ')'
    if ($State.Catalog.Reason) { $text += ' [' + $State.Catalog.Reason + ']' }
    return $text
}
function Install-EloToolUpdate {
    # Replaces the .bat with the verified one of the confirmed release; the previous file is kept next to it.
    # The running session keeps using its extracted files: the new version runs after a restart.
    param([string]$BatPath, [string]$CurrentVersion, [string]$ExpectedVersion,
        [scriptblock]$Fetch = { param($Url, $MaxBytes) Invoke-EloGitHubFetch $Url $MaxBytes }, [scriptblock]$Clock = { [datetime]::UtcNow })
    if (-not $BatPath -or $BatPath -notmatch '(?i)\.bat$' -or -not (Test-Path -LiteralPath $BatPath -PathType Leaf)) { throw 'tool_path_unavailable' }
    if ((Get-Item -LiteralPath $BatPath -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'tool_path_unavailable' }
    $release = Get-EloLatestToolRelease -Fetch $Fetch
    if ($release.Version -cne $ExpectedVersion) { throw 'release_changed' }
    if (-not (Test-EloNewerVersion $release.Version $CurrentVersion)) { throw 'tool_update_not_needed' }
    $bytes = Get-EloReleaseAsset -Release $release -Name 'ELO-Patch-Tools.bat' -Fetch $Fetch -MaxBytes 8MB
    $text = [Text.Encoding]::UTF8.GetString($bytes)
    if (-not $text.StartsWith('@echo off') -or (Get-EloToolVersion $text) -cne $release.Version) { throw 'downloaded_tool_invalid' }
    $backup = $BatPath + '.backup-' + (& $Clock).ToString('yyyyMMddHHmmss')
    if (Test-Path -LiteralPath $backup) { throw 'tool_backup_exists' }
    $temp = $BatPath + '.new-' + [guid]::NewGuid().ToString('N')
    try {
        [IO.File]::WriteAllBytes($temp, $bytes)
        [IO.File]::Replace($temp, $BatPath, $backup)
    } finally { if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue } }
    return @{ Version = $release.Version; Backup = $backup; Path = $BatPath }
}
