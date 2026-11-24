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
