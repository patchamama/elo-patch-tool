# Windows PowerShell 5.1 integration checks. No live discovery, Java, registry or browser.
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$bat = Join-Path $repo 'ELO-Patch-Tools.bat'
$checks = 0
function Assert($Condition, [string]$Message) {
    if (-not $Condition) { throw "ASSERT: $Message" }
    $script:checks++
}
# RED must occur before creating fixtures when the candidate has not been assembled.
Assert ([IO.File]::Exists($bat)) 'single-file integration candidate exists'
Assert ($PSVersionTable.PSVersion.Major -eq 5 -and $PSVersionTable.PSVersion.Minor -eq 1) 'Windows PowerShell 5.1 runner'
$source = [IO.File]::ReadAllText($bat, [Text.Encoding]::UTF8)
$blocks = @{}
foreach ($m in [regex]::Matches($source, '(?ms)^::ELO_PATCH_BEGIN:([A-Z_]+)\r?\n(.*?)^::ELO_PATCH_END:\1\s*$')) {
    Assert (-not $blocks.ContainsKey($m.Groups[1].Value)) 'unique packaged resource'
    $blocks[$m.Groups[1].Value] = $m.Groups[2].Value.TrimEnd("`r", "`n")
}
# Exercise the packaged scanner independently of the development source.
. ([scriptblock]::Create($blocks.SCAN_PS))
$rootFixture=Get-EloJavaCandidates -DriveRoots @('C:\','D:\') -ManualPath 'C:\manual' -MaxEntries 1 -IsReparsePoint { $false } -GetChildren {
    param($Path)
    if ($Path -in @('C:\java\bin\java.exe','D:\ELO\java\bin\java.exe')) {
        [pscustomobject]@{Name='java.exe';FullName=$Path;PSIsContainer=$false;Attributes=0}
    } elseif ($Path -ceq 'C:\manual') {
        [pscustomobject]@{Name='java.exe';FullName='C:\manual\java.exe';PSIsContainer=$false;Attributes=0}
    } else { @() }
}
Assert ($rootFixture.Locations.Count -eq 3 -and $rootFixture.Locations[0] -ceq 'C:\java\bin\java.exe' -and $rootFixture.Locations[1] -ceq 'D:\ELO\java\bin\java.exe') 'exact root layouts precede bounded manual fallback across drives'
$resources = @{ SCAN_PS='scan.ps1'; SERVER_PS='server.ps1'; CLI_PS='cli.ps1'; UI_HTML='ui.html'; REPORT_PS='report.ps1' }
foreach ($name in $resources.Keys) {
    Assert ($blocks.ContainsKey($name)) "embedded $name"
    $expected = [IO.File]::ReadAllText((Join-Path $PSScriptRoot $resources[$name]), [Text.Encoding]::UTF8).TrimEnd("`r", "`n")
    Assert (($blocks[$name] -replace "`r`n", "`n") -ceq ($expected -replace "`r`n", "`n")) "unmodified $name payload"
}
Assert ($source -notmatch '(?i)ExecutionPolicy\s+Bypass') 'production honors execution policy'
Assert ($source -notmatch '(?i)dev[/\\](scan|cli|server|ui|update)') 'no development-file runtime dependencies'
# Parse and load trusted functions only. CLI is dot-sourced, never direct-executed.
foreach ($name in @('SCAN_PS','SERVER_PS','CLI_PS','REPORT_PS')) {
    $tokens=$null; $errors=$null
    $null=[Management.Automation.Language.Parser]::ParseInput($blocks[$name],[ref]$tokens,[ref]$errors)
    Assert ($errors.Count -eq 0) "$name parses in Windows PowerShell"
    . ([scriptblock]::Create($blocks[$name]))
}
# Scanner behavior with fully synthetic discovery/probe adapters.
foreach ($case in @(
    @('17.0.21.1+2','KnownFixed'), @('17.0.21.1+1','PotentiallyVulnerable'),
    @('17.0.21+10','PotentiallyVulnerable'), @('17.0.22+1','Inconclusive'),
    @('21.0.13.1+2','KnownFixed'), @('25.0.5.1+2','KnownFixed'),
    @('27.0.1.1+4','KnownFixed'), @('17.0.21.1+2-ea','Inconclusive')
)) {
    $evidence='Temurin Runtime Environment (build '+$case[0]+')'
    Assert ((Get-EloJavaClassification $evidence).Status -ceq $case[1]) 'conservative version comparison'
}
$cancelled=Invoke-EloJavaScan -DriveRoots @() -ShouldCancel { $true } -GetChildren { throw 'must not enumerate' } -ProbeJava { throw 'must not probe' }
Assert ($cancelled.Cancelled -and $cancelled.Results.Count -eq 0) 'scanner cancellation before discovery is read-only'
$scanFixture=Invoke-EloJavaScan -DriveRoots @() -ManualPath 'C:\fixture space' -IsReparsePoint { $false } -GetChildren {
    param($Path)
    Assert ($Path -ceq 'C:\fixture space') 'literal scanner path with spaces'
    [pscustomobject]@{Name='java.exe';FullName='C:\fixture space\java.exe';PSIsContainer=$false;Attributes=0}
} -ProbeJava {
    param($Path,$Cancel)
    [pscustomobject]@{Succeeded=$true;Cancelled=$false;Evidence='Temurin Runtime Environment (build 17.0.20+1)';Error=$null;ExitCode=0}
}
Assert ($scanFixture.Results.Count -eq 1 -and $scanFixture.Results[0].Status -ceq 'PotentiallyVulnerable') 'scanner joins literal discovery and classification using mock probe'
$zuluScan=Invoke-EloJavaScan -DriveRoots @() -ManualPath 'C:\fixture' -IsReparsePoint { $false } -GetChildren {
    [pscustomobject]@{Name='java.exe';FullName='C:\fixture\java.exe';PSIsContainer=$false;Attributes=0}
} -ProbeJava {
    [pscustomobject]@{Succeeded=$true;Cancelled=$false;Evidence='OpenJDK Runtime Environment Zulu21.30+15-CA (build 21.0.1+12-LTS)';Error=$null;ExitCode=0}
}
Assert ($zuluScan.Results[0].Vendor -ceq 'Azul Zulu' -and $zuluScan.Results[0].Status -ceq 'Inconclusive') 'packaged scanner identifies Zulu without advisory classification'
$cliZulu=Invoke-EloCli -Arguments @('--cli','--scan','--json') -Scanner { param($ManualPath) $zuluScan }
$cliZuluJson=ConvertFrom-Json $cliZulu.Output
Assert ($cliZulu.ExitCode -eq 0 -and $cliZuluJson.scan.Results[0].Vendor -ceq 'Azul Zulu' -and $cliZuluJson.scan.Results[0].Status -ceq 'Inconclusive') 'CLI JSON preserves Zulu and inconclusive result'
$zuluSession=New-EloServerSession -Port 49151 -UiHtml 'fixture' -ScanSource 'fixture'
$zuluSession.Adapters.Resources={ @{ServerName='TEST';WindowsVersion='10.0';WindowsBuild='20348';TotalRamBytes=8GB;Disks=@(@{Name='C:';TotalBytes=100GB;FreeBytes=40GB})} }
ConvertTo-EloUiResults $zuluSession $zuluScan
Assert ($zuluSession.Results[0].vendor -ceq 'Azul Zulu' -and $zuluSession.Results[0].status -ceq 'inconclusive') 'web results preserve Zulu and inconclusive status'
foreach ($lang in @('en','de')) {
    $zuluHtml=Get-EloSessionReportHtml $zuluSession $lang
    Assert ($zuluHtml.Contains('Azul Zulu') -and $zuluHtml.Contains('21.0.1+12-LTS') -and -not $zuluHtml.Contains('https://adoptium.net/installation/')) 'technical report preserves Zulu without Temurin replacement guidance'
}
$fixtureRoot = Join-Path $PSScriptRoot 'integration-fixtures'
$run = Join-Path $fixtureRoot ([guid]::NewGuid().ToString('N'))
$oldTemp=$env:TEMP; $oldTmp=$env:TMP
try {
    [void][IO.Directory]::CreateDirectory($run)
    $env:TEMP=$run; $env:TMP=$run
    # Copy only the BAT: no development sources beside the executable.
    $standalone = Join-Path $run 'tool space & percent%PATH% unicode-路径-ä'
    [void][IO.Directory]::CreateDirectory($standalone)
    $copy = Join-Path $standalone 'ELO Patch Tools.bat'
    [IO.File]::WriteAllText($copy,$source,(New-Object Text.UTF8Encoding($false)))
    function Invoke-Bat([string]$Path,[string]$Arguments) {
        $p=New-Object Diagnostics.Process
        try {
            $info=New-Object Diagnostics.ProcessStartInfo
            $info.FileName=$env:ComSpec
            # The path is an environment variable to avoid a second percent expansion.
            $info.EnvironmentVariables['ELO_TEST_BAT']=$Path
            $info.Arguments='/d /s /c ""%ELO_TEST_BAT%" '+$Arguments+'"'
            $info.UseShellExecute=$false; $info.CreateNoWindow=$true
            $info.RedirectStandardOutput=$true; $info.RedirectStandardError=$true
            $p.StartInfo=$info
            Assert ($p.Start()) 'BAT process starts'
            $out=$p.StandardOutput.ReadToEndAsync(); $err=$p.StandardError.ReadToEndAsync()
            if (-not $p.WaitForExit(30000)) { $p.Kill(); throw 'BAT fixture timed out' }
            [pscustomobject]@{Code=$p.ExitCode;Out=$out.Result;Err=$err.Result}
        } finally { $p.Dispose() }
    }
    function Assert-Clean {
        Assert (@([IO.Directory]::GetDirectories($run,'elo-patch-*')).Count -eq 0) 'extraction cleaned'
    }
    $help=Invoke-Bat $copy '--help'
    Assert ($help.Code -eq 0 -and $help.Out -match 'built-in README') 'standalone BAT --help'
    Assert ($help.Out.Contains('ready fixed or removable drives C: through Z:') -and $help.Out.Contains('\java\bin\java.exe') -and $help.Out.Contains('\ELO\java\bin\java.exe') -and $help.Out.Contains('after root checks')) 'packaged help describes exact discovery and manual order'
    Assert ($help.Out -match 'Technical HTML report' -and $help.Out -match 'ELO version remains unknown') 'single-file help explains technical report and API boundary'
    Assert ($help.Out -notmatch '#token=' -and $help.Err -notmatch '#token=') 'no launch token in console'
    Assert-Clean
    # A Unicode TEMP path must not be round-tripped through the OEM console code page.
    $env:TEMP=$standalone; $env:TMP=$standalone
    $unicodeTemp=Invoke-Bat $copy '--help'
    Assert ($unicodeTemp.Code -eq 0 -and $unicodeTemp.Out -match 'built-in README') 'Unicode/metacharacter TEMP extraction path survives cmd routing'
    Assert (@([IO.Directory]::GetDirectories($standalone,'elo-patch-*')).Count -eq 0) 'Unicode TEMP extraction cleaned'
    $env:TEMP=$run; $env:TMP=$run
    $manual=Invoke-Bat $copy '--cli --manual --json'
    $json=ConvertFrom-Json $manual.Out
    Assert ($manual.Code -eq 0 -and $json.readme -match '--update-runtime') 'BAT CLI JSON/manual without scan'
    Assert-Clean
    $update=Invoke-Bat $copy '--cli --update-runtime --json'
    $json=ConvertFrom-Json $update.Out
    Assert ($update.Code -eq 2 -and $json.error -match 'requires --target') 'runtime update without explicit flags fails closed'
    Assert-Clean
    $headless=Invoke-Bat $copy '--no-browser'
    Assert ($headless.Code -ne 0 -and $headless.Err -match 'no_browser_requires_private_launch_handler') 'web no-browser explicitly refuses unsafe delivery'
    Assert-Clean
    $retained=Invoke-Bat $copy '--help --keep-temp'
    $dirs=@([IO.Directory]::GetDirectories($run,'elo-patch-*'))
    Assert ($retained.Code -eq 0 -and $dirs.Count -eq 1) 'keep-temp retains exactly one extraction'
    foreach ($name in $resources.Keys) {
        $file=Join-Path $dirs[0] $resources[$name]
        Assert ([IO.File]::Exists($file)) "extracted $name"
        $actual=[IO.File]::ReadAllText($file,[Text.Encoding]::UTF8).TrimEnd("`r", "`n")
        Assert (($actual -replace "`r`n", "`n") -ceq ($blocks[$name] -replace "`r`n", "`n")) "UTF-8 extraction $name"
    }
    # Load the actual packaged backend with trusted mocks; no test switches in production.
    . (Join-Path $dirs[0] 'backend.ps1') -LoadOnly
    function Invoke-EloJavaScan {
        param($ManualPath,$DriveRoots)
        Assert ($ManualPath -ceq 'C:\ELO data') 'manual path survives routing'
        [pscustomobject]@{Results=@();Cancelled=$false}
    }
    $r=Invoke-EloPackagedTool -Arguments @('--cli','--scan','--json','--manual-path','C:\ELO data')
    Assert ($r.ExitCode -eq 0 -and (ConvertFrom-Json $r.Output).scan.Cancelled -eq $false) 'actual CLI scanner adapter JSON'
    $script:webCalls=0
    function Start-EloServer {
        param($UiHtml,$ScanSource,[switch]$NoBrowser)
        $script:webCalls++
        Assert ($UiHtml -match '<meta charset="utf-8">' -and $ScanSource -match 'function Invoke-EloJavaScan') 'packaged web resources'
    }
    $r=Invoke-EloPackagedTool -Arguments @()
    Assert ($r.ExitCode -eq 0 -and $script:webCalls -eq 1) 'default routes to web'
    $r=Invoke-EloPackagedTool -Arguments @('--scan')
    Assert ($r.ExitCode -eq 2 -and $script:webCalls -eq 1) 'web rejects unsupported options rather than silently scanning'
    # Actual CLI bridge must not serialize its private session/preview capabilities.
    $target=[pscustomobject]@{
        Location='C:\ELO data\jre\bin\java.exe'; RuntimeRoot='C:\ELO data\jre'
        RuntimeRootRationale='Fixture only'; EloPathRationale='Isolated fixture, not ELO'
        Status='PotentiallyVulnerable'; Vendor='Temurin'; FullVersion='17.0.20+1'
        Build='17.0.20+1'; Architecture='x64'; Reason='Fixture only'
        Evidence='Fixture evidence'; Error=$null; Source='fixture'
    }
    $script:cliTarget=$target
    function Invoke-EloJavaScan {
        param($ManualPath,$DriveRoots)
        [pscustomobject]@{Results=@($script:cliTarget);Cancelled=$false}
    }
    $script:cliFixtureSession=New-EloServerSession -Port 49152 -UiHtml 'fixture' -ScanSource 'fixture'
    $script:cliFixtureSession.Adapters=@{
        Admin={ $true }; ReadOptions={ @{Exists=$true;Value='-Xmx1g';Kind='String'} }
        Fingerprint={ param($Path) 'fixture' }; Clock={ [DateTime]::UtcNow }
        WriteOptions={ throw 'unexpected real action' }; Verify={ throw 'unexpected probe' }
    }
    function New-EloServerSession { param($Port,$UiHtml,$ScanSource) $script:cliFixtureSession }
    function New-EloCliConsole {
        @{IsInteractive={ $false };Write={ throw 'unexpected console' };ReadLine={ throw 'unexpected prompt' }}
    }
    $r=Invoke-EloPackagedTool -Arguments @('--cli','--mitigate','--target','0','--confirm-admin','--confirm-mitigation','--json')
    $report=ConvertFrom-Json $r.Output
    Assert ($r.ExitCode -eq 1 -and $report.error -match 'noninteractive') 'actual CLI mitigation bridge refuses headless confirmation'
    Assert ($null -ne $script:cliFixtureSession.Preview) 'actual backend preview created read-only'
    Assert (-not $r.Output.Contains($script:cliFixtureSession.Preview.Id)) 'private preview token never printed in CLI JSON'
    Assert (-not $r.Output.Contains($script:cliFixtureSession.Token)) 'session token never printed in CLI JSON'
    foreach ($id in $script:cliFixtureSession.Targets.Keys) {
        Assert (-not $r.Output.Contains($id)) 'private target capability never printed in CLI JSON'
    }
    # Reload the server after the routing mock, then exercise parsed HTTP requests.
    . ([scriptblock]::Create($blocks.SERVER_PS))
    $session=New-EloServerSession -Port 49152 -UiHtml $blocks.UI_HTML -ScanSource $blocks.SCAN_PS
    $script:writes=0; $script:probes=0
    $session.Adapters=@{
        Admin={ $true }; ReadOptions={ @{Exists=$true;Value='-Xmx1g';Kind='String'} }
        WriteOptions={ param($Value) $script:writes++; throw 'unexpected write' }
        Fingerprint={ param($Path) 'fixture-fingerprint' }
        Verify={ param($Path,$Options) $script:probes++; throw 'unexpected probe' }
        Clock={ [DateTime]::UtcNow }
    }
    function Request([string]$Method,[string]$Target,[string]$Body='', [string]$Token=$session.Token,[string]$Origin=$session.Origin) {
        $bytes=[Text.Encoding]::UTF8.GetBytes($Body)
        $head="$Method $Target HTTP/1.1`r`nHost: 127.0.0.1:49152`r`nOrigin: $Origin`r`nX-Session-Token: $Token`r`nContent-Type: application/json`r`nContent-Length: $($bytes.Length)`r`n`r`n"
        $stream=New-Object IO.MemoryStream
        try {
            $prefix=[Text.Encoding]::ASCII.GetBytes($head)
            $stream.Write($prefix,0,$prefix.Length); $stream.Write($bytes,0,$bytes.Length); $stream.Position=0
            $request=Read-EloHttpRequest $stream '127.0.0.1'
            try { @{Status=200;Body=(Invoke-EloApi $session $request)} }
            catch { ConvertTo-EloErrorResponse $_.Exception }
        } finally { $stream.Dispose() }
    }
    # Actual extracted report module, scanner mapping, API route and serialization.
    # Resource adapter stays in memory; no CIM, credentials, browser or Java here.
    $session.Adapters.Resources={ @{ServerName='FIXTURE-SERVER';WindowsVersion='10.0';WindowsBuild='20348';TotalRamBytes=8GB;Disks=@(@{Name='C:';TotalBytes=100GB;FreeBytes=40GB})} }
    foreach ($language in @('en','de')) {
        $response=Request POST '/api/report' ('{"language":"'+$language+'"}')
        Assert ($response.Status -eq 200 -and $response.Body.html.Contains('<html lang="'+$language+'">')) 'packaged bilingual HTML report route'
        Assert ($response.Body.html.Contains('FIXTURE-SERVER') -and $response.Body.html.Contains('40.00 GiB')) 'packaged report resources'
        Assert ($response.Body.html -notmatch '<script|#token=|X-Session-Token') 'safe packaged HTML'
    }
    $response=Request POST '/api/report' '{"language":"en"}' ('0'*64)
    Assert ($response.Status -eq 401) 'packaged report authentication required'
    $response=Request POST '/api/report' '{"language":"en","password":"secret"}'
    Assert ($response.Status -eq 400) 'credentials rejected by report route'
    $response=Request GET '/api/status'
    Assert ($response.Status -eq 200 -and $response.Body.state -ceq 'idle') 'actual parsed GET status contract'
    $response=Request GET '/api/results'
    Assert ($response.Status -eq 200 -and $response.Body.ContainsKey('security')) 'actual results metadata contract'
    $response=Request GET '/api/status' '' ('0'*64)
    Assert ($response.Status -eq 401 -and $response.Body.error -ceq 'authentication_required') 'token required'
    $response=Request POST '/api/cancel' '{}' $session.Token 'http://evil.invalid'
    Assert ($response.Status -eq 403) 'cross-origin rejected'
    $response=Request POST '/api/cancel' '{}'
    Assert ($response.Status -eq 200 -and $response.Body.ok) 'cancel request contract'
    $response=Request POST '/api/preview' '{"actionId":"update-runtime","resultId":"fixture"}'
    Assert ($response.Status -eq 409 -and $response.Body.error -cin @('target_not_eligible','completed_scan_required')) 'HTTP runtime update refuses an unknown target before any change'
    $response=Request POST '/api/scan' '{"searchPath":"relative"}'
    Assert ($response.Status -eq 400) 'invalid manual path rejected before scan'
    $response=Request POST '/api/scan' '{"searchPath":"C:\\safe","searchPath":"C:\\other"}'
    Assert ($response.Status -eq 400) 'duplicate JSON keys rejected'
    # A trusted in-memory scan worker substitutes only discovery, keeping actual API routing.
    function Start-EloScanWorker {
        param($Session,$ManualPath)
        Assert ($ManualPath -ceq $run) 'HTTP searchPath remains literal data'
        $Session.State='scanning'
    }
    $body=@{searchPath=$run} | ConvertTo-Json -Compress
    $response=Request POST '/api/scan' $body
    Assert ($response.Status -eq 200 -and $session.State -ceq 'scanning') 'actual POST scan contract using isolated directory'
    Assert ($script:writes -eq 0 -and $script:probes -eq 0) 'no privileged writes or Java probes'
    # End-to-end preview/action contract, using only in-memory machine/probe adapters.
    $script:machine=@{Exists=$true;Value='-Xmx1g -Dfixture="space value"';Kind='ExpandString'}
    $original=$script:machine.Clone()
    $script:failProbe=0; $script:fakeWrites=0; $script:fakeProbes=0
    $session.Adapters.ReadOptions={ $script:machine.Clone() }
    $session.Adapters.WriteOptions={ param($Value) $script:fakeWrites++; $script:machine=$Value.Clone() }
    $session.Adapters.Verify={ param($Path,$Options) $script:fakeProbes++; $script:fakeProbes -ne $script:failProbe }
    ConvertTo-EloUiResults $session ([pscustomobject]@{Results=@($target)})
    $session.State='completed'
    $id=@($session.Targets.Keys)[0]
    function Preview-Mitigation {
        Request POST '/api/preview' (@{actionId='mitigate';resultId=$id} | ConvertTo-Json -Compress)
    }
    function Apply-Mitigation($View) {
        Request POST '/api/action' (@{actionId='mitigate';resultId=$id;previewId=$View.Body.previewId} | ConvertTo-Json -Compress)
    }
    $view=Preview-Mitigation
    Assert ($view.Status -eq 200 -and $view.Body.summary.ContainsKey('en') -and $view.Body.summary.ContainsKey('de')) 'actual bilingual mitigation preview contract'
    Assert ($view.Body.summary.en.Contains($original.Value) -and $view.Body.summary.en.Contains('-XX:-UseBASE64Intrinsics')) 'preview discloses exact old/new options'
    Assert ($script:fakeWrites -eq 0 -and $script:fakeProbes -eq 0) 'preview has no write or disposable JVM side effects'
    $applied=Apply-Mitigation $view
    Assert ($applied.Status -eq 200 -and $applied.Body.ok) 'actual action contract succeeds with in-memory adapters'
    Assert ($script:machine.Value -ceq ($original.Value+' -XX:-UseBASE64Intrinsics') -and $script:machine.Kind -ceq $original.Kind) 'pre-existing options and registry type preserved'
    Assert ((Test-EloSameOptions $session.Backup $original) -and $script:fakeWrites -eq 1 -and $script:fakeProbes -eq 2) 'exact backup plus before/after verification'
    $technical=Request POST '/api/report' '{"language":"en"}'
    Assert ($technical.Body.html.Contains('Machine option set: Verified') -and $technical.Body.html.Contains('Newly launched JVM flag: Verified')) 'actual mitigation postconditions mapped separately'
    Assert ($technical.Body.html.Contains('Current running ELO process flag: Unknown / unavailable')) 'disposable probe is not running ELO evidence'
    Assert ($technical.Body.html.Contains('Runtime update: Not performed') -and $technical.Body.html.Contains('Backup: Not performed')) 'no invented update or runtime backup'
    Assert (-not $technical.Body.html.Contains($original.Value)) 'raw JVM options not in sanitized report'
    Assert (-not $technical.Body.html.Contains('Temporary mitigation: Unknown / unavailable')) 'successful attempt has no contradictory unknown placeholder'
    $technicalDe=Request POST '/api/report' '{"language":"de"}'
    Assert ($technicalDe.Body.html.Contains('Maschinenoption gesetzt: Nachgewiesen') -and $technicalDe.Body.html.Contains('Flag des aktuell laufenden ELO-Prozesses: Unbekannt / nicht verfuegbar')) 'German scope claims remain independent'
    $replay=Apply-Mitigation $view
    Assert ($replay.Status -eq 409 -and $script:fakeWrites -eq 1) 'single-use preview replay rejected'
    $view=Preview-Mitigation
    $script:machine.Value='-Xmx2g'
    $stale=Apply-Mitigation $view
    Assert ($stale.Status -eq 409 -and $stale.Body.error -ceq 'stale_preview' -and $script:fakeWrites -eq 1) 'changed settings invalidate preview before writes'
    $script:machine=$original.Clone(); $script:fakeWrites=0; $script:fakeProbes=0
    $script:failProbe=1
    $view=Preview-Mitigation; $failed=Apply-Mitigation $view
    Assert ($failed.Status -eq 422 -and $failed.Body.error -ceq 'probe_failed_no_change' -and $script:fakeWrites -eq 0) 'unsupported JVM option refuses any write'
    $script:fakeProbes=0; $script:failProbe=2
    $view=Preview-Mitigation; $failed=Apply-Mitigation $view
    Assert ($failed.Status -eq 422 -and $failed.Body.error -ceq 'verification_failed_rolled_back') 'failed post-write probe reports rollback'
    Assert ((Test-EloSameOptions $script:machine $original) -and $script:fakeWrites -eq 2) 'rollback restores exact previous value and type in mock only'
    $technical=Request POST '/api/report' '{"language":"en"}'
    Assert ($technical.Body.html.Contains('Temporary mitigation: Failed') -and -not $technical.Body.html.Contains('Machine option set: Verified')) 'failed retry invalidates prior machine-option success'
    $script:fakeProbes=0; $script:failProbe=0
    $view=Preview-Mitigation
    $session.Preview.Expires=[DateTime]::UtcNow.AddMinutes(-1)
    $expired=Apply-Mitigation $view
    Assert ($expired.Status -eq 409 -and $expired.Body.error -ceq 'preview_expired_or_mismatched') 'expired preview cannot reach mock writes'
    $session.Adapters.Admin={ $false }
    $denied=Preview-Mitigation
    Assert ($denied.Status -eq 403 -and $denied.Body.error -ceq 'administrator_required' -and $denied.Body.warnings.Count -gt 0) 'administrator failure uses bilingual warnings, not auth error'
    $session.Adapters.Admin={ $true }
    # Exercise the CLI adapter's private public-preview mapping on a successful mock action.
    $script:fakeWrites=0; $script:fakeProbes=0; $script:failProbe=0
    $cliSession=New-EloServerSession -Port 49153 -UiHtml 'fixture' -ScanSource 'fixture'
    $cliSession.Adapters=$session.Adapters
    $cliActions=New-EloPackagedCliActions $cliSession
    $script:previewText=$null; $script:readAfterPreview=$false
    $console=@{
        IsInteractive={ $true }
        Write={ param($Text) $script:previewText=$Text }
        ReadLine={ $script:readAfterPreview=($script:previewText -match 'APPLY MITIGATION'); 'APPLY MITIGATION' }
    }
    $cliResult=Invoke-EloCli -Arguments @('--cli','--mitigate','--target','0','--confirm-admin','--confirm-mitigation','--json') -Scanner {
        param($ManualPath) [pscustomobject]@{Results=@($script:cliTarget);Cancelled=$false}
    } -Actions $cliActions -Console $console
    $cliReport=ConvertFrom-Json $cliResult.Output
    Assert ($cliResult.ExitCode -eq 0 -and $cliReport.action.result.ok -and $script:readAfterPreview) 'actual CLI adapters apply only after mock console preview and exact consent'
    Assert ($null -eq $cliReport.action.preview.PreviewId -and $null -eq $cliReport.action.preview.View) 'public CLI report has no backend capabilities'
    Assert ($script:writes -eq 0 -and $script:probes -eq 0) 'all real machine/probe sentinels remain unused'
    $beforeDenial=$script:fakeWrites
    $deniedSession=New-EloServerSession -Port 49154 -UiHtml 'fixture' -ScanSource 'fixture'
    $deniedSession.Adapters=$session.Adapters
    $console.ReadLine={ 'NO' }
    $deniedCli=Invoke-EloCli -Arguments @('--cli','--mitigate','--target','0','--confirm-admin','--confirm-mitigation','--json') -Scanner {
        param($ManualPath) [pscustomobject]@{Results=@($script:cliTarget);Cancelled=$false}
    } -Actions (New-EloPackagedCliActions $deniedSession) -Console $console
    Assert ($deniedCli.ExitCode -eq 1 -and $script:fakeWrites -eq $beforeDenial) 'CLI denial cannot apply even with both confirmation flags'
    # Wire response encoding and launch failures must not expose capability URIs.
    $wire=New-Object IO.MemoryStream
    try {
        Write-EloHttpResponse $wire 200 '{"message":"Grüße"}'
        $raw=[Text.Encoding]::UTF8.GetString($wire.ToArray())
        $parts=$raw -split "`r`n`r`n",2
        Assert ($parts[0] -match 'charset=utf-8' -and $parts[1] -ceq '{"message":"Grüße"}') 'actual HTTP response preserves UTF-8'
        $length=[Text.Encoding]::UTF8.GetByteCount($parts[1])
        Assert ($parts[0].Contains("Content-Length: $length`r`n")) 'HTTP content length counts UTF-8 bytes'
        Assert ($raw -notmatch '#token=') 'no capability URI in HTTP response'
    } finally { $wire.Dispose() }
    $script:launchUri=$null
    $launchOutput=@(Invoke-EloSessionLaunch $session -NoBrowser -LaunchHandler {
        param($Uri) $script:launchUri=$Uri; 'suppressed launch output'
    })
    Assert ($launchOutput.Count -eq 0 -and $script:launchUri -ceq ($session.Origin+'/#token='+$session.Token)) 'trusted private handler receives URI without console output'
    try { Invoke-EloSessionLaunch $session -BrowserLauncher { param($Uri) throw $Uri }; throw 'missing launch failure' }
    catch {
        $failure=ConvertTo-EloErrorResponse $_.Exception
        Assert ($failure.Body.error -ceq 'browser_launch_failed' -and -not (($failure.Body | ConvertTo-Json).Contains($session.Token))) 'browser exception URI is redacted to stable error'
    }
    $html=$blocks.UI_HTML
    Assert ($html.Contains('ready fixed or removable drives C: through Z:') -and $html.Contains('bereiten festen oder Wechsellaufwerken C: bis Z:') -and $html.Contains('X:\\java\\bin\\java.exe') -and $html.Contains('X:\\ELO\\java\\bin\\java.exe')) 'packaged bilingual UI describes exact drive layouts'
    Assert ($html.Contains('POST scan -> {} checks ready fixed or removable drives C: through Z:') -and $html.Contains('after the root checks')) 'packaged UI contract describes root checks and manual order'
    Assert ($html -match "X-Session-Token" -and $html -match 'history.replaceState' -and $html -match "api\('preview',\{actionId,resultId:row.id\}\)") 'UI uses existing auth and preview request contract'
    # Test extractor failure paths through the real BAT, not a parallel parser.
    foreach ($case in @('duplicate','nested','missing','malformed','unmatched')) {
        $bad=$source
        switch ($case) {
            duplicate { $bad += "`r`n::ELO_PATCH_BEGIN:UI_HTML`r`nextra`r`n::ELO_PATCH_END:UI_HTML`r`n" }
            nested { $bad=$bad.Replace('::ELO_PATCH_BEGIN:SCAN_PS',"::ELO_PATCH_BEGIN:SCAN_PS`r`n::ELO_PATCH_BEGIN:UI_HTML") }
            missing { $bad=$bad.Replace('::ELO_PATCH_END:UI_HTML','') }
            malformed { $bad=$bad.Replace('::ELO_PATCH_BEGIN:UI_HTML','::ELO_PATCH_BEGIN:UNKNOWN') }
            unmatched { $bad=$bad.Replace('::ELO_PATCH_END:UI_HTML','::ELO_PATCH_END:SCAN_PS') }
        }
        $path=Join-Path $standalone ($case+'.bat')
        [IO.File]::WriteAllText($path,$bad,(New-Object Text.UTF8Encoding($false)))
        $r=Invoke-Bat $path '--help'
        Assert ($r.Code -ne 0 -and $r.Out -notmatch 'built-in README') "extractor rejects $case"
    }
    Write-Output "PASS: $checks deterministic integration assertions. No live ELO changes."
} finally {
    $env:TEMP=$oldTemp; $env:TMP=$oldTmp
    # Only this test's GUID-owned fixture tree; never the caller's TEMP or ELO.
    if ([IO.Directory]::Exists($run)) { [IO.Directory]::Delete($run,$true) }
}
