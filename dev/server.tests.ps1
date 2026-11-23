$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\server.ps1"
. "$PSScriptRoot\scan.ps1"
. "$PSScriptRoot\cli.ps1"
$script:Count = 0
function Assert($Condition, $Message) { if (-not $Condition) { throw "FAIL: $Message" }; $script:Count++ }
function Reject([scriptblock]$Work, [int]$Status) {
    try { & $Work; throw 'Expected rejection' } catch { Assert ($_.Exception.Data['Status'] -eq $Status) "Expected HTTP $Status, got $($_.Exception.Message)" }
}
$s = New-EloServerSession -Port 54321 -UiHtml '<!doctype html>' -ScanSource 'function Invoke-EloJavaScan { param($DriveRoots,$ManualPath,$ShouldCancel) [pscustomobject]@{ Results=@(); Cancelled=(& $ShouldCancel) } }'
Assert ($s.Token -cmatch '^[a-f0-9]{64}$') '256-bit session token'
Assert ($s.Token -cne (New-EloSecret)) 'independent random secrets'
function Request($Method='GET', $Path='/api/status', $Body='', $Headers=$null, $Remote='127.0.0.1') {
    if ($null -eq $Headers) { $Headers = @{Host='127.0.0.1:54321'; 'X-Session-Token'=$s.Token; Origin=$s.Origin; 'Content-Type'='application/json'} }
    [pscustomobject]@{Method=$Method; Target=$Path; Headers=$Headers; Body=$Body; Remote=$Remote}
}
. "$PSScriptRoot\report.ps1"
$s.Adapters.Resources={ @{ServerName='TEST-SERVER';WindowsVersion='10.0';WindowsBuild='20348';TotalRamBytes=8GB;Disks=@(@{Name='C:';TotalBytes=100GB;FreeBytes=40GB})} }
$s.Adapters.ReportOptions={ @{Machine='-XX:-UseBASE64Intrinsics password=secret-fixture';User='-XX:+UseBASE64Intrinsics';Process='-XX:-UseBASE64Intrinsics'} }
foreach ($lang in @('en','de')) {
    $technical=Invoke-EloApi $s (Request POST '/api/report' ('{"language":"'+$lang+'"}'))
    Assert ($technical.html.Contains('<html lang="'+$lang+'">')) 'technical report language'
    Assert ($technical.html.Contains($(if ($lang -eq 'en') {'Machine: Flag present'} else {'Machine: Flag vorhanden'})) -and $technical.html.Contains($(if ($lang -eq 'en') {'User: Conflicting enabling flag present'} else {'User: Konfligierendes aktivierendes Flag vorhanden'}))) 'authenticated report observes scoped options'
    Assert ($technical.html.Contains($(if ($lang -eq 'en') {'Process: Flag present'} else {'Process: Flag vorhanden'}))) 'process option presence reported'
    Assert ($technical.html.Contains($(if ($lang -eq 'en') {'Environment values do not prove protection of existing ELO processes.'} else {'Umgebungswerte beweisen keinen Schutz bestehender ELO-Prozesse.'}))) 'option presence does not claim ELO process protection'
    Assert (-not $technical.html.Contains('secret-fixture')) 'authenticated report excludes option secrets'
    Assert ($technical.html.Contains('TEST-SERVER') -and $technical.html.Contains('8.00 GiB') -and $technical.html.Contains('40.00 GiB')) 'technical report resources'
    Assert ($technical.html -notmatch 'X-Session-Token|#token=|<script') 'report excludes capabilities and active content'
    Assert ($technical.html.Contains($(if ($lang -eq 'en') {'Session scan state: Ready'} else {'Scanstatus der Sitzung: Bereit'}))) 'session state, not implied completion'
}
Reject { Invoke-EloApi $s (Request POST '/api/report' '{"language":"en","password":"secret"}') } 400
Reject { Invoke-EloApi $s (Request POST '/api/report' '{"language":"<script>"}') } 400
Reject { Invoke-EloApi $s (Request POST '/api/report' '{"language":"en"}' -Headers @{Host='127.0.0.1:54321';Origin=$s.Origin;'Content-Type'='application/json'}) } 401
Reject { Invoke-EloApi $s (Request GET '/api/report') } 405
Reject { Invoke-EloApi $s (Request POST '/api/report?language=en' '{}') } 404
$evidenceSession=New-EloServerSession -Port 54322 -UiHtml 'fixture' -ScanSource 'fixture'
$evidenceSession.Adapters.Resources=$s.Adapters.Resources
$scan=Invoke-EloJavaScan -DriveRoots @() -ManualPath 'C:\fixture' -IsReparsePoint { $false } -GetChildren {
    [pscustomobject]@{Name='java.exe';FullName='C:\fixture\java.exe';PSIsContainer=$false;Attributes=0}
} -ProbeJava {
    [pscustomobject]@{Succeeded=$true;Cancelled=$false;Evidence='Temurin Runtime Environment (build 17.0.20+1)';Error=$null;ExitCode=0}
}
ConvertTo-EloUiResults $evidenceSession $scan
Assert ($evidenceSession.ReportJvms[0].Classification -ceq 'PotentiallyVulnerable' -and $evidenceSession.ReportJvms[0].VendorVerified) 'actual scanner probe maps classification and vendor'
foreach ($language in @('en','de')) {
    $html=Get-EloSessionReportHtml $evidenceSession $language
    Assert ($html.Contains('17.0.20+1') -and $html.Contains('https://adoptium.net/installation/')) 'verified vendor guidance and actual version'
    Assert (-not $html.Contains('C:\fixture') -and -not $html.Contains('Runtime Environment')) 'no paths or raw probe output in report'
}
$zuluScan=Invoke-EloJavaScan -DriveRoots @() -ManualPath 'C:\fixture' -IsReparsePoint { $false } -GetChildren {
    [pscustomobject]@{Name='java.exe';FullName='C:\fixture\java.exe';PSIsContainer=$false;Attributes=0}
} -ProbeJava {
    [pscustomobject]@{Succeeded=$true;Cancelled=$false;Evidence='OpenJDK Runtime Environment Zulu21.30+15-CA (build 21.0.1+12-LTS)';Error=$null;ExitCode=0}
}
$zuluCli=Invoke-EloCli -Arguments @('--cli','--scan','--json') -Scanner { param($ManualPath) $zuluScan }
$zuluCliJson=ConvertFrom-Json $zuluCli.Output
Assert ($zuluCli.ExitCode -eq 0 -and $zuluCliJson.scan.Results[0].Vendor -ceq 'Azul Zulu' -and $zuluCliJson.scan.Results[0].Status -ceq 'Inconclusive') 'CLI JSON retains Zulu and inconclusive status'
ConvertTo-EloUiResults $evidenceSession $zuluScan
Assert ($evidenceSession.Results[0].vendor -ceq 'Azul Zulu' -and $evidenceSession.Results[0].status -ceq 'inconclusive') 'Zulu shown without fixed classification in UI'
Assert ($evidenceSession.ReportJvms[-1].VendorVerified -and $evidenceSession.ReportJvms[-1].Vendor -ceq 'Azul Zulu' -and $evidenceSession.ReportJvms[-1].Classification -ceq 'Unknown') 'Zulu identity verified separately from classification'
foreach ($language in @('en','de')) { Assert ((Get-EloSessionReportHtml $evidenceSession $language).Contains('Azul Zulu')) 'Zulu identity included in technical report' }
$zuluScan.Results[0].ExitCode=1
ConvertTo-EloUiResults $evidenceSession $zuluScan
Assert (-not $evidenceSession.ReportJvms[-1].VendorVerified) 'failed Zulu probe does not verify vendor'
$zuluScan.Results[0].ExitCode=0; $zuluScan.Results[0].Status='KnownFixed'
ConvertTo-EloUiResults $evidenceSession $zuluScan
Assert ($evidenceSession.Results[0].status -ceq 'inconclusive' -and $evidenceSession.ReportJvms[-1].Classification -ceq 'Unknown') 'asserted Zulu fixed status is not proof'
$scan.Results[0].Evidence='Temurin Runtime Environment (build 17.0.21.1+2)'
$scan.Results[0].FullVersion='17.0.21.1+2'; $scan.Results[0].Build='17.0.21.1+2'; $scan.Results[0].Status='KnownFixed'
ConvertTo-EloUiResults $evidenceSession $scan
Assert ($evidenceSession.ReportJvms[-1].Classification -ceq 'Fixed') 'actual fixed advisory classification'
$scan.Results[0].ExitCode=1
ConvertTo-EloUiResults $evidenceSession $scan
Assert (-not $evidenceSession.ReportJvms[-1].Verified -and -not $evidenceSession.ReportJvms[-1].VendorVerified) 'failed probe cannot prove execution, vendor or classification'
$scan.Results[0].Evidence='<script>secret-fixture</script>'; $scan.Results[0].Vendor='Temurin'
ConvertTo-EloUiResults $evidenceSession $scan
Assert (-not $evidenceSession.ReportJvms[-1].VendorVerified -and $evidenceSession.ReportJvms[-1].Classification -ceq 'Unknown') 'asserted vendor/status without raw matching evidence is unknown'
$html=Get-EloSessionReportHtml $evidenceSession en
Assert (-not $html.Contains('secret-fixture')) 'injected raw evidence excluded'
$evidenceSession.Adapters.Resources={ throw 'secret-resource-error' }
$evidenceSession.State='cancelled'
$html=Get-EloSessionReportHtml $evidenceSession en
Assert ($html.Contains('Session scan state: Cancelled') -and -not $html.Contains('secret-resource-error')) 'cancelled scan and resource failure are safe'
$evidenceSession.Adapters.Resources={ @{ServerName='<script>secret-name</script>';WindowsVersion='bad';Disks=@()} }
$html=Get-EloSessionReportHtml $evidenceSession de
Assert (-not $html.Contains('secret-name') -and $html.Contains('Unbekannt / nicht verfuegbar')) 'resource injection sanitized in German'
$r = Invoke-EloApi -Session $s -Request (Request)
Assert ($r.state -eq 'idle') 'authenticated initial state'
Reject { Invoke-EloApi $s (Request -Remote '10.0.0.1') } 403
Reject { Invoke-EloApi $s (Request -Headers @{Host='localhost:54321';'X-Session-Token'=$s.Token}) } 403
Reject { Invoke-EloApi $s (Request -Headers @{Host='127.0.0.1:54321';'X-Session-Token'=$s.Token;Origin='https://evil.invalid'}) } 403
Reject { Invoke-EloApi $s (Request -Headers @{Host='127.0.0.1:54321'}) } 401
Reject { Invoke-EloApi $s (Request -Path '/api/status?token=bad') } 404
Reject { Invoke-EloApi $s (Request -Method 'DELETE') } 405
Reject { Invoke-EloApi $s (Request -Path '/api/cancel') } 405
Reject { Invoke-EloApi $s (Request -Headers @{Host='127.0.0.1:54321';'X-Session-Token'=$s.Token;'Sec-Fetch-Site'='cross-site'}) } 403
Reject { Invoke-EloApi $s (Request -Headers @{Host='127.0.0.1:54321';'X-Session-Token'= ('0'*64)}) } 401
Reject { Invoke-EloApi $s (Request -Method POST -Path /api/preview -Body '{"actionId":"mitigate","resultId":"../java.exe"}') } 400
Reject { Invoke-EloApi $s (Request -Method POST -Path /api/cancel -Body '{}' -Headers @{Host='127.0.0.1:54321';'X-Session-Token'=$s.Token;'Content-Type'='application/json'}) } 403
Reject { Invoke-EloApi $s (Request -Method POST -Path /api/cancel -Body '{"command":"whoami"}') } 400
Reject { Invoke-EloApi $s (Request -Method POST -Path /api/cancel -Body '[]') } 400
Reject { Invoke-EloApi $s (Request -Method POST -Path /api/cancel -Body '{"x":1,"x":2}') } 400
Reject { Invoke-EloApi $s (Request -Method POST -Path /api/cancel -Body '{}' -Headers @{Host='127.0.0.1:54321';'X-Session-Token'=$s.Token;Origin=$s.Origin;'Content-Type'='text/plain'}) } 415
foreach ($path in @('relative','\\server\share','C:\x\..\y','C:\NUL','C:\x*','C:\x:stream','C:\x.','C:/x',"C:\bad`npath")) { Reject { Test-EloLocalPath $path } 400 }
Assert ((Merge-EloJavaOptions '-Xmx1g -Dname="hello world"') -ceq '-Xmx1g -Dname="hello world" -XX:-UseBASE64Intrinsics') 'preserve options exactly'
Assert ((Merge-EloJavaOptions $null) -ceq '-XX:-UseBASE64Intrinsics') 'missing options'
Assert ((Merge-EloJavaOptions '') -ceq '-XX:-UseBASE64Intrinsics') 'empty options'
Reject { Merge-EloJavaOptions ('x'*1001) } 409
Assert ((Merge-EloJavaOptions '-Dpath=%LITERAL%') -ceq '-Dpath=%LITERAL% -XX:-UseBASE64Intrinsics') 'literal percent option preserved by parser'
Reject { Merge-EloJavaOptions "-Xmx1g`n-Dinjected=x" } 409
Assert ((Merge-EloJavaOptions '-XX:+UseBASE64Intrinsics') -ceq '-XX:-UseBASE64Intrinsics') 'conflicting flag replaced'
Assert ((Merge-EloJavaOptions '-XX:-UseBASE64Intrinsics') -ceq '-XX:-UseBASE64Intrinsics') 'already disabled flag remains exactly once'
Assert ((Merge-EloJavaOptions ' -Xmx1g  -XX:+UseBASE64Intrinsics -XX:-UseBASE64Intrinsics -Dlabel="UseBASE64Intrinsics" ') -ceq ' -Xmx1g    -Dlabel="UseBASE64Intrinsics"  -XX:-UseBASE64Intrinsics') 'remove only standalone duplicate/conflicting flags, preserve all other bytes'
Assert ((Merge-EloJavaOptions '-Dname="hello world" "-XX:+UseBASE64Intrinsics"') -ceq '-Dname="hello world"  -XX:-UseBASE64Intrinsics') 'quoted standalone flag removed'
Assert ((Merge-EloJavaOptions "-Dname='hello world'`t-Xmx1g") -ceq "-Dname='hello world'`t-Xmx1g -XX:-UseBASE64Intrinsics") 'single quoted values and tab separators preserved'
Reject { Merge-EloJavaOptions '-Dname="unterminated' } 409
Reject { Merge-EloJavaOptions '-Dname="ambiguous\"quote"' } 409
Reject { Merge-EloJavaOptions '-XX:UseBASE64Intrinsics=false' } 409
Reject { Merge-EloJavaOptions '-XX:+usebase64intrinsics' } 409
Assert (Test-EloFlagEvidence '     bool UseBASE64Intrinsics = false {product} {command line}') 'verify disabled flag'
Assert (-not (Test-EloFlagEvidence 'bool UseBASE64Intrinsics = true {product}')) 'enabled flag rejected'
Assert (-not (Test-EloFlagEvidence 'unknown flag')) 'missing flag rejected'
# Wire framing: exercise the real parser with deterministic in-memory bytes.
function Wire([string]$Text) {
    $stream=New-Object IO.MemoryStream(,[Text.Encoding]::UTF8.GetBytes($Text))
    try { Read-EloHttpRequest $stream '127.0.0.1' } finally { $stream.Dispose() }
}
$parsed=Wire "GET /api/status HTTP/1.1`r`nHost: 127.0.0.1:54321`r`n`r`n"
Assert ($parsed.Method -ceq 'GET' -and $parsed.Body -ceq '') 'parse HTTP request'
Reject { Wire "GET / HTTP/1.1`r`nHost: a`r`nHost: b`r`n`r`n" } 400
Reject { Wire "POST /api/cancel HTTP/1.1`r`nTransfer-Encoding: chunked`r`nContent-Length: 2`r`n`r`n{}" } 400
Reject { Wire "POST /api/cancel HTTP/1.1`r`nContent-Length: 8193`r`n`r`n" } 413
Reject { Wire "POST /api/cancel HTTP/1.1`r`nHost: x`r`n`r`n" } 411
Reject { Wire "POST /api/cancel HTTP/1.1`r`nContent-Length: 4`r`n`r`n{}" } 400
Reject { Wire "GET / HTTP/1.1`r`n folded: bad`r`n`r`n" } 400
Reject { Wire ("GET / HTTP/1.1`r`nX: "+('a'*16384)+"`r`n`r`n") } 431
Reject { Wire "GET http://evil/ HTTP/1.1`r`n`r`n" } 400
$wireResponse=New-Object IO.MemoryStream
try {
    Write-EloHttpResponse $wireResponse 200 '{"ok":true}'
    $raw=[Text.Encoding]::UTF8.GetString($wireResponse.ToArray())
    Assert ($raw.Contains('Connection: close') -and $raw.Contains('Cache-Control: no-store') -and $raw.Contains('frame-ancestors')) 'response security headers'
    Assert (-not $raw.Contains($s.Token)) 'response has no session token'
} finally { $wireResponse.Dispose() }

# Trusted in-memory adapters: never touch real environment or installed Java.
$script:Fake=@{Record=@{Exists=$true;Value='-Xmx1g -Dname="hello world"';Kind='ExpandString'};Admin=$true;Hash='original';Writes=0;Probes=0;FailProbe=0;FailWrite=$false;FailRollback=$false;Now=[DateTime]::UtcNow}
$s.Adapters=@{
    Admin={ $script:Fake.Admin }; Clock={ $script:Fake.Now }
    ReadOptions={ @{Exists=$script:Fake.Record.Exists;Value=$script:Fake.Record.Value;Kind=$script:Fake.Record.Kind} }
    WriteOptions={ param($Record)
        $script:Fake.Writes++
        if ($script:Fake.FailWrite -and $script:Fake.Writes -eq 1) { throw 'write failed' }
        if ($script:Fake.FailRollback -and $script:Fake.Writes -eq 2) { throw 'rollback failed' }
        $script:Fake.Record=@{Exists=$Record.Exists;Value=$Record.Value;Kind=$Record.Kind}
    }
    Fingerprint={ param($Path) $script:Fake.Hash }
    Verify={ param($Path,$Options) $script:Fake.Probes++; return $script:Fake.Probes -ne $script:Fake.FailProbe }
}
function Reset-Fake {
    $script:Fake.Record=@{Exists=$true;Value='-Xmx1g -Dname="hello world"';Kind='ExpandString'}
    $script:Fake.Admin=$true; $script:Fake.Hash='original'; $script:Fake.Writes=0; $script:Fake.Probes=0
    $script:Fake.FailProbe=0; $script:Fake.FailWrite=$false; $script:Fake.FailRollback=$false
    $s.Preview=$null; $s.State='completed'; $s.RecoveryRequired=$false; $s.Targets=@{jvm1=[pscustomobject]@{Location='C:\ELO data\jre\bin\java.exe';Status='PotentiallyVulnerable'}}
}
function Preview { Invoke-EloApi $s (Request POST /api/preview '{"actionId":"mitigate","resultId":"jvm1"}') }
function Apply($PreviewId) { Invoke-EloApi $s (Request POST /api/action ('{"actionId":"mitigate","resultId":"jvm1","previewId":"'+$PreviewId+'"}')) }
Reset-Fake
$p=Preview
Assert ($script:Fake.Writes -eq 0 -and $script:Fake.Probes -eq 0) 'preview is read-only'
Assert ($p.summary.en.Contains('MACHINE') -and $p.warnings[0].en.Contains('NOT protected')) 'honest scope and existing JVM warning'
Assert ($p.summary.en.Length -le 4096 -and $p.summary.de.Length -le 4096) 'preview meets UI limits'
$done=Apply $p.previewId
Assert ($done.ok -eq $true -and $script:Fake.Probes -eq 2 -and $script:Fake.Writes -eq 1) 'confirm probes before and after write'
Assert ($script:Fake.Record.Value -ceq '-Xmx1g -Dname="hello world" -XX:-UseBASE64Intrinsics') 'existing option bytes preserved'
Assert ($script:Fake.Record.Kind -ceq 'ExpandString' -and $s.Backup.Value -ceq '-Xmx1g -Dname="hello world"') 'registry kind and exact backup preserved'
Reject { Apply $p.previewId } 409
Reset-Fake; $script:Fake.Record.Value='-Xmx1g -XX:+UseBASE64Intrinsics -XX:-UseBASE64Intrinsics'; $p=Preview; $done=Apply $p.previewId
Assert ($script:Fake.Record.Value -ceq '-Xmx1g   -XX:-UseBASE64Intrinsics' -and $s.Backup.Value -ceq '-Xmx1g -XX:+UseBASE64Intrinsics -XX:-UseBASE64Intrinsics') 'deduplication preserves exact reversible original and registry kind'
Reset-Fake; $script:Fake.Record.Value='-Dpath=%EXPANSION%'
Reject { Preview } 409
Assert ($script:Fake.Writes -eq 0) 'ambiguous expandable environment fails closed before write'
Reset-Fake; $p=Preview; $script:Fake.Now=$script:Fake.Now.AddMinutes(3)
Reject { Apply $p.previewId } 409
Assert ($script:Fake.Writes -eq 0) 'expired preview never writes'
Reset-Fake; $p=Preview; $script:Fake.Hash='replaced'
Reject { Apply $p.previewId } 409
Reset-Fake; $p=Preview; $script:Fake.Record.Value='changed by another admin'
Reject { Apply $p.previewId } 409
Assert ($script:Fake.Writes -eq 0) 'concurrent configuration not overwritten'
Reset-Fake; $p=Preview; $script:Fake.Admin=$false
Reject { Apply $p.previewId } 403
Reset-Fake; $script:Fake.Admin=$false
Reject { Preview } 403
Reset-Fake; $script:Fake.Record=@{Exists=$false;Value=$null;Kind='String'}; $p=Preview; $script:Fake.FailProbe=2
Reject { Apply $p.previewId } 422
Assert (-not $script:Fake.Record.Exists -and $null -eq $script:Fake.Record.Value) 'rollback removes previously absent value'
Reset-Fake; $p=Preview; $script:Fake.FailProbe=1
Reject { Apply $p.previewId } 422
Assert ($script:Fake.Writes -eq 0) 'unsupported JVM never changes environment'
Reset-Fake; $p=Preview; $script:Fake.FailProbe=2
Reject { Apply $p.previewId } 422
Assert ($script:Fake.Writes -eq 2 -and $script:Fake.Record.Value -ceq '-Xmx1g -Dname="hello world"') 'failed post-write verification restores backup'
Reset-Fake; $p=Preview; $script:Fake.FailWrite=$true
Reject { Apply $p.previewId } 422
Assert ($script:Fake.Writes -eq 2) 'partial write failure attempts verified rollback'
Reset-Fake; $p=Preview; $script:Fake.FailProbe=2; $script:Fake.FailRollback=$true
Reject { Apply $p.previewId } 500
Assert ($s.State -ceq 'error') 'rollback failure freezes subsequent changes pending manual recovery'
$s.State='completed'
Reject { Preview } 409
Reject { Invoke-EloApi $s (Request -Path /api/results) } 500
Reset-Fake
foreach ($route in @('/api/preview','/api/action')) {
    $body='{"actionId":"update-runtime","resultId":"jvm1"}'
    if ($route -eq '/api/action') { $body='{"actionId":"update-runtime","resultId":"jvm1","previewId":"fake"}' }
    Reject { Invoke-EloApi $s (Request POST $route $body) } 503
}
Assert ($script:Fake.Writes -eq 0 -and $script:Fake.Probes -eq 0) 'updates never download/replace/execute anything'
Reset-Fake; $p=Preview
$other=New-EloServerSession -Port 54321 -UiHtml '<html>' -ScanSource '# none'
Reject { Invoke-EloMitigation $other ([pscustomobject]@{actionId='mitigate';resultId='jvm1';previewId=$p.previewId}) } 409
Reset-Fake; $p=Preview
Reject { Apply 'wrong' } 409
Reject { Apply $p.previewId } 409
Reset-Fake; $s.State='cancelled'
Reject { Preview } 409

# Evidence translation is complete-or-fail, never silently truncated or safe.
$fixture=[pscustomobject]@{Location='C:\ELO data\jre\bin\java.exe';EloCandidateRoot='C:\ELO data';RuntimeRoot='C:\ELO data\jre';Status='KnownFixed';Architecture='64-bit';FullVersion='17.0.21.1+2';Build='17.0.21.1+2';Source='https://adoptium.net/news/2026/11/temurin-november-2026-cspu-java4shell/';Vendor='Temurin';EloPathRationale='ELO-prefix heuristic only';Reason='Exact build in supplied rules';Evidence='openjdk version evidence'}
ConvertTo-EloUiResults $s ([pscustomobject]@{Results=@($fixture)})
Assert ($s.Results.Count -eq 1 -and $s.Results[0].status -ceq 'patched') 'exact parent-verified Temurin build maps to patched'
Assert ($s.Results[0].path -ceq $fixture.Location) 'result path identifies actual java.exe'
$security=(Invoke-EloApi $s (Request -Path /api/results)).security
Assert ($security.verifiedOn -ceq '2026-11-23' -and $security.advisories.Count -eq 3) 'parent-verified advisory date and complete metadata'
Assert ($security.advisories[0].title.en.Contains('user-supplied text') -and $security.advisories[0].title.en.Contains('not fetched')) 'OpenJDK provenance is not presented as a direct fetch'
Assert ($security.advisories[1].url -ceq 'https://linux.oracle.com/cve/CVE-2026-114938.html' -and $security.advisories[1].title.en.Contains('parent fetched directly')) 'Oracle direct-fetch provenance and exact URL'
Assert ($s.Results[0].classificationEvidence.en.Contains('no ELO compatibility') -and $s.Results[0].classificationEvidence.en.Contains('64-bit')) 'scope limitations and original architecture evidence preserved'
foreach ($advisory in $security.advisories) {
    Assert ($advisory.title.en.Length -le 256 -and $advisory.title.de.Length -le 256 -and $advisory.url.Length -le 512 -and $advisory.id -cmatch '^[A-Za-z0-9_-]{1,128}$') 'advisory shape respects HTML size limits'
}
foreach ($build in @('17.0.21.1+2','21.0.13.1+2','25.0.5.1+2','27.0.1.1+4')) {
    $fixture.Build=$build; $fixture.FullVersion=$build; $fixture.Architecture='ARM64'
    ConvertTo-EloUiResults $s ([pscustomobject]@{Results=@($fixture)})
    Assert ($s.Results[0].status -ceq 'patched' -and $s.Results[0].architecture -ceq 'arm64') 'only exact verified builds, architecture preserved'
}
$fixture.Build='27.0.1.1+5'; $fixture.FullVersion=$fixture.Build
ConvertTo-EloUiResults $s ([pscustomobject]@{Results=@($fixture)})
Assert ($s.Results[0].status -ceq 'inconclusive') 'later unverified build not declared patched'
$fixture.Build='17.0.21.1+2'; $fixture.FullVersion=$fixture.Build; $fixture.Vendor='Oracle'
ConvertTo-EloUiResults $s ([pscustomobject]@{Results=@($fixture)})
Assert ($s.Results[0].status -ceq 'inconclusive') 'other vendor not verified by Temurin advisory'
$fixture.Vendor='Temurin'; $fixture.Build='17.0.21.1+3'
ConvertTo-EloUiResults $s ([pscustomobject]@{Results=@($fixture)})
Assert ($s.Results[0].status -ceq 'inconclusive') 'conflicting build evidence not declared patched'
$fixture.Architecture='64-bit'
ConvertTo-EloUiResults $s ([pscustomobject]@{Results=@($fixture)})
Assert ($s.Results[0].architecture -ceq 'unknown' -and $s.Results[0].runtimeRoot -ceq 'C:\ELO data\jre') 'unknown ISA and spaced paths preserved'
Assert ($s.Results[0].eloRationale.de -and $s.Results[0].classificationEvidence.en) 'full bilingual evidence'
$fixture.Evidence='x'*4096
Reject { ConvertTo-EloUiResults $s ([pscustomobject]@{Results=@($fixture)}) } 422
Reject { ConvertTo-EloUiResults $s ([pscustomobject]@{Results=@(1..251)}) } 422

# Real asynchronous runspace; deterministic cancellation gate, no ELO traversal.
$s.ScanSource=@'
function Invoke-EloJavaScan {
    param($DriveRoots,$ManualPath,$ShouldCancel)
    while (-not (& $ShouldCancel)) { Start-Sleep -Milliseconds 10 }
    [pscustomobject]@{Results=@();Cancelled=$true}
}
'@
$s.State='idle'
try {
    $start=Invoke-EloApi $s (Request POST /api/scan '{}')
    Assert ($start.ok -eq $true -and $s.State -eq 'scanning') 'asynchronous scan returns immediately'
    Reject { Invoke-EloApi $s (Request POST /api/scan '{}') } 409
    $cancel=Invoke-EloApi $s (Request POST /api/cancel '{}')
    Assert ($cancel.ok -eq $true -and $s.State -eq 'cancelling') 'cancel request is not completion'
    $clock=[Diagnostics.Stopwatch]::StartNew()
    while ($s.Worker -and $clock.Elapsed.TotalSeconds -lt 10) { Update-EloScanWorker $s; Start-Sleep -Milliseconds 10 }
    Assert ($s.State -ceq 'cancelled' -and -not $s.Worker) 'cooperative cancellation completes and disposes worker'
} finally { if ($s.Worker) { $s.Worker.PowerShell.Stop(); $s.Worker.PowerShell.Dispose(); $s.Worker=$null } }
$s.ScanSource='function Invoke-EloJavaScan { param($DriveRoots,$ManualPath,$ShouldCancel) [pscustomobject]@{Results=@();Cancelled=$false} }'
try {
    Start-EloScanWorker $s
    $clock=[Diagnostics.Stopwatch]::StartNew()
    while ($s.Worker -and $clock.Elapsed.TotalSeconds -lt 10) { Update-EloScanWorker $s; Start-Sleep -Milliseconds 10 }
    Assert ($s.State -ceq 'completed') 'normal scan completes'
    $snapshot=Invoke-EloApi $s (Request -Path /api/results)
    Assert ($snapshot.results.Count -eq 0 -and $snapshot.security.verifiedOn -ceq '2026-11-23' -and $snapshot.security.advisories.Count -eq 3) 'advisory metadata also accompanies empty results'
} finally { if ($s.Worker) { $s.Worker.PowerShell.Stop(); $s.Worker.PowerShell.Dispose(); $s.Worker=$null } }
# Incomplete/access-denied scans must not disappear into a generic completed state.
$s.ScanSource=@'
function Invoke-EloJavaScan {
    param($DriveRoots,$ManualPath,$ShouldCancel)
    [pscustomobject]@{Results=@();Cancelled=$false;Discovery=[pscustomobject]@{Issues=@('sensitive path: denied');LimitReached=$false;DepthLimitReached=$false}}
}
'@
try {
    Start-EloScanWorker $s
    $clock=[Diagnostics.Stopwatch]::StartNew()
    while ($s.Worker -and $clock.Elapsed.TotalSeconds -lt 10) { Update-EloScanWorker $s; Start-Sleep -Milliseconds 10 }
    Assert ($s.State -ceq 'error') 'incomplete scan is not reported completed'
    Reject { Invoke-EloApi $s (Request -Path /api/results) } 422
    Assert ($s.LastError.Code -ceq 'scan_incomplete') 'scan coverage failure exposes stable code without raw paths'
} finally { if ($s.Worker) { $s.Worker.PowerShell.Stop(); $s.Worker.PowerShell.Dispose(); $s.Worker=$null } }
$s.ScanSource='function Invoke-EloJavaScan { param($DriveRoots,$ManualPath,$ShouldCancel) throw (New-Object UnauthorizedAccessException("sensitive exception")) }'
try {
    Start-EloScanWorker $s
    $clock=[Diagnostics.Stopwatch]::StartNew()
    while ($s.Worker -and $clock.Elapsed.TotalSeconds -lt 10) { Update-EloScanWorker $s; Start-Sleep -Milliseconds 10 }
    Assert ($s.State -ceq 'error' -and $s.LastError.Code -ceq 'access_denied') 'worker preserves access error category, not diagnostic text'
    Reject { Invoke-EloApi $s (Request -Path /api/results) } 403
} finally { if ($s.Worker) { $s.Worker.PowerShell.Stop(); $s.Worker.PowerShell.Dispose(); $s.Worker=$null } }

# Available-port allocation and private launch delivery, with no real browser.
$bound=New-EloLoopbackListener
try {
    Assert ($bound.LocalEndpoint.Address.ToString() -ceq '127.0.0.1' -and $bound.LocalEndpoint.Port -gt 0) 'OS selects available strictly loopback port'
    Reject { New-EloLoopbackListener -Port $bound.LocalEndpoint.Port } 503
} finally { $bound.Stop() }
Reject { Invoke-EloSessionLaunch $s -NoBrowser } 422
Reject { Start-EloServer -UiHtml '<title>fixture</title>' -ScanSource '# none' -NoBrowser } 422
Reject { Start-EloServer -UiHtml '<title>fixture</title>' -ScanSource '# none' -NoBrowser -OpenBrowser } 422
$script:PrivateUrl=$null
$launchOutput=@(& { Invoke-EloSessionLaunch $s -NoBrowser -LaunchHandler { param($Url) $script:PrivateUrl=$Url; Write-Warning $Url; 'must not reach output' } } 3>&1)
Assert ($script:PrivateUrl -ceq ($s.Origin+'/#token='+$s.Token) -and $launchOutput.Count -eq 0) 'no-browser private callback is usable without token logs'
Reject { Invoke-EloSessionLaunch $s -NoBrowser -LaunchHandler { param($Url) throw $Url } } 503
$script:FailedPort=0
Reject { Start-EloServer -UiHtml '<title>fixture</title>' -ScanSource '# none' -NoBrowser -LaunchHandler { param($Url) $script:FailedPort=([Uri]$Url).Port; throw 'private failure' } } 503
$rebound=New-EloLoopbackListener -Port $script:FailedPort
try { Assert ($rebound.LocalEndpoint.Port -eq $script:FailedPort) 'failed private launch closes its listener' } finally { $rebound.Stop() }
try { Invoke-EloSessionLaunch $s -BrowserLauncher { param($Url) throw $Url } } catch {
    Assert ($_.Exception.Message -ceq 'browser_launch_failed' -and -not $_.ToString().Contains($s.Token)) 'browser failure never reveals launch URI'
}
$access=ConvertTo-EloErrorResponse (New-Object UnauthorizedAccessException('sensitive path/token'))
Assert ($access.Status -eq 403 -and $access.Body.error -ceq 'access_denied' -and $access.Body.warnings[0].en) 'access failures have stable code and translated guidance'
Assert (-not ($access.Body | ConvertTo-Json -Depth 5).Contains('sensitive path/token')) 'error envelope never echoes underlying diagnostics'
$exception=New-Object InvalidOperationException('rollback_failed_manual_recovery_required'); $exception.Data['Status']=500
$recovery=ConvertTo-EloErrorResponse $exception
Assert ($recovery.Body.warnings[0].en.Contains('may still be changed') -and $recovery.Body.warnings[0].de) 'manual recovery warning is actionable and bilingual'

# Exercise the actual loopback host, not just dispatch. A known token is injected
# only into this isolated test runspace; production always uses the CSPRNG.
$readyState=[hashtable]::Synchronized(@{Port=0})
$hostPs=[PowerShell]::Create()
$hostScript=@'
param($serverPath,$readyState)
. $serverPath
function New-EloSecret { return ('a'*64) }
$privateLaunch={ param($Url) $readyState.Port=([Uri]$Url).Port }.GetNewClosure()
Start-EloServer -UiHtml '<!doctype html><title>fixture</title>' -ScanSource 'function Invoke-EloJavaScan { param($DriveRoots,$ManualPath,$ShouldCancel) [pscustomobject]@{Results=@();Cancelled=$false} }' -NoBrowser -LaunchHandler $privateLaunch
'@
function Live([string]$Message) {
    $client=New-Object Net.Sockets.TcpClient
    try {
        $client.Connect('127.0.0.1',$port); $client.ReceiveTimeout=3000; $client.SendTimeout=3000
        $stream=$client.GetStream(); $bytes=[Text.Encoding]::UTF8.GetBytes($Message)
        $stream.Write($bytes,0,$bytes.Length)
        $reader=New-Object IO.StreamReader($stream)
        return $reader.ReadToEnd()
    } finally { $client.Close() }
}
try {
    $null=$hostPs.AddScript($hostScript).AddArgument("$PSScriptRoot\server.ps1").AddArgument($readyState)
    $hostHandle=$hostPs.BeginInvoke()
    $clock=[Diagnostics.Stopwatch]::StartNew()
    while ($readyState.Port -eq 0 -and $clock.Elapsed.TotalSeconds -lt 10) { Start-Sleep -Milliseconds 10 }
    Assert ($readyState.Port -gt 0) 'no-browser host delivers OS-selected port privately'
    $port=$readyState.Port
    $ready=$false; $clock=[Diagnostics.Stopwatch]::StartNew()
    while (-not $ready -and $clock.Elapsed.TotalSeconds -lt 10) {
        try { $page=Live "GET / HTTP/1.1`r`nHost: 127.0.0.1:$port`r`n`r`n"; $ready=$true } catch { Start-Sleep -Milliseconds 30 }
    }
    Assert ($ready -and $page.Contains('<title>fixture</title>') -and $page.StartsWith('HTTP/1.1 200')) 'live page bootstrap'
    $reply=Live "GET /api/status HTTP/1.1`r`nHost: 127.0.0.1:$port`r`nX-Session-Token: $('a'*64)`r`n`r`n"
    Assert ($reply.StartsWith('HTTP/1.1 200') -and $reply.Contains('"state":"idle"')) 'live authenticated status'
    Assert (-not $reply.Contains('a'*64)) 'live token not reflected'
    $reply=Live "GET /api/results HTTP/1.1`r`nHost: evil.invalid:$port`r`nX-Session-Token: $('a'*64)`r`n`r`n"
    Assert ($reply.StartsWith('HTTP/1.1 403')) 'live DNS-rebinding Host rejection'
    $reply=Live "POST /api/cancel HTTP/1.1`r`nHost: 127.0.0.1:$port`r`nX-Session-Token: $('a'*64)`r`nContent-Type: application/json`r`nContent-Length: 2`r`n`r`n{}"
    Assert ($reply.StartsWith('HTTP/1.1 403')) 'live missing Origin rejected'
    $reply=Live "POST /api/cancel HTTP/1.1`r`nHost: 127.0.0.1:$port`r`nX-Session-Token: $('a'*64)`r`nOrigin: http://127.0.0.1:$port`r`nContent-Type: application/json`r`nContent-Length: 2`r`n`r`n{}"
    Assert ($reply.StartsWith('HTTP/1.1 200') -and $reply.Contains('"ok":true')) 'live valid POST'
    $reply=Live "GET /api/status HTTP/1.1`r`nHost: 127.0.0.1:$port`r`n`r`n"
    Assert ($reply.StartsWith('HTTP/1.1 401')) 'live token required'
} finally { $hostPs.Stop(); $hostPs.Dispose() }
Write-Output "PASS: $script:Count assertions"
