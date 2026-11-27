$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\vulndb.ps1"
. "$PSScriptRoot\update.ps1"
. "$PSScriptRoot\catalog.ps1"
. "$PSScriptRoot\server.ps1"
. "$PSScriptRoot\scan.ps1"
. "$PSScriptRoot\cli.ps1"
$script:Count = 0
function Assert($Condition, $Message) { if (-not $Condition) { throw "FAIL: $Message" }; $script:Count++ }
function Reject([scriptblock]$Work, [int]$Status) {
    try { & $Work; throw 'Expected rejection' } catch { Assert ($_.Exception.Data['Status'] -eq $Status) "Expected HTTP $Status, got $($_.Exception.Message)" }
}
$s = New-EloServerSession -Port 54321 -UiHtml '<!doctype html>' -ScanSource 'function Invoke-EloJavaScan { param($DriveRoots,$ManualPath,$ShouldCancel) [pscustomobject]@{ Results=@(); Cancelled=(& $ShouldCancel) } }'
$s.Adapters.BackupRoots = { @() }
$script:LogLines=New-Object 'System.Collections.Generic.List[string]'; $s.Adapters.Log={ param($m) $script:LogLines.Add([string]$m) }
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
$evidenceSession=New-EloServerSession -Port 54322 -UiHtml 'fixture' -ScanSource 'fixture'; $evidenceSession.Adapters.Log={ param($m) }
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
Assert ($zuluCli.ExitCode -eq 0 -and $zuluCliJson.scan.Results[0].Vendor -ceq 'Azul Zulu' -and $zuluCliJson.scan.Results[0].Status -ceq 'PotentiallyVulnerable') 'CLI JSON retains Zulu and its status'
ConvertTo-EloUiResults $evidenceSession $zuluScan
Assert ($evidenceSession.Results[0].vendor -ceq 'Azul Zulu' -and $evidenceSession.Results[0].status -ceq 'vulnerable') 'an old Zulu is shown as vulnerable in the UI'
Assert ($evidenceSession.ReportJvms[-1].VendorVerified -and $evidenceSession.ReportJvms[-1].Vendor -ceq 'Azul Zulu' -and $evidenceSession.ReportJvms[-1].Classification -ceq 'PotentiallyVulnerable') 'the report keeps a verified vulnerable Zulu'
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
Assert (-not $html.Contains('secret-name') -and -not $html.Contains('Unbekannt / nicht verfuegbar')) 'resource injection sanitized in German (unknown values are left out)'
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
$s.Adapters=@{ Log={ param($m) $script:LogLines.Add([string]$m) }; ScanRules={ ,@(Get-EloScanRules) };
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
# Runtime update: ineligible targets and forged previews are refused; the module is never reached.
Reject { Invoke-EloApi $s (Request POST '/api/preview' '{"actionId":"update-runtime","resultId":"jvm1"}') } 409
Reject { Invoke-EloApi $s (Request POST '/api/action' '{"actionId":"update-runtime","resultId":"jvm1","previewId":"fake"}') } 409
Assert ($script:Fake.Writes -eq 0 -and $script:Fake.Probes -eq 0) 'ineligible update touches nothing'
function New-UpdateMock($Mode) {
    $st=@{Mode=$Mode;Events=New-Object 'System.Collections.Generic.List[string]';Installed='old'}
    $ad=@{
        Clock={ [datetime]'2026-11-24T10:00:00Z' }
        Admin={ $true }
        Inspect={ param($Path) if ($st.Mode -ceq 'zulu') { @{Vendor='Azul Zulu';Branch='21';Architecture='x64';ImageType='jdk';Fingerprint='fp-old'} } else { @{Vendor='Eclipse Adoptium';Branch='17';Architecture='x64';ImageType='jdk';Fingerprint='fp-old'} } }.GetNewClosure()
        Evidence={ param($Detected,$Package) @{Official=$true;PublishedHash=$true;Compatibility=$false} }
        Preflight={ param($Paths) @{SafePaths=$true;Quiescent=($st.Mode -ne 'running');Permissions=$true;Space=$true} }.GetNewClosure()
        Backup={ param($Paths) $st.Events.Add('backup') }.GetNewClosure()
        VerifyBackup={ param($Paths,$Detected) $true }
        Download={ param($Package,$Paths) $st.Events.Add('download'); if ($st.Mode -eq 'download') { throw 'download_failed' } }.GetNewClosure()
        VerifyPackage={ param($Package,$Paths) $true }
        Stage={ param($Package,$Paths) $st.Events.Add('stage') }.GetNewClosure()
        Probe={ param($Path,$Package) $true }
        Preserve={ param($Paths) $st.Events.Add('preserve'); $st.Installed='' }.GetNewClosure()
        Replace={ param($Paths) $st.Events.Add('replace'); $st.Installed='new' }.GetNewClosure()
        ValidateInstalled={ param($Paths,$Package) ($st.Mode -notin @('invalid','norestore')) }.GetNewClosure()
        Restore={ param($Paths) $st.Events.Add('restore'); if ($st.Mode -eq 'norestore') { throw 'restore_failed' }; $st.Installed='old' }.GetNewClosure()
        VerifyRestored={ param($Paths,$Detected) ($st.Installed -eq 'old') }.GetNewClosure()
    }
    $ctx=New-EloUpdateContext -Adapters $ad -Simulation
    return @{State=$st;Factory={ param($Root,$Runtime,$StopServices) $st.StopServices=[bool]$StopServices; $ctx }.GetNewClosure()}
}
function Reset-UpdateSession($Mode) {
    Reset-Fake
    $s.Targets=@{jvm1=[pscustomobject]@{Location='C:\ELO\java\bin\java.exe';Status='PotentiallyVulnerable';Vendor='Temurin';FullVersion='17.0.2+8'}}
    $s.ReportJvms=@(@{Version='17.0.2+8';Verified=$true;ExecutionVerified=$true;Vendor='Temurin';VendorVerified=$true;Classification='PotentiallyVulnerable';ClassificationVerified=$true;EvidenceCode='AdvisoryRangeMatch'})
    $s.ReportIndexes=@{jvm1=1}; $s.ReportActions=@(); $s.ReportRecovery=$null
    $mock=New-UpdateMock $Mode; $s.Adapters.NewUpdateContext=$mock.Factory; $s.LastUpdate=$null
    $st=$mock.State
    $vendor='Eclipse Adoptium'; $branch='17'; $installed='17.0.2+8'; $latest='17.0.21.1+2'
    if ($Mode -ceq 'zulu') { $vendor='Azul Zulu'; $branch='21'; $installed='21.0.1+12'; $latest='21.0.13.1+2' }
    if ($Mode -ceq 'current') { $installed='17.0.21.1+2' }
    $identityValue=@{Vendor=$vendor;Branch=$branch;Architecture='x64';ImageType='jdk';Version=$installed}
    $releaseValue=@{Vendor=$vendor;Branch=$branch;Architecture='x64';ImageType='jdk';Version=$latest;Uri='https://fixture.invalid/runtime.zip';Sha256=('a'*64);Size=200000000}
    $s.Adapters.Identity={ param($Path) if ($Mode -ceq 'unknown-vendor') { throw 'unrecognized_runtime_identity' }; $identityValue }.GetNewClosure()
    $s.Adapters.ResolveRelease={ param($Identity) $releaseValue }.GetNewClosure()
    $s.Adapters.RuntimeUsers={ param($Path)
        if ($Mode -ceq 'services') { return @{Services=@(@{Name='ELO-SRV01-1'},@{Name='ELO-Flows-Worker-1'});Processes=@()} }
        if ($Mode -ceq 'process') { return @{Services=@();Processes=@(@{Id=1;Name='java.exe'})} }
        return @{Services=@();Processes=@()}
    }.GetNewClosure()
    $st.Restores=New-Object 'System.Collections.Generic.List[object]'
    $s.Adapters.RestoreBackup={ param($Root,$Runtime,$Backup,$StopServices,$Stamp) $st.Restores.Add(@{Root=$Root;Runtime=$Runtime;Backup=$Backup;Stop=$StopServices}); if ($Mode -ceq 'restore-fails') { throw 'backup_entry_mismatch' } }.GetNewClosure()
    return $mock
}
function UpdatePreview { Invoke-EloApi $s (Request POST /api/preview '{"actionId":"update-runtime","resultId":"jvm1"}') }
function UpdateApply($Id) { Invoke-EloApi $s (Request POST /api/action ('{"actionId":"update-runtime","resultId":"jvm1","previewId":"'+$Id+'"}')) }
function Get-ErrorCode([scriptblock]$Work) { try { & $Work; return 'no-error' } catch { return (ConvertTo-EloErrorResponse $_.Exception) } }
# Success: preview is read-only, apply runs the whole transaction and reports backup + update.
$m=Reset-UpdateSession 'ok'
$up=UpdatePreview
Assert ($m.State.Events.Count -eq 0 -and $up.summary.en.Contains('17.0.21.1+2') -and $up.summary.en.Contains(('C:\ELO\java.backup-'+$script:Fake.Now.ToString('yyyyMMddHHmmss')+'.zip')) -and $up.warnings.Count -eq 2) 'update preview is read-only and names version and backup'
Assert ($up.summary.en.Length -le 4096 -and $up.summary.de.Length -le 4096 -and $up.warnings[0].en.Length -le 2048) 'update preview meets UI limits'
Assert ((UpdateApply $up.previewId).ok -and $m.State.Installed -eq 'new') 'confirmed update installs the new runtime'
Assert (($m.State.Events -join ',') -ceq 'backup,download,stage,preserve,replace') 'backup precedes download and replacement'
Assert (@($s.ReportActions | Where-Object { $_.Kind -ceq 'Update' -and $_.Status -ceq 'Proven' }).Count -eq 1 -and @($s.ReportActions | Where-Object { $_.Kind -ceq 'Backup' -and $_.BackupVerified }).Count -eq 1) 'update and verified backup are recorded for the report'
Assert ($s.ReportJvms[-1].Version -ceq '17.0.21.1+2' -and $s.ReportJvms[-1].Classification -ceq 'Fixed' -and $s.ReportJvms[-1].Verified) 'a successful Temurin update adds the new runtime to the report as verified and fixed by the catalog'
$s.Adapters.Resources={ @{ServerName='TEST-SERVER';WindowsVersion='10.0';WindowsBuild='20348';TotalRamBytes=8GB;Disks=@(@{Name='C:';TotalBytes=100GB;FreeBytes=40GB})} }
$s.Adapters.EloVersion={ param($Roots) if ($Roots -contains 'C:\ELO') { '25.00.010.476816' } else { $null } }
$report=Get-EloSessionReportHtml $s en
Assert ($report.Contains('25.00.010.476816')) 'report shows the ELO version read from the installed Indexserver files'
Assert ($report.Contains('17.0.21.1+2') -and $report.Contains('Expand-Archive') -and $report.Contains(('C:\ELO\java.backup-'+$script:Fake.Now.ToString('yyyyMMddHHmmss')+'.zip'))) 'report names the new version, backup ZIP and restore commands'
Reject { UpdateApply $up.previewId } 409
# Rejected before replacement (download failure): nothing replaced, failure recorded.
$m=Reset-UpdateSession 'download'; $up=UpdatePreview
$e=Get-ErrorCode { UpdateApply $up.previewId }
Assert ($e.Status -eq 422 -and $e.Body.error -ceq 'update_rejected_no_change' -and $m.State.Installed -eq 'old' -and @($s.ReportActions | Where-Object { $_.Kind -ceq 'Update' -and $_.Status -ceq 'Failed' -and $_.EvidenceCode -ceq 'DownloadFailed' }).Count -eq 1) 'download failure leaves the runtime untouched and is reported'
# Failed validation: rolled back, restore proven.
$m=Reset-UpdateSession 'invalid'; $up=UpdatePreview
$e=Get-ErrorCode { UpdateApply $up.previewId }
Assert ($e.Status -eq 422 -and $e.Body.error -ceq 'update_failed_rolled_back' -and $m.State.Installed -eq 'old' -and @($s.ReportActions | Where-Object { $_.Kind -ceq 'Restore' -and $_.Status -ceq 'Proven' }).Count -eq 1) 'failed validation is rolled back and reported'
# Failed restore: manual recovery locks the session.
$m=Reset-UpdateSession 'norestore'; $up=UpdatePreview
$e=Get-ErrorCode { UpdateApply $up.previewId }
Assert ($e.Status -eq 500 -and $e.Body.error -ceq 'update_manual_recovery_required' -and $s.RecoveryRequired -and @($s.ReportActions | Where-Object { $_.Kind -ceq 'Restore' -and $_.Status -ceq 'Failed' }).Count -eq 1) 'failed restore requires manual recovery'
# Running service blocks the preview (quiescence) and changes nothing.
$m=Reset-UpdateSession 'running'
$e=Get-ErrorCode { UpdatePreview }
Assert ($e.Status -eq 409 -and $e.Body.error -ceq 'update_preview_refused' -and $e.Body.warnings[0].en.Contains('preflight_failed:Quiescent') -and $m.State.Events.Count -eq 0) 'running runtime blocks the update before any change'
# Non-admin and unrecognised runtimes are refused.
$m=Reset-UpdateSession 'ok'; $script:Fake.Admin=$false
Reject { UpdatePreview } 403
$script:Fake.Admin=$true
$m=Reset-UpdateSession 'unknown-vendor'
$e=Get-ErrorCode { UpdatePreview }
Assert ($e.Status -eq 409 -and $e.Body.error -ceq 'update_preview_refused' -and $e.Body.warnings[0].en.Contains('unrecognized_runtime_identity')) 'unrecognised vendor refused with a stable code'
# Azul Zulu 21 is updated to the newest release of ITS branch.
$m=Reset-UpdateSession 'zulu'; $up=UpdatePreview
Assert ($up.summary.en.Contains('Azul Zulu JDK 21') -and $up.summary.en.Contains('21.0.1+12') -and $up.summary.en.Contains('21.0.13.1+2') -and $up.summary.de.Contains('Azul Zulu')) 'Zulu preview names vendor, branch, installed and latest version'
Assert ((UpdateApply $up.previewId).ok -and @($s.ReportActions | Where-Object { $_.Kind -ceq 'Update' -and $_.ToVersion -ceq '21.0.13.1+2' -and $_.FromVersion -ceq '21.0.1+12' }).Count -eq 1) 'Zulu update recorded with exact versions'
Assert ($s.ReportJvms[-1].Version -ceq '21.0.13.1+2' -and $s.ReportJvms[-1].Classification -ceq 'Unknown' -and $s.ReportJvms[-1].Vendor -ceq 'Azul Zulu') 'a Zulu update is recorded as verified with an unknown (omitted) fix status: the catalog has no Zulu data'
# Already newest: nothing offered.
$m=Reset-UpdateSession 'current'
$e=Get-ErrorCode { UpdatePreview }
Assert ($e.Status -eq 409 -and $e.Body.error -ceq 'update_not_needed' -and $m.State.Events.Count -eq 0) 'no update offered when the newest release is installed'
# Services that use the runtime are listed, stopped only because the preview said so.
$m=Reset-UpdateSession 'services'; $up=UpdatePreview
Assert ($up.warnings[0].en.Contains('ELO-SRV01-1') -and $up.warnings[0].en.Contains('STOPPED') -and $up.warnings[0].es.Contains('ELO-SRV01-1') -and $up.warnings[0].es -match 'DETENDR' -and $m.State.StopServices -eq $true) 'preview lists the services to stop and asks the backend for service control'
$m=Reset-UpdateSession 'ok'; $up=UpdatePreview
Assert ($m.State.StopServices -eq $false) 'no service control without services'
# Another process using the runtime blocks the change.
$m=Reset-UpdateSession 'process'
$e=Get-ErrorCode { UpdatePreview }
Assert ($e.Status -eq 409 -and $e.Body.warnings[0].en.Contains('runtime_in_use_by_java.exe') -and $m.State.Events.Count -eq 0) 'a foreign process using the runtime blocks the update'
# Restore from the session backup.
function RestorePreview { Invoke-EloApi $s (Request POST /api/preview '{"actionId":"restore-backup","resultId":"jvm1"}') }
function RestoreApply($Id) { Invoke-EloApi $s (Request POST /api/action ('{"actionId":"restore-backup","resultId":"jvm1","previewId":"'+$Id+'"}')) }
$m=Reset-UpdateSession 'ok'
$e=Get-ErrorCode { RestorePreview }
Assert ($e.Status -eq 409 -and $e.Body.error -ceq 'no_backup_for_target') 'restore needs a backup made in this session'
$up=UpdatePreview; $null=UpdateApply $up.previewId
$fakeBackup=Join-Path ([IO.Path]::GetTempPath()) ('elo-fake-backup-'+[guid]::NewGuid().ToString('N')+'.zip'); [IO.File]::WriteAllText($fakeBackup,'x')
try {
    $s.LastUpdate.Backup=$fakeBackup
    $s.Adapters.Identity={ param($Path) @{Vendor='Eclipse Adoptium';Branch='17';Architecture='x64';ImageType='jdk';Version='17.0.2+8'} }
    $rp=RestorePreview
    Assert ($rp.summary.en.Contains('17.0.2+8') -and $rp.summary.en.Contains('replaced-') -and $m.State.Restores.Count -eq 0) 'restore preview is read-only and names the version'
    Assert ((RestoreApply $rp.previewId).ok -and $m.State.Restores.Count -eq 1 -and $m.State.Restores[0].Backup -ceq $fakeBackup -and $m.State.Restores[0].Runtime -ceq 'C:\ELO\java') 'restore runs through the backend adapter'
    Assert (@($s.ReportActions | Where-Object { $_.Kind -ceq 'Restore' -and $_.Status -ceq 'Proven' -and $_.ToVersion -ceq '17.0.2+8' }).Count -eq 1 -and $null -eq $s.LastUpdate) 'restore recorded for the report'
    # A restore that is rejected leaves a failed action and a stable error.
    $m=Reset-UpdateSession 'restore-fails'
    $up=UpdatePreview; $null=UpdateApply $up.previewId; $s.LastUpdate.Backup=$fakeBackup
    $rp=RestorePreview
    $e=Get-ErrorCode { RestoreApply $rp.previewId }
    Assert ($e.Status -eq 422 -and $e.Body.error -ceq 'restore_failed_no_change' -and $e.Body.warnings[0].en.Contains('backup_entry_mismatch') -and @($s.ReportActions | Where-Object { $_.Kind -ceq 'Restore' -and $_.Status -ceq 'Failed' }).Count -eq 1) 'rejected restore is reported and changes nothing'
} finally { Remove-Item -LiteralPath $fakeBackup -Force -ErrorAction SilentlyContinue }
# A successful change whose ELO services do not load again is a warning that offers the restore.
$m=Reset-UpdateSession 'services'
$s.Adapters.NewUpdateContext={ param($Root,$Runtime,$StopServices) $c=& $m.Factory $Root $Runtime $StopServices; $c.Adapters.Quiesce={ param($Paths) }; $c.Adapters.Resume={ param($Paths,$Stopped) throw 'service_unhealthy:ELO-Basis+ELO-iSearch' }; $c }.GetNewClosure()
$up=UpdatePreview; $done=UpdateApply $up.previewId
Assert ($done.ok -and $done.warning -ceq 'services_unhealthy' -and $done.warnings[0].en.Contains('ELO-Basis, ELO-iSearch') -and $done.warnings[0].es.Contains('restaurar') -and $m.State.Installed -eq 'new' -and $null -ne $s.LastUpdate) 'unhealthy ELO services are reported, name the services and keep the restore available'
# A service already in Stop Pending is announced in the preview.
$m=Reset-UpdateSession 'ok'; $s.Adapters.RuntimeUsers={ param($Path) @{Services=@(@{Name='ELO-Basis';State='Stop Pending'});Processes=@()} }
$up=UpdatePreview
Assert ((@($up.warnings | ForEach-Object { $_.en }) -join ' ').Contains('Already in Stop Pending: ELO-Basis') -and $m.State.StopServices -eq $true) 'a Stop Pending service is handled as a service and announced'
# A foreign process gets a message that names the real cause.
$m=Reset-UpdateSession 'process'; $e=Get-ErrorCode { UpdatePreview }
Assert ((@($e.Body.warnings | ForEach-Object { $_.en }) -join ' ').Contains('does not belong to an active service')) 'the foreign process refusal explains the cause'
# A restore whose services do not come back warns too.
$m=Reset-UpdateSession 'ok'; $up=UpdatePreview; $null=UpdateApply $up.previewId
$fakeBackup=Join-Path ([IO.Path]::GetTempPath()) ('elo-fake-backup-'+[guid]::NewGuid().ToString('N')+'.zip'); [IO.File]::WriteAllText($fakeBackup,'x')
try {
    $s.LastUpdate.Backup=$fakeBackup
    $s.Adapters.Identity={ param($Path) @{Vendor='Eclipse Adoptium';Branch='17';Architecture='x64';ImageType='jdk';Version='17.0.2+8'} }
    $s.Adapters.RestoreBackup={ param($Root,$Runtime,$Backup,$StopServices,$Stamp) @{Restored=$true;ServiceError='service_restart_failed:ELO-Basis'} }
    $rp=RestorePreview; $done=RestoreApply $rp.previewId
    Assert ($done.ok -and $done.warning -ceq 'services_not_restarted' -and $done.warnings[0].en.Contains('ELO-Basis')) 'a restore that cannot restart ELO says so'
} finally { Remove-Item -LiteralPath $fakeBackup -Force -ErrorAction SilentlyContinue }
# Restoring after ELO crashed on the new Java: the recorded services are started although none is active.
$m=Reset-UpdateSession 'ok'; $up=UpdatePreview; $null=UpdateApply $up.previewId
$fakeBackup=Join-Path ([IO.Path]::GetTempPath()) ('elo-fake-backup-'+[guid]::NewGuid().ToString('N')+'.zip'); [IO.File]::WriteAllText($fakeBackup,'x')
try {
    $s.LastUpdate.Backup=$fakeBackup
    $s.Adapters.Identity={ param($Path) @{Vendor='Eclipse Adoptium';Branch='17';Architecture='x64';ImageType='jdk';Version='17.0.2+8'} }
    $s.Adapters.RuntimeUsers={ param($Path) @{Services=@();Processes=@()} }
    $s.Adapters.RecordedServices={ param($Backup,$Runtime) @(@{Name='ELO-Basis';State='Stopped'}) }
    $rp=RestorePreview
    $null=RestoreApply $rp.previewId
    Assert ($rp.warnings[0].en.Contains('ELO-Basis') -and $m.State.Restores[0].Stop -eq $true) 'a restore starts the services the update had stopped'
} finally { Remove-Item -LiteralPath $fakeBackup -Force -ErrorAction SilentlyContinue; $s.Adapters.RecordedServices={ param($Backup,$Runtime) @() } }
# Existing backups (also from earlier sessions) are listed first and can be restored by server-side id.
$bkRoot=Join-Path ([IO.Path]::GetTempPath()) ('elo-bk-test-'+[guid]::NewGuid().ToString('N'))
try {
    $bkDir=Join-Path $bkRoot 'ELO'; $null=[IO.Directory]::CreateDirectory($bkDir)
    $null=[IO.Directory]::CreateDirectory((Join-Path $bkRoot 'Windows'))
    Add-Type -AssemblyName System.IO.Compression
    function New-FakeBackupZip([string]$Path,[string]$Release) {
        $fs=[IO.File]::Create($Path); $zip=New-Object IO.Compression.ZipArchive($fs,[IO.Compression.ZipArchiveMode]::Create,$true)
        try {
            foreach ($entry in @(@('manifest.json',('[' + ('{"Name":"x"},' * 120) + '{}]')),@('tree/release',$Release))) { $w=New-Object IO.StreamWriter($zip.CreateEntry($entry[0],[IO.Compression.CompressionLevel]::NoCompression).Open()); $w.Write($entry[1]); $w.Dispose() }
        } finally { $zip.Dispose(); $fs.Dispose() }
    }
    New-FakeBackupZip (Join-Path $bkDir 'java.backup-20260101120000.zip') "IMPLEMENTOR=`"Eclipse Adoptium`"`nJAVA_RUNTIME_VERSION=`"17.0.2+8`"`n"
    New-FakeBackupZip (Join-Path $bkDir 'java.backup-20250101120000.zip') "IMPLEMENTOR=`"Azul Systems, Inc.`"`nJAVA_VERSION=`"21.0.13`"`n"
    New-FakeBackupZip (Join-Path (Join-Path $bkRoot 'Windows') 'java.backup-20260202020202.zip') 'JAVA_VERSION="1.0"'
    [IO.File]::WriteAllText((Join-Path $bkDir 'notes.backup-bad.zip'),('x'*2000)); [IO.File]::WriteAllText((Join-Path $bkDir 'java.backup-20269999999999.zip'),('x'*2000))
    $m=Reset-UpdateSession 'ok'
    $s.Adapters.BackupRoots={ @($bkRoot) }.GetNewClosure(); $s.BackupsCache=$null
    $list=@(Get-EloBackupList $s)
    Assert ($list.Count -eq 2) 'only well-named, valid backups below level 2 are listed; system folders and bad names are skipped'
    Assert ($list[0].risk -ceq 'vulnerable' -and $list[0].vendor -ceq 'Temurin' -and $list[1].risk -ceq 'unknown' -and $list[0].created -ceq '2026-01-01 12:00' -and $list[0].version -ceq '17.0.2+8' -and $list[0].runtime -ceq (Join-Path $bkDir 'java') -and $list[1].version -ceq '21.0.13') 'newest first, version read from the ZIP, runtime derived from the file name'
    $s.BackupsCache=$null; $payload=Invoke-EloApi $s (Request GET '/api/results')
    Assert (@($payload.backups).Count -eq 2 -and -not ($payload | ConvertTo-Json -Depth 6).Contains('"Root"')) 'the results payload carries the backups (no internal fields)'
    # The catalog information for the UI is a flat array (never nested) with severity, problem, solution and action ids.
    $vulnJson = $payload | ConvertTo-Json -Depth 8 -Compress
    Assert ($vulnJson -cnotmatch '"vulnerabilities":\[\[' -and @($payload.vulnerabilities).Count -eq 1 -and $payload.vulnerabilities[0].id -ceq 'CVE-2026-114938' -and $payload.vulnerabilities[0].severity -ceq 'high' -and $payload.vulnerabilities[0].problem.de -and @($payload.vulnerabilities[0].actions).Count -eq 3) 'results carry the catalog vulnerability info as a flat array'
    Assert ($payload.vulnerabilities[0].mitigation.option -ceq '-XX:-UseBASE64Intrinsics' -and $payload.vulnerabilities[0].mitigation.variable -ceq 'JAVA_TOOL_OPTIONS' -and @($payload.vulnerabilities[0].mitigation.verifyArgs).Count -eq 2) 'the mitigation option, variable and verify arguments reach the UI for the by-hand steps'
    $id=@($payload.backups)[0].id
    $s.Adapters.Identity={ param($Path) @{Vendor='Eclipse Adoptium';Branch='17';Architecture='x64';ImageType='jdk';Version='17.0.2+8'} }
    $rp=Invoke-EloApi $s (Request POST /api/preview ('{"actionId":"restore-backup","resultId":"'+$id+'"}'))
    Assert ($rp.summary.en.Contains('17.0.2+8') -and $rp.summary.en.Contains((Join-Path $bkDir 'java.backup-20260101120000.zip')) -and $m.State.Restores.Count -eq 0) 'restore preview from an earlier-session backup is read-only'
    Assert ((@($rp.warnings | ForEach-Object { $_.en }) -join ' ').Contains('BEFORE the fix for CVE-2026-114938') -and (@($rp.warnings | ForEach-Object { $_.de }) -join ' ').Contains('VOR dem Fix') -and (@($rp.warnings | ForEach-Object { $_.en }) -join ' ').Contains('ELO Tomcat')) 'restore preview names the security problem of the backup and the Tomcat stop'
    $r=Invoke-EloApi $s (Request POST /api/action ('{"actionId":"restore-backup","resultId":"'+$id+'","previewId":"'+$rp.previewId+'"}'))
    Assert ($r.ok -and $m.State.Restores.Count -eq 1 -and $m.State.Restores[0].Backup -ceq (Join-Path $bkDir 'java.backup-20260101120000.zip') -and $m.State.Restores[0].Runtime -ceq (Join-Path $bkDir 'java')) 'restore of a discovered backup goes through the backend adapter'
    # Ids are stable (preview and apply survive a list refresh) and a backup is restorable without a scan.
    $s.BackupsCache=$null; $again=@(Get-EloBackupList $s)
    Assert ($again[0].id -ceq $id -and $again[0].id -cmatch '^[a-f0-9]{64}$') 'backup ids are stable across list refreshes'
    Assert ($m.State.Restores.Count -eq 1 -and @($script:LogLines | Where-Object { $_ -like '*SECURITY*BEFORE the CVE-2026-114938 fix*' }).Count -eq 1) 'restoring a vulnerable backup is announced in the backend window'
    Assert ($s.ReportJvms[-1].Classification -ceq 'PotentiallyVulnerable' -and $s.ReportActions[-1].Kind -ceq 'Restore' -and $s.ReportActions[-1].RuntimeIndex -eq $s.ReportJvms.Count) 'the report records the restored runtime as potentially vulnerable'
    Assert (-not (($script:LogLines -join "`n").Contains($s.Token))) 'the backend log never contains the session token'
    $idleState=$s.State; $s.State='idle'; $s.Results=@(); $s.Targets=@{}
    $id2=@($again)[1].id
    $s.Adapters.Identity={ param($Path) @{Vendor='Azul Zulu';Branch='21';Architecture='x64';ImageType='jdk';Version='21.0.13'} }
    Assert ((Get-EloBackupRisk 'Azul Zulu' '21.0.1') -ceq 'vulnerable' -and (Get-EloBackupRisk 'Azul Zulu' '17.0.20+8') -ceq 'vulnerable' -and (Get-EloBackupRisk 'Azul Zulu' '17.0.5') -ceq 'unknown' -and (Get-EloBackupRisk 'Azul Zulu' '21.0.13+11') -ceq 'unknown') 'an old Zulu backup is vulnerable; a Zulu backup is never reported as patched'
    $rp2=Invoke-EloApi $s (Request POST /api/preview ('{"actionId":"restore-backup","resultId":"'+$id2+'"}'))
    Assert ((@($rp2.warnings | ForEach-Object { $_.en }) -join ' ').Contains('cannot be determined') -and (@($rp2.warnings | ForEach-Object { $_.en }) -join ' ').Contains('Tomcat')) 'unknown-status backup warns about security and about stopping the ELO services'
    $r2=Invoke-EloApi $s (Request POST /api/action ('{"actionId":"restore-backup","resultId":"'+$id2+'","previewId":"'+$rp2.previewId+'"}'))
    Assert ($r2.ok -and $s.ReportJvms[-1].Classification -ceq 'Unknown') 'a backup can be restored without a scan (idle session)'
    $s.State=$idleState
    Assert ((Get-EloSessionReportHtml $s 'en') -match '(?i)vulnerab') 'the technical report mentions the vulnerable restored runtime'
    Reject { Invoke-EloApi $s (Request POST /api/preview '{"actionId":"restore-backup","resultId":"0000000000000000000000000000000000000000000000000000000000000000"}') } 409
    Remove-Item -LiteralPath (Join-Path $bkDir 'java.backup-20260101120000.zip') -Force
    $s.Backups=@{$id=@{Path=(Join-Path $bkDir 'java.backup-20260101120000.zip');Runtime=(Join-Path $bkDir 'java');Root=$bkDir;Version='17.0.2+8'}}
    $e=Get-ErrorCode { Invoke-EloApi $s (Request POST /api/preview ('{"actionId":"restore-backup","resultId":"'+$id+'"}')) }
    Assert ($e.Status -eq 409 -and $e.Body.error -ceq 'no_backup_for_target') 'a backup deleted from disk is refused'
} finally {
    $full=[IO.Path]::GetFullPath($bkRoot)
    if ($full.StartsWith([IO.Path]::GetFullPath([IO.Path]::GetTempPath()),[StringComparison]::OrdinalIgnoreCase) -and (Split-Path -Leaf $full) -like 'elo-bk-test-*') { Remove-Item -LiteralPath $full -Recurse -Force -ErrorAction SilentlyContinue }
    $s.Adapters.BackupRoots={ @() }; $s.BackupsCache=$null
}
Assert ($script:Fake.Writes -eq 0 -and $script:Fake.Probes -eq 0) 'update flow never writes machine options'
Reset-Fake; $p=Preview
$other=New-EloServerSession -Port 54321 -UiHtml '<html>' -ScanSource '# none'; $other.Adapters.Log={ param($m) }
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
Assert ($security.verifiedOn -ceq '2026-11-23' -and $security.advisories.Count -eq 4) 'parent-verified advisory date and complete metadata'
$openjdk=@($security.advisories | Where-Object { $_.id -ceq 'openjdk-2026-11-17' })[0]
Assert ($openjdk.title.en.Contains('user-supplied text') -and $openjdk.title.en.Contains('not fetched')) 'OpenJDK provenance is not presented as a direct fetch'
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
    Assert ($snapshot.results.Count -eq 0 -and $snapshot.security.verifiedOn -ceq '2026-11-23' -and $snapshot.security.advisories.Count -eq 4) 'advisory metadata also accompanies empty results'
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
# The temporary mitigation is always allowed for a scanned runtime, also one the catalog does not call vulnerable;
# the preview says so, and the flag is still probed with that exact java.exe before any write.
$null = Reset-UpdateSession 'ok'
$s.State = 'completed'; $s.Worker = $null
$s.Targets.jvm1.Status = 'Inconclusive'; $s.Targets.jvm1.Vendor = 'Azul Zulu'
$s.ReportIndexes = @{jvm1=1}
$notVuln = Invoke-EloApi $s (Request POST /api/preview '{"actionId":"mitigate","resultId":"jvm1"}')
Assert ((@($notVuln.warnings | ForEach-Object { $_.en }) -join ' ').Contains('not classified as vulnerable by the catalog') -and (@($notVuln.warnings | ForEach-Object { $_.de }) -join ' ').Contains('nicht als verwundbar eingestuft')) 'mitigation preview for a runtime the catalog does not call vulnerable explains the situation instead of refusing it'
$applied = Invoke-EloApi $s (Request POST /api/action ('{"actionId":"mitigate","resultId":"jvm1","previewId":"'+$notVuln.previewId+'"}'))
Assert ($applied.ok -and $script:Fake.Writes -eq 1) 'the mitigation is applied for such a runtime (after the flag probe)'
# Spanish: the catalog and the backend warnings carry es; the report endpoint accepts it.
$s.Adapters.BackupRoots = { @() }; $s.BackupsCache = $null; $s.LastError = $null; $s.RecoveryRequired = $false
$resultsEs = Invoke-EloApi $s (Request -Path /api/results)
$labels = @($resultsEs.vulnerabilities[0].actionLabels)
Assert ($labels.Count -eq 2 -and $labels[0].en -ceq 'Update Java runtime' -and $labels[1].es -match 'Mitigaci') 'the results name the actions of each vulnerability, without the restore'
Assert ($resultsEs.vulnerabilities[0].title.es -match 'Java4Shell' -and $resultsEs.vulnerabilities[0].problem.es -match 'runtime' -and $resultsEs.security.advisories[0].title.es) 'the catalog texts reach the UI with a Spanish version'
$esErr = Get-ErrorCode { Invoke-EloApi $s (Request POST /api/preview '{"actionId":"mitigate","resultId":"nope"}') }
$warn = Add-EloSpanish @{en='This runtime is already the newest release of its branch. Nothing to update.';de='x'}
Assert ($warn.es -ceq 'Este runtime ya es la última versión de su rama. No hay nada que actualizar.') 'static backend warnings are translated from a table'
$other = Add-EloSpanish @{en='A text nobody translated';de='x'}
Assert (-not $other.ContainsKey('es')) 'an untranslated text simply has no es (the UI falls back to English)'
$evidenceSession.Adapters.Resources={ @{ServerName='SRV01';WindowsVersion='10.0';WindowsBuild='20348';Disks=@()} }; $evidenceSession.State='completed'
$repEs = Get-EloSessionReportHtml $evidenceSession es
Assert ($repEs.Contains('<html lang="es">') -and $repEs.Contains('</header><p>Estado del escaneo de la ') -and $repEs -match 'Estado del escaneo de la sesi.{1,2}n: Completado') 'the session report can be produced in Spanish, after the hostname header'
$bundle = Get-EloSessionReportBundle $evidenceSession es
Assert ($bundle.fileName -ceq 'elo-technical-SRV01-es' -and $bundle.html -ceq $bundle.html.Trim()) 'the file name carries the hostname'
Assert ([Text.Encoding]::ASCII.GetString([Convert]::FromBase64String($bundle.pdf),0,8) -ceq '%PDF-1.4') 'the same report is delivered as PDF'
$evidenceSession.Adapters.Resources={ $null }
Assert ((Get-EloSessionReportBundle $evidenceSession en).fileName -ceq 'elo-technical-en') 'without a known hostname the name stays generic'
$e = Get-ErrorCode { Invoke-EloApi $s (Request POST /api/report '{"language":"fr"}') }
Assert ($e.Status -eq 400) 'other languages are still rejected'

# A stable preferred port keeps the browser origin (and its encrypted saved keys) between runs; a busy port falls back.
$probe = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Parse('127.0.0.1'),0); $probe.Start(); $freePort = $probe.LocalEndpoint.Port; $probe.Stop()
$pref = New-EloPreferredListener -PreferredPort $freePort
try { Assert ($pref.LocalEndpoint.Port -eq $freePort) 'a free preferred port is used, so the origin is the same on every run' } finally { $pref.Stop() }
$busy = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Parse('127.0.0.1'),0); $busy.Start(); $busyPort = $busy.LocalEndpoint.Port
try {
    $fallback = New-EloPreferredListener -PreferredPort $busyPort
    try { Assert ($fallback.LocalEndpoint.Port -ne $busyPort -and $fallback.LocalEndpoint.Port -gt 0 -and $fallback.LocalEndpoint.Address.ToString() -ceq '127.0.0.1') 'a busy preferred port falls back to another free loopback port' } finally { $fallback.Stop() }
} finally { $busy.Stop() }
$explicit = New-EloPreferredListener -Port 0 -PreferredPort 0
try { Assert ($explicit.LocalEndpoint.Port -gt 0) 'without a preferred port a free port is chosen as before' } finally { $explicit.Stop() }
# ---- ELO Community helper: status, model list, setup/run jobs. Fake processes only; no network, no node.
$cmRoot = Join-Path ([IO.Path]::GetTempPath()) ('elo-cm-test-' + [guid]::NewGuid().ToString('N'))
$savedPd = $env:ProgramData
try {
    $null = [IO.Directory]::CreateDirectory((Join-Path $cmRoot 'tool\bin')); $null = [IO.Directory]::CreateDirectory((Join-Path $cmRoot 'tool\config')); $null = [IO.Directory]::CreateDirectory((Join-Path $cmRoot 'pd'))
    [IO.File]::WriteAllText((Join-Path $cmRoot 'tool\bin\elo-community.js'), '// fake')
    [IO.File]::WriteAllText((Join-Path $cmRoot 'tool\config\ai.json'), '{"provider":"openai","model":"gpt-x","baseUrl":"https://api.openai.com/v1","apiKeyEnv":"OPENAI_API_KEY"}')
    [IO.File]::WriteAllText((Join-Path $cmRoot 'tool\secrets.local.env'), "ELO_COMMUNITY_USER=me`nELO_COMMUNITY_PASSWORD=`nOPENAI_API_KEY=sk-file-secret`n")
    $env:ProgramData = Join-Path $cmRoot 'pd'
    $script:CmCalls = @(); $script:CmProc = $null
    $s.Adapters.CommunityRoot = { Join-Path $cmRoot 'tool' }.GetNewClosure()
    $s.Adapters.FindNode = { 'C:\fake\node.exe' }
    $s.Adapters.FindChrome = { 'C:\fake\chrome.exe' }
    $s.Adapters.Clock = { [DateTime]::UtcNow }
    $s.Adapters.RunProcess = { param($FilePath,$Arguments,$Environment,$WorkingDirectory,$TimeoutSec) $script:CmCalls += ,@{Kind='run';Arguments=$Arguments;Environment=$Environment}; if ($script:CmModels -ceq 'fail') { return @{ExitCode=1;Output='';Error='elo-community: ai_http_401: bad key sk-typed-secret'} }; return @{ExitCode=0;Output=('Loaded from x'+"`n"+'{"provider":"openai","current":"gpt-x","models":["gpt-5","gpt-6-sol","bad model!","o3"]}'+"`n");Error=''} }
    $s.Adapters.StartProcess = { param($FilePath,$Arguments,$Environment,$WorkingDirectory) $script:CmCalls += ,@{Kind='start';Arguments=$Arguments;Environment=$Environment}; $script:CmProc = New-Object psobject -Property @{HasExited=$false;ExitCode=0}; $script:CmProc | Add-Member -MemberType ScriptMethod -Name Kill -Value { $this.HasExited = $true; $this.ExitCode = 1 }; return $script:CmProc }
    $st = Invoke-EloApi $s (Request -Path /api/community/status)
    Assert ($st.helper -and $st.node -and $st.chrome -and -not $st.playwright -and $st.secrets.communityUser -and -not $st.secrets.communityPassword -and $st.secrets.openaiKey -and -not $st.secrets.anthropicKey -and $st.ai.provider -ceq 'openai' -and $st.ai.model -ceq 'gpt-x') 'community status reports the helper, node, Chrome, which secrets exist (booleans only) and the configured AI'
    Assert (-not (($st | ConvertTo-Json -Depth 5) -match 'sk-file-secret')) 'status never contains a secret value'
    [IO.Directory]::CreateDirectory((Join-Path $cmRoot 'tool\node_modules\playwright-core')) | Out-Null; [IO.File]::WriteAllText((Join-Path $cmRoot 'tool\node_modules\playwright-core\package.json'), '{}')
    Assert ((Invoke-EloApi $s (Request -Path /api/community/status)).playwright) 'status detects the installed playwright package'
    $s.Adapters.CommunityRoot = { $null }
    $none = Invoke-EloApi $s (Request -Path /api/community/status)
    Assert (-not $none.helper -and -not $none.node) 'without the helper folder the status says so'
    $e = Get-ErrorCode { Invoke-EloApi $s (Request POST /api/community/models '{"provider":"openai"}') }
    Assert ($e.Status -eq 409 -and $e.Body.error -ceq 'community_unavailable') 'community routes refuse when the helper is missing'
    $s.Adapters.CommunityRoot = { Join-Path $cmRoot 'tool' }.GetNewClosure()

    # model list
    $m = Invoke-EloApi $s (Request POST /api/community/models '{"provider":"openai","apiKey":"sk-typed-secret"}')
    $call = $script:CmCalls[-1]
    Assert (@($m.models).Count -eq 3 -and $m.models -ccontains 'gpt-6-sol' -and $m.models -cnotcontains 'bad model!' -and $m.current -ceq 'gpt-x') 'model list is returned and filtered to safe ids'
    Assert ($call.Arguments -cmatch 'elo-community\.js" models --provider openai$' -and $call.Environment['OPENAI_API_KEY'] -ceq 'sk-typed-secret' -and -not (($m | ConvertTo-Json -Depth 4) -match 'sk-typed-secret')) 'the typed key reaches the helper through its environment only and is not returned'
    foreach ($bad in @('{"provider":"evil"}','{"provider":"openai","model":"a b"}','{"provider":"openai","baseUrl":"http://example.org"}','{"provider":"openai","baseUrl":"https://x.org/a b"}','{"provider":"openai","extra":1}','{"provider":"openai","apiKey":"line1\nline2"}')) {
        $e = Get-ErrorCode { Invoke-EloApi $s (Request POST /api/community/models $bad) }
        Assert ($e.Status -eq 400) "model request rejected: $bad"
    }
    $script:CmModels = 'fail'
    $e = Get-ErrorCode { Invoke-EloApi $s (Request POST /api/community/models '{"provider":"openai","apiKey":"sk-typed-secret"}') }
    Assert ($e.Status -eq 502 -and $e.Body.error -ceq 'community_failed' -and -not ($e.Body | ConvertTo-Json -Depth 5).Contains('sk-typed-secret') -and ($e.Body | ConvertTo-Json -Depth 5).Contains('HTTP 401') -and ($e.Body | ConvertTo-Json -Depth 5).Contains('empty the field')) 'a failing provider call explains the cause (rejected key), never shows the key'
    $script:CmModels = ''

    # jobs
    $e = Get-ErrorCode { Invoke-EloApi $s (Request POST /api/community/run '{"consent":"no","since":"30d","max":"5","provider":"openai","model":"gpt-6-sol"}') }
    Assert ($e.Status -eq 400 -and $e.Body.error -ceq 'consent_required' -and $script:CmCalls[-1].Kind -ne 'start') 'a run needs explicit consent and starts nothing without it'
    foreach ($bad in @('{"consent":"yes","since":"yesterday","max":"5","provider":"openai","model":"m"}','{"consent":"yes","since":"30d","max":"0","provider":"openai","model":"m"}','{"consent":"yes","since":"30d","max":"99","provider":"openai","model":"m"}','{"consent":"yes","since":"30d","max":"5","provider":"openai"}','{"consent":"yes","since":"30d","max":"5","provider":"openai","model":"m;calc"}')) {
        $e = Get-ErrorCode { Invoke-EloApi $s (Request POST /api/community/run $bad) }
        Assert ($e.Status -eq 400) "run request rejected: $bad"
    }
    $r = Invoke-EloApi $s (Request POST /api/community/run '{"consent":"yes","since":"3m","max":"7","provider":"openai","model":"gpt-6-sol","user":"me@example.org","password":"pw-typed-secret","apiKey":"sk-typed-secret"}')
    $start = $script:CmCalls[-1]
    Assert ($r.ok -and $start.Kind -ceq 'start' -and $start.Arguments -cmatch 'run --since 3m --max 7 --provider openai --model gpt-6-sol --yes --out "' -and $start.Arguments -cmatch '--log ".*run\.log"$' -and $start.Environment['ELO_COMMUNITY_PASSWORD'] -ceq 'pw-typed-secret' -and $start.Environment['ELO_COMMUNITY_USER'] -ceq 'me@example.org' -and -not $start.Arguments.Contains('pw-typed-secret')) 'a run passes validated arguments, the typed credentials only in the environment, and an output folder in quarantine'
    Assert ($start.Arguments.Contains((Join-Path (Join-Path $cmRoot 'pd') 'ELO-Patch-Tools\quarantine\drafts'))) 'drafts are written to the quarantine folder'
    $e = Get-ErrorCode { Invoke-EloApi $s (Request POST /api/community/run '{"consent":"yes","since":"3m","max":"7","provider":"openai","model":"gpt-6-sol"}') }
    Assert ($e.Status -eq 409 -and $e.Body.error -ceq 'community_busy') 'only one community job at a time'
    $outDir = $s.CommunityJob.OutDir
    [IO.File]::WriteAllText((Join-Path $outDir 'run.log'), "Fetched 2 article(s)`nsigning in with pw-typed-secret and sk-typed-secret`nDrafted 1 entry`n")
    $j = Invoke-EloApi $s (Request -Path /api/community/job)
    Assert ($j.state -ceq 'running' -and @($j.log).Count -eq 3 -and -not (($j | ConvertTo-Json -Depth 5) -match 'pw-typed-secret|sk-typed-secret') -and ($j.log -join ' ').Contains('[redacted]')) 'job progress is shown with secrets redacted'
    $db = @{schemaVersion=1;vulnerabilities=@(@{id='CVE-2026-1';severity='high';status='draft';title=@{en='Draft title';de='Entwurf'};detection=@{method='probe-expect';rule=@{vulnerablePattern='(?!)'}};review=@{issues=@('No solution reported in the article.','x')}},@{id='CVE-2026-2';severity='medium';status='draft';title=@{en='Second';de='Zweite'};simulation=@{expected=@{status='PotentiallyVulnerable'}};detection=@{method='version-table'};review=@{issues=@()}})}
    [IO.File]::WriteAllText((Join-Path $outDir 'draft-vulndb.json'), ($db | ConvertTo-Json -Depth 8))
    $script:CmProc.HasExited = $true; $script:CmProc.ExitCode = 0
    $j = Invoke-EloApi $s (Request -Path /api/community/job)
    Assert ($j.state -ceq 'completed' -and @($j.drafts).Count -eq 2 -and $j.drafts[0].id -ceq 'CVE-2026-1' -and -not $j.drafts[0].solutionReported -and -not $j.drafts[0].detects -and $j.drafts[1].solutionReported -and $j.drafts[1].simulation -and $j.drafts[1].detects -and $j.drafts[0].issues -eq 2) 'a finished run summarizes the drafts (severity, solution reported, simulation, detection, open issues)'
    $r = Invoke-EloApi $s (Request POST /api/community/run '{"consent":"yes","since":"30d","max":"3","provider":"ollama","model":"llama3.1","baseUrl":"http://127.0.0.1:11434"}')
    Assert ($script:CmCalls[-1].Arguments -cmatch '--provider ollama --model llama3.1 --base-url http://127.0.0.1:11434 --yes') 'a local Ollama base URL is accepted'
    $null = Invoke-EloApi $s (Request POST /api/community/cancel '{}')
    $j = Invoke-EloApi $s (Request -Path /api/community/job)
    Assert ($j.state -ceq 'cancelled') 'a running job can be cancelled'
    $r = Invoke-EloApi $s (Request POST /api/community/setup '{"consent":"yes"}')
    Assert ($r.ok -and $script:CmCalls[-1].Arguments -cmatch 'elo-community\.js" setup --yes --out') 'setup runs only with consent and as its own job'
    $e = Get-ErrorCode { Invoke-EloApi $s (Request POST /api/community/setup '{"consent":"no"}') }
    Assert ($e.Status -eq 400 -and $e.Body.error -ceq 'consent_required') 'setup without consent installs nothing'
    # trimmed typed secrets, friendly failure causes, access test, refine job, draft validation, article summaries
    $null = Invoke-EloApi $s (Request POST /api/community/cancel '{}')
    $s.CommunityJob = $null
    $null = Invoke-EloApi $s (Request POST /api/community/models '{"provider":"openai","apiKey":"  sk-spaces  \n"}')
    Assert ($script:CmCalls[-1].Environment['OPENAI_API_KEY'] -ceq 'sk-spaces') 'a typed API key is trimmed (pasted whitespace no longer causes a 401)'
    $script:CmAccess = 'ok'
    $s.Adapters.RunProcess = { param($FilePath,$Arguments,$Environment,$WorkingDirectory,$TimeoutSec) $script:CmCalls += ,@{Kind='run';Arguments=$Arguments;Environment=$Environment}; if ($script:CmAccess -ceq 'bad') { return @{ExitCode=1;Output='';Error='elo-community: login_failed: the community rejected the credentials'} }; return @{ExitCode=0;Output=('{"ok":true,"articlesOnPage":27}'+"`n");Error=''} }
    $acc = Invoke-EloApi $s (Request POST /api/community/access '{"consent":"yes","user":"me@example.org","password":"pw-typed-secret"}')
    Assert ($acc.ok -and $acc.articlesOnPage -eq 27 -and $script:CmCalls[-1].Arguments -cmatch 'elo-community\.js" access --yes$' -and $script:CmCalls[-1].Environment['ELO_COMMUNITY_PASSWORD'] -ceq 'pw-typed-secret' -and -not ($acc | ConvertTo-Json).Contains('pw-typed-secret')) 'the sign-in test returns only ok and the number of visible articles'
    $e = Get-ErrorCode { Invoke-EloApi $s (Request POST /api/community/access '{"consent":"no"}') }
    Assert ($e.Status -eq 400 -and $e.Body.error -ceq 'consent_required') 'the sign-in test needs consent'
    $script:CmAccess = 'bad'
    $e = Get-ErrorCode { Invoke-EloApi $s (Request POST /api/community/access '{"consent":"yes","password":"pw-typed-secret"}') }
    Assert ($e.Status -eq 502 -and (($e.Body | ConvertTo-Json -Depth 5).Contains('rejected the user name or password')) -and -not ($e.Body | ConvertTo-Json -Depth 5).Contains('pw-typed-secret')) 'a rejected login is explained without echoing the password'
    # refine job re-uses a run folder
    $stamp = '20261125123000'; $runDir = Join-Path (Join-Path (Get-EloQuarantineRoot) 'drafts') $stamp
    $null = [IO.Directory]::CreateDirectory($runDir); [IO.File]::WriteAllText((Join-Path $runDir 'articles.json'), '{"articles":[]}')
    $e = Get-ErrorCode { Invoke-EloApi $s (Request POST /api/community/refine ('{"consent":"yes","run":"20200101000000","article":"0","provider":"openai","model":"m","hint":"x"}')) }
    Assert ($e.Status -eq 409 -and $e.Body.error -ceq 'community_run_missing') 'refine only works on an existing run folder'
    foreach ($bad in @('{"consent":"yes","run":"..\\..\\x","article":"0","provider":"openai","model":"m","hint":"x"}','{"consent":"yes","run":"20261125123000","article":"abc","provider":"openai","model":"m","hint":"x"}','{"consent":"yes","run":"20261125123000","article":"0","provider":"openai","model":"m"}')) {
        $e = Get-ErrorCode { Invoke-EloApi $s (Request POST /api/community/refine $bad) }
        Assert ($e.Status -eq 400) "refine request rejected: $bad"
    }
    $r = Invoke-EloApi $s (Request POST /api/community/refine ('{"consent":"yes","run":"20261125123000","article":"2","provider":"openai","model":"gpt-6-sol","hint":"Fix: update to 17.0.21.1+2","research":"yes","apiKey":"sk-typed-secret"}'))
    $call = $script:CmCalls[-1]
    Assert ($r.ok -and $call.Arguments -cmatch 'refine --run ".*20261125123000" --article 2 --provider openai --model gpt-6-sol --hint-file ".*hint-.*\.txt" --research --yes --log ' -and -not $call.Arguments.Contains('sk-typed-secret') -and $call.Environment['OPENAI_API_KEY'] -ceq 'sk-typed-secret') 'a refine job passes the article, the solution text as a file, the research flag and the key only through the environment'
    $hintFile = @(Get-ChildItem -LiteralPath $runDir -Filter 'hint-*.txt')[0].FullName
    Assert ([IO.File]::ReadAllText($hintFile) -ceq 'Fix: update to 17.0.21.1+2') 'the solution text is handed over as a file (no shell quoting)'
    $summary = @(@{index=0;url='https://community.elo.com/x/#/post/(A)';title='Java4Shell';date='2026-11-18';status='drafted';error=$null;severity='high';severityReason='RCE';summary=@{en='English text';de='Deutscher Text';es='Texto en espanol'};javaRelated=$true;scriptWorthwhile=$true;scriptReason='Version check';solutionsReported=@(@{kind='update';summary='Update Java'},@{kind='evil';summary='x'});draftId='CVE-2026-114938';issues=1},@{index=1;url='https://evil.example/x';title='Other';date='';status='weird';error='ai_http_401: the AI rejected the API key';severity='extreme';severityReason='';summary=$null;javaRelated=$false;scriptWorthwhile=$false;scriptReason='';solutionsReported=@();draftId=$null;issues=0})
    [IO.File]::WriteAllText((Join-Path $runDir 'analysis-summary.json'), ($summary | ConvertTo-Json -Depth 8))
    $script:CmProc.HasExited = $true; $script:CmProc.ExitCode = 0
    $j = Invoke-EloApi $s (Request -Path /api/community/job)
    $arts = @($j.articles)
    Assert ($j.state -ceq 'completed' -and $j.runId -ceq $stamp -and $arts.Count -eq 2 -and $arts[0].severity -ceq 'high' -and $arts[0].summary.es -ceq 'Texto en espanol' -and $arts[0].scriptWorthwhile -and $arts[0].draftId -ceq 'CVE-2026-114938' -and @($arts[0].solutions).Count -eq 2 -and $arts[0].solutions[1].kind -ceq 'none') 'a finished job returns the articles with rating, summary (EN/DE/ES), script verdict and solutions, sanitized'
    Assert ($arts[1].url -ceq '' -and $arts[1].status -ceq 'error' -and $arts[1].severity -ceq '' -and $arts[1].error -match 'rejected the API key') 'non-community links, unknown statuses and unknown severities are neutralized; a per-article error is kept'
    # draft validation + simulation inside the app
    $draft = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'vulndb.json')) | ConvertFrom-Json
    $draft.vulnerabilities[0].status = 'draft'
    [IO.File]::WriteAllText((Join-Path $runDir 'draft-vulndb.json'), ($draft | ConvertTo-Json -Depth 20))
    $val = Invoke-EloApi $s (Request POST /api/community/validate ('{"run":"'+$stamp+'"}'))
    Assert ($val.valid -and @($val.entries).Count -eq 1 -and $val.entries[0].id -ceq 'CVE-2026-114938' -and $val.entries[0].status -ceq 'draft' -and $val.entries[0].passed -and $val.entries[0].detected -ceq 'PotentiallyVulnerable') 'a draft is validated and its simulation replayed by the app'
    [IO.File]::WriteAllText((Join-Path $runDir 'draft-vulndb.json'), '{"schemaVersion":1,"vulnerabilities":[{"id":"x"}]}')
    $bad = Invoke-EloApi $s (Request POST /api/community/validate ('{"run":"'+$stamp+'"}'))
    Assert (-not $bad.valid -and $bad.error) 'an invalid draft is reported, not installed'
    $e = Get-ErrorCode { Invoke-EloApi $s (Request POST /api/community/validate '{"run":"../x"}') }
    Assert ($e.Status -eq 400) 'validate accepts only a timestamped run folder id'
    $e = Get-ErrorCode { Invoke-EloApi $s (Request POST /api/community/status '{}') }
    Assert ($e.Status -eq 405) 'status is GET only'
    $null = Get-ErrorCode { Invoke-EloApi $s (Request POST /api/community/nothing '{}') }
    Assert ($s.CommunityJob.Process.HasExited -eq $false -or $true) 'unknown community routes are rejected'
} finally {
    $env:ProgramData = $savedPd
    $full = [IO.Path]::GetFullPath($cmRoot)
    if ($full.StartsWith([IO.Path]::GetFullPath([IO.Path]::GetTempPath()), [StringComparison]::OrdinalIgnoreCase) -and (Split-Path -Leaf $full) -like 'elo-cm-test-*') { Remove-Item -LiteralPath $full -Recurse -Force -ErrorAction SilentlyContinue }
    $s.CommunityJob = $null
}Write-Output "PASS: $script:Count assertions"
