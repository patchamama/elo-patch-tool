# Deterministic Windows PowerShell 5.1 tests: no real scanner or machine writes.
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\vulndb.ps1"
. "$PSScriptRoot\cli.ps1"
$script:checks = 0
function Assert($Condition, $Message) {
    if (-not $Condition) { throw "FAIL: $Message" }
    $script:checks++
}
$script:scanCalls = 0; $script:applyCalls = 0; $script:previewCalls = 0; $script:updatePreviewCalls = 0; $script:updateApplyCalls = 0
$script:seenPath = $null
$scanner = {
    param($ManualPath)
    $script:scanCalls++; $script:seenPath = $ManualPath
    [pscustomobject]@{ Results = @([pscustomobject]@{
        Location = 'D:\ELO Test\jre\bin\java.exe'; Status = 'PotentiallyVulnerable'
        Evidence = 'Temurin evidence'; Source = 'https://example.invalid/advisory'; Build = '17.0.1+1'
    }); Cancelled = $false; Discovery = @{ Coverage = 'bounded test'; Issues = @() } }
}
$actions = @{
    IsAdmin = { $true }
    Preview = { param($Result) $script:previewCalls++; @{ Summary = 'Save old value; global effect'; Token = 'opaque' } }
    Apply = { param($Preview) $script:applyCalls++; @{ ok = $true } }
    UpdatePreview = { param($Result) $script:updatePreviewCalls++; @{ Summary = 'Replace runtime with the newest release; backup kept'; Token = 'opaque' } }
    UpdateApply = { param($Preview) $script:updateApplyCalls++; @{ ok = $true } }
}
$modify = @('--cli','--mitigate','--target','0','--confirm-admin','--confirm-mitigation','--json')
$r = Invoke-EloCli -Arguments $modify -Scanner $scanner -Actions $actions
Assert ($r.ExitCode -ne 0 -and $script:applyCalls -eq 0) 'noninteractive process refuses mutation despite flags'
$script:previewCalls = 0; $script:scanCalls = 0
$script:consoleEvents = New-Object 'System.Collections.Generic.List[string]'
$console = @{
    IsInteractive = { $true }
    Write = { param($Text) $script:consoleEvents.Add([string]$Text) }
    ReadLine = { $script:consoleEvents.Add('READ'); 'APPLY MITIGATION' }
}
function Invoke-InteractiveTestCli {
    param($Arguments, $Scanner, $Actions)
    Invoke-EloCli -Arguments $Arguments -Scanner $Scanner -Actions $Actions -Console $console
}
$script:selfUpdates=0
$onlineActions=@{
    CheckUpdate={ @{Checked=$true;Current='1.4.0';Latest='1.5.0';Available=$true;Catalog=@{Source='downloaded';Updated='2026-12-01';Reason=''}} }
    SelfUpdate={ param($Current,$Expected) $script:selfUpdates++; @{Version=$Expected;Backup='C:\Tools\backup'} }
}
$r = Invoke-EloCli -Arguments @('--cli','--check-update','--json') -Scanner $scanner -Actions $onlineActions
Assert ($r.ExitCode -eq 0 -and (ConvertFrom-Json $r.Output).action.result.Latest -ceq '1.5.0' -and $script:selfUpdates -eq 0 -and $script:scanCalls -eq 0) 'check-update reports and changes nothing'
$r = Invoke-EloCli -Arguments @('--cli','--self-update','--json') -Scanner $scanner -Actions $onlineActions
Assert ($r.ExitCode -ne 0 -and $script:selfUpdates -eq 0) 'self-update needs --confirm-update'
$r = Invoke-EloCli -Arguments @('--cli','--self-update','--confirm-update','--json') -Scanner $scanner -Actions $onlineActions -Console @{IsInteractive={ $false }}
Assert ($r.ExitCode -ne 0 -and $script:selfUpdates -eq 0) 'self-update is refused without an interactive console'
$typed=@{IsInteractive={ $true };Write={ param($Text) };ReadLine={ 'no' }}
$r = Invoke-EloCli -Arguments @('--cli','--self-update','--confirm-update','--json') -Scanner $scanner -Actions $onlineActions -Console $typed
Assert ($r.ExitCode -ne 0 -and $script:selfUpdates -eq 0) 'self-update is cancelled unless the phrase is typed'
$typed.ReadLine={ 'APPLY TOOL UPDATE' }
$r = Invoke-EloCli -Arguments @('--cli','--self-update','--confirm-update','--json') -Scanner $scanner -Actions $onlineActions -Console $typed
Assert ($r.ExitCode -eq 0 -and $script:selfUpdates -eq 1) 'a typed confirmation installs the update'
$r = Invoke-EloCli -Arguments @('--cli','--check-update','--scan','--json') -Scanner $scanner -Actions $onlineActions
Assert ($r.ExitCode -ne 0) 'online modes cannot be combined with other modes'
$r = Invoke-EloCli -Arguments @('--help') -Scanner $scanner
Assert ($r.Output.Contains('--check-update') -and $r.Output.Contains('--self-update') -and $r.Output.Contains('ELO_PATCH_NO_UPDATE_CHECK')) 'help documents the online options'
Assert ($r.ExitCode -eq 0 -and $r.Output -match 'README' -and $r.Output -match 'JAVA_TOOL_OPTIONS') 'complete help'
Assert ($r.Output.Contains('ready fixed or removable drives C: through Z:') -and $r.Output.Contains('\java\bin\java.exe') -and $r.Output.Contains('\ELO\java\bin\java.exe')) 'help specifies drive scope and exact root layouts'
Assert ($r.Output.Contains('after root checks') -and $r.Output.Contains('depth 5') -and $r.Output.Contains('10,000 entries') -and $r.Output -notmatch 'searched before drive roots') 'help specifies optional bounded manual search order'
Assert ($script:scanCalls -eq 0) 'help performs no scan'
foreach ($needle in @('Compress-Archive','Expand-Archive','Stop-Service','Start-Service','Get-FileHash','Rename-Item')) { Assert ($r.Output.Contains($needle)) ('help lists the PowerShell command '+$needle) }
$r = Invoke-EloCli -Arguments @('--cli','--scan','--json','--no-browser','--keep-temp','--manual-path','D:\ELO Test') -Scanner $scanner
$j = $r.Output | ConvertFrom-Json
Assert ($r.ExitCode -eq 0 -and $script:seenPath -ceq 'D:\ELO Test') 'literal spaced path forwarding'
Assert ($j.scan.Results[0].Evidence -ceq 'Temurin evidence') 'raw evidence retained'
Assert ($j.security.verifiedOn -ceq '2026-11-23' -and $j.security.sourceDate -eq '2026-11') 'verification and source dates explicit'
Assert ($j.security.warning -match 'Unknown JVM vendors/builds remain inconclusive') 'unknown vendors remain uncertain'
Assert ($j.security.advisories[0].provenance -match 'directly fetched' -and $j.security.advisories[1].url -ceq 'https://linux.oracle.com/cve/CVE-2026-114938.html') 'direct fetch provenance'
Assert ($j.security.advisories[2].url -cmatch '^https://www\.azul\.com/') 'Azul advisory listed with the fetched sources'
Assert ($j.security.advisories[3].provenance -match 'User-supplied.*not independently fetched') 'OpenJDK supplied text provenance'
Assert ($j.keepTemp -and $j.readOnly) 'headless read-only flags'
foreach ($bad in @(@('--command','whoami'), @('--credential','secret'), @('--manual-path'), @('--scan','--scan'), @('--manual-path','--json'), @('--manual-path','\\host\share'), @('--manual-path','C:\x;whoami'))) {
    $before = $script:scanCalls
    $r = Invoke-EloCli -Arguments $bad -Scanner $scanner -Actions $actions
    Assert ($r.ExitCode -ne 0 -and $before -eq $script:scanCalls) 'invalid options rejected before scanning'
}
foreach ($flags in @(@('--mitigate','--target','0'), @('--mitigate','--target','0','--confirm-admin'), @('--confirm-admin'))) {
    $r = Invoke-EloCli -Arguments $flags -Scanner $scanner -Actions $actions
    Assert ($r.ExitCode -ne 0 -and $script:applyCalls -eq 0) 'explicit confirmations required'
}
# Runtime update from the CLI: same discipline as the mitigation (explicit flags, preview, typed phrase).
foreach ($flags in @(@('--update-runtime','--json'), @('--update-runtime','--target','0','--json'), @('--update-runtime','--target','0','--confirm-admin','--json'), @('--update-runtime','--target','0','--confirm-admin','--confirm-mitigation','--json'), @('--mitigate','--target','0','--confirm-admin','--confirm-update','--json'))) {
    $r = Invoke-EloCli -Arguments $flags -Scanner $scanner -Actions $actions
    Assert ($r.ExitCode -ne 0 -and $script:updateApplyCalls -eq 0 -and $script:applyCalls -eq 0) ('update/mitigation flags must match: '+($flags -join ' '))
}
$updateArgs = @('--cli','--update-runtime','--target','0','--confirm-admin','--confirm-update','--json')
$r = Invoke-EloCli -Arguments $updateArgs -Scanner $scanner -Actions $actions
Assert ($r.ExitCode -ne 0 -and $script:updateApplyCalls -eq 0) 'noninteractive process refuses an update despite flags'
$script:consoleEvents.Clear()
$updateConsole = @{ IsInteractive = { $true }; Write = { param($Text) $script:consoleEvents.Add([string]$Text) }; ReadLine = { $script:consoleEvents.Add('READ'); 'APPLY UPDATE' } }
$script:updatePreviewCalls = 0; $script:updateApplyCalls = 0
$r = Invoke-EloCli -Arguments $updateArgs -Scanner $scanner -Actions $actions -Console $updateConsole
Assert ($r.ExitCode -eq 0 -and $script:updatePreviewCalls -eq 1 -and $script:updateApplyCalls -eq 1 -and $script:applyCalls -eq 0) 'confirmed update runs the update backend once, never the mitigation'
Assert ($script:consoleEvents[0] -like 'Replace runtime*' -and ($script:consoleEvents -join '|') -like '*Type APPLY UPDATE*' -and $script:consoleEvents[-1] -ceq 'READ') 'update preview and typed phrase are shown before reading'
$script:consoleEvents.Clear()
$wrongPhrase = @{ IsInteractive = { $true }; Write = { param($Text) $script:consoleEvents.Add([string]$Text) }; ReadLine = { 'APPLY MITIGATION' } }
$before = $script:updateApplyCalls
$r = Invoke-EloCli -Arguments $updateArgs -Scanner $scanner -Actions $actions -Console $wrongPhrase
Assert ($r.ExitCode -ne 0 -and $script:updateApplyCalls -eq $before -and $r.Output -match 'Update cancelled') 'the mitigation phrase cannot authorize an update'
$script:consoleEvents.Clear()
$script:applyCalls = 0
$r = Invoke-InteractiveTestCli -Arguments $modify -Scanner $scanner -Actions $actions
Assert ($script:consoleEvents[0] -ceq 'Save old value; global effect' -and $script:consoleEvents[2] -ceq 'READ') 'dynamic preview and prompt before input'
Assert ($r.ExitCode -eq 0 -and $script:applyCalls -eq 1 -and $script:previewCalls -eq 1) 'confirmed trusted action once'
Assert (($r.Output | ConvertFrom-Json).action.preview.Summary -match 'global') 'preview preserved in report'
$denied = $actions.Clone(); $denied.IsAdmin = { $false }
$r = Invoke-EloCli -Arguments $modify -Scanner $scanner -Actions $denied
Assert ($r.ExitCode -ne 0 -and $script:applyCalls -eq 1) 'real admin check independent of declaration'
$r = Invoke-EloCli -Arguments $modify -Scanner $scanner
Assert ($r.ExitCode -ne 0) 'missing action backend fails closed'
$r = Invoke-EloCli -Arguments @('--scan','--json') -Scanner { throw 'test failure' }
Assert ($r.ExitCode -ne 0 -and ($r.Output | ConvertFrom-Json).error) 'scanner error is structured failure'
$r = Invoke-EloCli -Arguments @('--scan','--json') -Scanner { @{ Results=@(); Cancelled=$true } }
Assert ($r.ExitCode -ne 0 -and ($r.Output | ConvertFrom-Json).scan.Cancelled) 'cancelled is not successful completion'
$r = Invoke-EloCli -Arguments $modify -Scanner { @{ Results=@(@{Status='KnownFixed'}); Cancelled=$false } } -Actions $actions
Assert ($r.ExitCode -ne 0 -and $script:applyCalls -eq 1) 'ineligible target refused'
$failed = $actions.Clone(); $failed.Apply = { throw 'verification_failed_rolled_back' }
$r = Invoke-InteractiveTestCli -Arguments $modify -Scanner $scanner -Actions $failed
Assert ($r.ExitCode -ne 0 -and $r.Output -match 'verification_failed_rolled_back') 'backend failure not hidden'
$failed.Apply = { @{ ok=$false } }
$r = Invoke-InteractiveTestCli -Arguments $modify -Scanner $scanner -Actions $failed
Assert ($r.ExitCode -ne 0) 'backend must attest success'
$r = Invoke-EloCli -Arguments @('--manual')
Assert ($r.ExitCode -eq 0 -and $r.Output -match 'PrintFlagsFinal' -and $r.Output -match 'restore') 'read-only manual instructions'
$r = Invoke-EloCli -Arguments @('--scan','--json') -Scanner { Write-Error 'probe failed'; @{ Results=@(); Cancelled=$false } }
Assert ($r.ExitCode -ne 0 -and ($r.Output | ConvertFrom-Json).error -match 'probe failed') 'nonterminating scanner errors fail closed'
$r = Invoke-EloCli -Arguments @('--mitigate','--target','999999','--confirm-admin','--confirm-mitigation') -Scanner $scanner -Actions $actions
Assert ($r.ExitCode -ne 0) 'out-of-range index rejected'
$missingPreview = $actions.Clone(); $missingPreview.Preview = { $null }
$before = $script:applyCalls
$r = Invoke-EloCli -Arguments $modify -Scanner $scanner -Actions $missingPreview
Assert ($r.ExitCode -ne 0 -and $script:applyCalls -eq $before) 'missing preview prevents apply'
$r = Invoke-EloCli -Arguments @() -Scanner $scanner
Assert ($r.ExitCode -eq 0 -and $r.Output -match 'Temurin evidence') 'default invocation remains headless scan'
# Interactive consent failures never reach Apply; reports remain a single JSON document.
foreach ($read in @({ 'no' }, { $null }, { 'apply mitigation' }, { throw 'input unavailable' })) {
    $inputConsole = $console.Clone(); $inputConsole.ReadLine = $read
    $before = $script:applyCalls
    $r = Invoke-EloCli -Arguments $modify -Scanner $scanner -Actions $actions -Console $inputConsole
    Assert ($r.ExitCode -ne 0 -and $script:applyCalls -eq $before -and ($r.Output | ConvertFrom-Json).readOnly) 'denial/EOF/input failure cannot mutate'
}
$inputConsole = $console.Clone(); $inputConsole.IsInteractive = { $false }
$inputConsole.ReadLine = { throw 'must not read without console' }
$before = $script:applyCalls
$r = Invoke-EloCli -Arguments $modify -Scanner $scanner -Actions $actions -Console $inputConsole
Assert ($r.ExitCode -ne 0 -and $script:applyCalls -eq $before -and $r.Output -match 'noninteractive action refused') 'no console refuses without reading'
$inputConsole = $console.Clone(); $inputConsole.Write = { throw 'display failed' }
$r = Invoke-EloCli -Arguments $modify -Scanner $scanner -Actions $actions -Console $inputConsole
Assert ($r.ExitCode -ne 0 -and $script:applyCalls -eq $before) 'failed preview display cannot mutate'
$inputConsole = @{
    IsInteractive={ throw 'read-only must not inspect console' }
    Write={ throw 'read-only must not write console' }; ReadLine={ throw 'read-only must not read console' }
}
$r = Invoke-EloCli -Arguments @('--scan','--json') -Scanner $scanner -Console $inputConsole
Assert ($r.ExitCode -eq 0 -and ($r.Output | ConvertFrom-Json).readOnly) 'read-only JSON never accesses console'
$script:adminChecks = 0
$revoked = $actions.Clone(); $revoked.IsAdmin = { $script:adminChecks++; $script:adminChecks -eq 1 }
$r = Invoke-InteractiveTestCli -Arguments $modify -Scanner $scanner -Actions $revoked
Assert ($r.ExitCode -ne 0 -and $script:applyCalls -eq $before -and $script:adminChecks -eq 2) 'admin gate rechecked after consent'
$orderedActions = $actions.Clone()
$orderedActions.Apply = {
    param($Preview)
    Assert ($script:consoleEvents[0] -ceq $Preview.Summary -and $script:consoleEvents[2] -ceq 'READ') 'apply occurs only after preview and input'
    @{ok=$true}
}
$script:consoleEvents.Clear()
$r = Invoke-InteractiveTestCli -Arguments $modify -Scanner $scanner -Actions $orderedActions
Assert ($r.ExitCode -eq 0) 'separate confirmation allows action'
# Exercise the real callable backend with ALL machine adapters replaced by memory.
# Dot-sourcing server.ps1 defines functions only; no host/process/registry is started.
. "$PSScriptRoot\vulndb.ps1"
. "$PSScriptRoot\server.ps1"
. "$PSScriptRoot\scan.ps1"
Assert ((Get-EloCliReadme).Contains('Technical HTML report (web mode)') -and (Get-EloCliReadme).Contains('ELO version remains unknown')) 'help documents sanitized report and unknown ELO API'
$backendScanner = {
    @{ Results=@([pscustomobject]@{
        Location='D:\ELO Test\jre\bin\java.exe'; RuntimeRoot='D:\ELO Test\jre'
        RuntimeRootRationale='test layout'; EloPathRationale='test fixture'
        Status='PotentiallyVulnerable'; Evidence='fixture'; Source='fixture'
        Vendor='Temurin'; Build='17.0.1+1'; FullVersion='17.0.1+1'; Architecture='x64'
    }); Cancelled=$false }
}
function New-TestBackendSession {
    $state = @{ Options=@{ Exists=$true; Value='  -Xmx512m  '; Kind='ExpandString' }; Writes=0; Probes=0; FailSecond=$false }
    $session = New-EloServerSession -Port 54321 -UiHtml 'fixture' -ScanSource 'fixture'
    $session.Adapters = @{
        Admin={ $true }; Clock={ [DateTime]::UtcNow }; Fingerprint={ param($Path) 'unchanged-fixture' }
        ReadOptions={ $state.Options.Clone() }.GetNewClosure()
        WriteOptions={ param($Record) $state.Writes++; $state.Options=$Record.Clone() }.GetNewClosure()
        Verify={ param($Path,$Options) $state.Probes++; -not ($state.FailSecond -and $state.Probes -eq 2) }.GetNewClosure()
    }
    @{ Session=$session; State=$state }
}
foreach ($read in @({ 'no' }, { $null })) {
    $fixture = New-TestBackendSession
    $inputConsole = $console.Clone(); $inputConsole.ReadLine = $read
    $r = Invoke-EloCli -Arguments $modify -Scanner $backendScanner -Actions (New-EloCliBackendAdapters $fixture.Session) -Console $inputConsole
    Assert ($r.ExitCode -ne 0 -and $fixture.State.Writes -eq 0 -and $fixture.State.Probes -eq 0) 'real backend denial/EOF has no writes or flag probes'
    Assert ($fixture.State.Options.Value -ceq '  -Xmx512m  ') 'denial preserves exact existing options'
}
$fixture = New-TestBackendSession
$bridge = New-EloCliBackendAdapters -Session $fixture.Session
$script:consoleEvents.Clear()
$r = Invoke-InteractiveTestCli -Arguments $modify -Scanner $backendScanner -Actions $bridge
Assert ($script:consoleEvents[0].Contains('Previous value: [  -Xmx512m  ]') -and $script:consoleEvents[0].Contains("New value: [$($fixture.State.Options.Value)]")) 'exact current and proposed machine options shown'
Assert ($r.ExitCode -eq 0) "real backend bridge success: $($r.Output)"
Assert ($fixture.State.Writes -eq 1 -and $fixture.State.Probes -eq 2) 'backend performs preflight and readback verification'
Assert ($fixture.State.Options.Value.StartsWith('  -Xmx512m  ') -and $fixture.State.Options.Kind -ceq 'ExpandString') 'existing bytes and registry type preserved in memory'
Assert ($fixture.Session.Backup.Value -ceq '  -Xmx512m  ') 'exact backup retained'
$fixture = New-TestBackendSession; $fixture.State.FailSecond=$true
$bridge = New-EloCliBackendAdapters -Session $fixture.Session
$r = Invoke-InteractiveTestCli -Arguments $modify -Scanner $backendScanner -Actions $bridge
Assert ($r.ExitCode -ne 0 -and $fixture.State.Writes -eq 2) 'backend verification failure invokes rollback'
Assert ($fixture.State.Options.Value -ceq '  -Xmx512m  ') 'rollback restores original bytes'
$fixture = New-TestBackendSession; $fixture.Session.RecoveryRequired=$true
$r = Invoke-EloCli -Arguments $modify -Scanner $backendScanner -Actions (New-EloCliBackendAdapters $fixture.Session)
Assert ($r.ExitCode -ne 0 -and $fixture.State.Writes -eq 0) 'pending recovery rejects bridge action'
# ---- catalog maintenance commands (temp ProgramData; nothing machine-wide is touched)
$catalogFile = Join-Path $PSScriptRoot 'vulndb.json'
$admin = @{ IsAdmin = { $true } }
$r = Invoke-EloCli -Arguments @('--cli','--catalog-validate',$catalogFile,'--json') -Actions $admin
$j = $r.Output | ConvertFrom-Json
Assert ($r.ExitCode -eq 0 -and $j.action.result.valid -eq $true -and $j.action.result.vulnerabilities[0].id -ceq 'CVE-2026-114938' -and $j.readOnly -eq $true) 'catalog validate is read-only and lists the entries'
$r = Invoke-EloCli -Arguments @('--cli','--catalog-simulate','CVE-2026-114938','--json') -Actions $admin
$j = $r.Output | ConvertFrom-Json
Assert ($r.ExitCode -eq 0 -and $j.action.result.Passed -eq $true -and $j.action.result.Status -ceq 'PotentiallyVulnerable') 'catalog simulate reproduces the vulnerable verdict'
foreach ($bad in @(@('--catalog-simulate','a b'),@('--catalog-simulate','CVE-9999-0000'),@('--catalog-validate','relative.json'),@('--catalog-validate','C:\no-such-file.json'),@('--catalog-install',$catalogFile),@('--catalog-restore','x'),@('--catalog-list','--confirm-admin'),@('--catalog-validate',$catalogFile,'--scan'),@('--catalog-validate',$catalogFile,'--target','0'),@('--catalog-validate'))) {
    $r = Invoke-EloCli -Arguments (@('--cli') + $bad + @('--json')) -Actions $admin
    Assert ($r.ExitCode -ne 0) ('catalog command refused: ' + ($bad -join ' '))
}
# A draft file (e.g. produced by the AI helper) is simulated entry by entry without being installed.
$draftDb = [IO.File]::ReadAllText($catalogFile) | ConvertFrom-Json
$draftEntry = $draftDb.vulnerabilities[0] | ConvertTo-Json -Depth 20 | ConvertFrom-Json
$draftEntry.id = 'ELO-DRAFT-FLAG'; $draftEntry.status = 'draft'; $draftEntry.severity = 'medium'
$draftEntry.detection = [pscustomobject]@{ method = 'probe-expect'; probes = @([pscustomobject]@{ id = 'flags'; args = @('-XX:+PrintFlagsFinal','-version'); timeoutSec = 10; expect = @() }); rule = [pscustomobject]@{ probe = 'flags'; vulnerablePattern = '(?m)^\s*bool\s+TestFlag\s*=\s*true' } }
$draftEntry.simulation = [pscustomobject]@{ description = 'flag on'; probes = [pscustomobject]@{ flags = '     bool TestFlag = true {product}' }; expected = [pscustomobject]@{ status = 'PotentiallyVulnerable' } }
$draftDb.vulnerabilities = @($draftDb.vulnerabilities[0], $draftEntry)
$draftFile = Join-Path ([IO.Path]::GetTempPath()) ('elo-cli-draft-' + [guid]::NewGuid().ToString('N') + '.json')
try {
    [IO.File]::WriteAllText($draftFile, ($draftDb | ConvertTo-Json -Depth 20))
    $r = Invoke-EloCli -Arguments @('--cli','--catalog-simulate',$draftFile,'--json') -Actions $admin
    $j = $r.Output | ConvertFrom-Json
    $results = @($j.action.result)
    Assert ($r.ExitCode -eq 0 -and $results.Count -eq 2 -and $results[0].passed -eq $true -and $results[1].id -ceq 'ELO-DRAFT-FLAG' -and $results[1].status -ceq 'draft' -and $results[1].passed -eq $true -and $results[1].detected -ceq 'PotentiallyVulnerable') 'a draft catalog file is simulated entry by entry (probe-expect and version-table)'
} finally { Remove-Item -LiteralPath $draftFile -Force -ErrorAction SilentlyContinue }$r = Invoke-EloCli -Arguments @('--cli','--catalog-install',$catalogFile,'--json') -Actions @{ IsAdmin = { $false } }
Assert ($r.ExitCode -ne 0) 'catalog install without --confirm-admin is refused'
$tmpPd = Join-Path ([IO.Path]::GetTempPath()) ('elo-cli-pd-' + [guid]::NewGuid().ToString('N'))
$savedPd = $env:ProgramData
try {
    $env:ProgramData = $tmpPd
    $r = Invoke-EloCli -Arguments @('--cli','--catalog-install',$catalogFile,'--confirm-admin','--json') -Actions @{ IsAdmin = { $false } }
    Assert ($r.ExitCode -ne 0 -and -not (Test-Path (Join-Path $tmpPd 'ELO-Patch-Tools\vulndb.json'))) 'catalog install needs a real administrator'
    $r = Invoke-EloCli -Arguments @('--cli','--catalog-install',$catalogFile,'--confirm-admin','--json') -Actions $admin
    Assert ($r.ExitCode -eq 0 -and (Test-Path (Join-Path $tmpPd 'ELO-Patch-Tools\vulndb.json'))) 'catalog install copies a validated catalog'
    $r = Invoke-EloCli -Arguments @('--cli','--catalog-install',$catalogFile,'--confirm-admin','--json') -Actions $admin
    $j = $r.Output | ConvertFrom-Json
    Assert ($r.ExitCode -eq 0 -and $j.action.result.quarantinedPrevious) 'a second install quarantines the previous catalog'
    $r = Invoke-EloCli -Arguments @('--cli','--catalog-list','--json') -Actions $admin
    $j = $r.Output | ConvertFrom-Json
    Assert ($r.ExitCode -eq 0 -and @($j.action.result).Count -eq 1 -and $j.readOnly -eq $true) 'quarantine listing shows the quarantined copy'
    $r = Invoke-EloCli -Arguments @('--cli','--catalog-restore',[string]@($j.action.result)[0].id,'--confirm-admin','--json') -Actions $admin
    Assert ($r.ExitCode -eq 0) 'quarantined catalog can be restored'
} finally {
    $env:ProgramData = $savedPd
    $full = [IO.Path]::GetFullPath($tmpPd)
    if ($full.StartsWith([IO.Path]::GetFullPath([IO.Path]::GetTempPath()), [StringComparison]::OrdinalIgnoreCase) -and (Split-Path -Leaf $full) -like 'elo-cli-pd-*') { Remove-Item -LiteralPath $full -Recurse -Force -ErrorAction SilentlyContinue }
}
Write-Output "PASS: $script:checks CLI assertions"
