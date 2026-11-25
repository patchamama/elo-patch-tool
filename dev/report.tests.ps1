$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/vulndb.ps1"
. "$PSScriptRoot/report.ps1"
function Assert($Condition, [string]$Message) { if (-not $Condition) { throw "FAIL: $Message" } }
$resources = {
    @{ ServerName='TEST-SERVER'; WindowsVersion='10.0'; WindowsBuild='20348'; TotalRamBytes=17179869184;
       Disks=@(@{Name='C:';TotalBytes=107374182400;FreeBytes=53687091200}) }
}
$report = New-EloTechnicalReport -ResourceCollector $resources
Assert ($report.System.ServerName -eq 'TEST-SERVER') 'injected server'
Assert ($report.Elo.Status -eq 'Unknown') 'no invented ELO version'
Assert ($report.Elo.MissingContract -match 'authentication.*version.*response') 'exact missing contract'
foreach ($language in @('en','de')) {
    $html = ConvertTo-EloTechnicalReportHtml -Report $report -Language $language
    foreach ($value in @('TEST-SERVER','10.0','20348','16.00 GiB','100.00 GiB','50.00 GiB','https://linux.oracle.com/cve/CVE-2026-114938.html')) {
        Assert ($html.Contains($value)) "render $value in $language"
    }
    Assert ($html -notmatch 'password|secret-token') 'no credential text'
}
Assert ((ConvertTo-EloTechnicalReportHtml $report en) -match 'Not performed') 'English state'
Assert ((ConvertTo-EloTechnicalReportHtml $report de) -match 'Nicht ausgef') 'German state'
$actions = @(
    @{Kind='Update';Status='Proven';Verified=$false;ToVersion='99.0.1'},
    @{RuntimeIndex=1;Kind='Mitigation';Status='Proven';Verified=$true;EvidenceVerified=$true;EvidenceCode='EffectiveJvmFlagObserved'},
    @{RuntimeIndex=1;Kind='Backup';Status='Proven';Verified=$true;BackupVersion='17.0.10';BackupVerified=$true;EvidenceVerified=$true;EvidenceCode='BackupManifestMatched'},
    @{Kind='Restore';Status='Failed';Message='password=secret-token'}
)
$known = New-EloTechnicalReport -ResourceCollector $resources -JvmEvidence @(@{Version='17.0.10';Verified=$true},@{Version='99.0.1';Verified=$false}) -Actions $actions -EloVersionAdapter { @{Verified=$true;Version='23.0.1'} }
Assert ($known.Elo.Version -eq '23.0.1') 'synthetic trusted ELO version'
Assert ($known.Actions[0].Status -eq 'Unknown') 'unverified success downgraded'
Assert ($known.Jvms[1].Version -eq $null) 'unverified JVM omitted'
Assert ($known.Jvms[0].ExecutionStatus -eq 'Unknown') 'detection does not imply execution'
$executed = New-EloTechnicalReport -ResourceCollector $resources -JvmEvidence @(@{Version='21.0.1';Verified=$true;ExecutionVerified=$true})
Assert ($executed.Jvms[0].ExecutionStatus -eq 'Proven') 'synthetic execution proof'
Assert ((ConvertTo-EloTechnicalReportHtml $executed en).Contains('Execution evidence: Verified')) 'execution evidence rendered'
$html = ConvertTo-EloTechnicalReportHtml $known en
Assert ($html.Contains('-XX:-UseBASE64Intrinsics')) 'verified mitigation'
Assert ($html.Contains('17.0.10')) 'verified backup version'
Assert (-not $html.Contains('99.0.1')) 'unproven update absent'
Assert (-not $html.Contains('secret-token')) 'raw error omitted'
Assert ($html.Contains('Failed')) 'failed distinct'
$bad = New-EloTechnicalReport -ResourceCollector { throw 'password=secret-token' } -EloVersionAdapter { throw 'secret-token' }
Assert ($bad.System.Status -eq 'Failed') 'collector failure'
Assert ($bad.Elo.Status -eq 'Failed') 'ELO adapter failure'
Assert (-not (ConvertTo-EloTechnicalReportHtml $bad en).Contains('secret-token')) 'exceptions suppressed'
$unsafe = New-EloTechnicalReport -ResourceCollector { @{ServerName='<script>secret-token</script>';WindowsVersion='password=secret-token';WindowsBuild='1';TotalRamBytes=-1;Disks=@(@{Name='https://u:secret-token@host/';TotalBytes=1;FreeBytes=2})} } -JvmEvidence @(@{Verified=$true;Version='<img src=x>'}) -EloVersionAdapter { @{Verified=$true;Version='password=secret-token'} }
$html = ConvertTo-EloTechnicalReportHtml $unsafe en
Assert ($html -notmatch 'secret-token|<script>|<img') 'unsafe fields rejected'
Assert ($unsafe.System.Disks.Count -eq 0) 'invalid disk rejected'
Assert ($unsafe.Elo.Status -eq 'Unknown') 'invalid ELO version rejected'
Assert ((ConvertTo-EloReportEscapedText ('<>&"' + [char]39)) -eq '&lt;&gt;&amp;&quot;&#39;') 'HTML encoding'
$proven = New-EloTechnicalReport -ResourceCollector $resources -JvmEvidence @(@{Version='17.0.9';Verified=$true}) -Actions @(@{RuntimeIndex=1;Kind='Update';Status='Proven';Verified=$true;FromVersion='17.0.9';ToVersion='17.0.10';EvidenceVerified=$true;EvidenceCode='InstalledRuntimeValidated'},@{Kind='Backup';Status='Proven';Verified=$true;BackupVerified=$false;BackupVersion='17.0.9'})
Assert ($proven.Actions[0].ToVersion -eq '17.0.10') 'verified update shown'
$backup = @($proven.Actions | Where-Object { $_.Kind -eq 'Backup' })[0]
Assert ($backup.Status -eq 'Unknown') 'backup requires archive verification'
Assert ($backup.BackupVersion -eq $null) 'unverified backup version omitted'
foreach ($status in @('Unknown','Failed','NotPerformed')) {
    $r = New-EloTechnicalReport -ResourceCollector $resources -Actions @(@{Kind='Update';Status=$status;Verified=$true;ToVersion='99.0.1'})
    Assert ($r.Actions[0].Status -eq $status) "preserve $status"
    Assert ($null -eq $r.Actions[0].ToVersion) 'no version for non-success'
}
$untrusted = New-EloTechnicalReport -ResourceCollector { $null } -JvmEvidence @(@{Version='21.0.1';Verified='true'}) -Actions @(@{Kind='Mitigation';Status='Proven';Verified='true'}) -EloVersionAdapter { @{Version='23.0.1';Verified='true'} }
Assert ($untrusted.System.Status -eq 'Unknown') 'absent resources unknown'
Assert ($untrusted.Jvms[0].Status -eq 'Unknown') 'string is not JVM proof'
Assert ($untrusted.Elo.Status -eq 'Unknown') 'string is not ELO proof'
Assert (-not (ConvertTo-EloTechnicalReportHtml $untrusted de).Contains('-XX:-UseBASE64Intrinsics')) 'string is not mitigation proof'
$known.System.ServerName='<svg onload=alert(1)>'
$known.Elo.Version='<img src=x>'
$known.Actions[0].ToVersion='password=secret-token'
$html=ConvertTo-EloTechnicalReportHtml $known en
Assert ($html -notmatch '<svg|<img|secret-token') 'renderer normalizes forged DTO'
Assert (($unsafe | ConvertTo-Json -Depth 10) -notmatch 'secret-token') 'DTO excludes secrets as well as HTML'
Assert (-not (ConvertTo-EloTechnicalReportHtml $report de).Contains('Authentifizierungsmethode')) 'an unavailable ELO version is not announced in the report'
Assert ((ConvertTo-EloTechnicalReportHtml $proven en).Contains('17.0.9')) 'old version retained for verified update'
$detailed = New-EloTechnicalReport -ResourceCollector $resources -JvmEvidence @(
    @{Version='17.0.10';Verified=$true;Classification='PotentiallyVulnerable';ClassificationVerified=$true;EvidenceCode='AdvisoryRangeMatch'},
    @{Version='21.0.1';Verified=$true;Classification='NotAffected';ClassificationVerified=$false;EvidenceCode='AdvisoryExcludesVersion'}
) -Actions @(
    @{RuntimeIndex=1;Kind='Mitigation';Status='Proven';Verified=$true;EvidenceVerified=$true;EvidenceCode='EffectiveJvmFlagObserved'},
    @{RuntimeIndex=1;Kind='Update';Status='Failed';EvidenceVerified=$true;EvidenceCode='DownloadFailed'},
    @{RuntimeIndex=1;Kind='Backup';Status='Proven';Verified=$true;BackupVerified=$true;BackupVersion='17.0.10';EvidenceVerified=$true;EvidenceCode='BackupManifestMatched'},
    @{RuntimeIndex=1;Kind='Restore';Status='Proven';Verified=$true;ToVersion='17.0.10';EvidenceVerified=$true;EvidenceCode='OriginalRuntimeRestored'}
)
Assert ($detailed.Jvms[0].Classification -eq 'PotentiallyVulnerable') 'bounded classification retained'
Assert ($detailed.Jvms[1].Classification -eq 'Unknown') 'classification requires proof'
Assert ($detailed.Actions[0].RuntimeIndex -eq 1) 'action associated with JVM'
foreach ($lang in @('en','de')) {
    $h=ConvertTo-EloTechnicalReportHtml $detailed $lang
    foreach ($uri in @('https://openjdk.org/groups/vulnerability/advisories/2026-11-17','https://linux.oracle.com/cve/CVE-2026-114938.html','https://adoptium.net/news/2026/11/temurin-november-2026-cspu-java4shell/')) { Assert ($h.Contains($uri)) 'exact advisory source' }
    Assert ($h.Contains('2026-11-23') -and $h.Contains('403')) 'verification date and source limits'
    Assert ($h.Contains('JVM #1')) 'JVM association rendered'
    Assert ($h.Contains('-XX:-UseBASE64Intrinsics')) 'verified effective flag'
    if ($lang -eq 'en') {
        foreach ($text in @('Potentially vulnerable','Matched advisory affected-version range','Download failed','Backup contents matched original manifest','Original runtime restored and verified','Advisories may change')) { Assert ($h.Contains($text)) "English evidence: $text" }
    } else {
        foreach ($text in @('Potenziell verwundbar','Betroffene Versionsspanne','Download fehlgeschlagen','Sicherungsinhalt','Urspruengliche Runtime','Hinweise koennen sich aendern')) { Assert ($h.Contains($text)) "German evidence: $text" }
    }
}
$rejected = New-EloTechnicalReport -ResourceCollector $resources -JvmEvidence @(@{Version='17.0.10';Verified=$true;Classification='<script>password=secret-token</script>';ClassificationVerified=$true;EvidenceCode='https://u:secret-token@host/'}) -Actions @(
    @{RuntimeIndex=99;Kind='Mitigation';Status='Proven';Verified=$true;EvidenceVerified=$true;EvidenceCode='EffectiveJvmFlagObserved'},
    @{RuntimeIndex=1;Kind='Restore';Status='Failed';EvidenceVerified=$true;EvidenceCode='<img src=x>secret-token';Message='password=secret-token'}
)
Assert ($rejected.Jvms[0].Classification -eq 'Unknown') 'unknown classification rejected'
Assert ($rejected.Actions[1].Status -eq 'Unknown') 'unassociated mitigation not proven'
Assert (($rejected | ConvertTo-Json -Depth 10) -notmatch 'secret-token|<script>|<img') 'evidence DTO privacy'
Assert ((ConvertTo-EloTechnicalReportHtml $rejected en) -notmatch 'secret-token|<script>|<img') 'evidence HTML privacy'
$missingProof = New-EloTechnicalReport -ResourceCollector $resources -JvmEvidence @(@{Version='17.0.10';Verified=$true}) -Actions @(@{RuntimeIndex=1;Kind='Mitigation';Status='Proven';Verified=$true;EvidenceCode='EffectiveJvmFlagObserved';EvidenceVerified='true'})
Assert ($missingProof.Actions[1].Status -eq 'Unknown') 'explicit mitigation evidence requires boolean proof'
$alternates = New-EloTechnicalReport -ResourceCollector $resources -JvmEvidence @(
    @{Version='21.0.1';Verified=$true;Classification='NotAffected';ClassificationVerified=$true;EvidenceCode='AdvisoryExcludesVersion'},
    @{Version='25.0.1';Verified=$true;Classification='Fixed';ClassificationVerified=$true;EvidenceCode='AdvisoryFixedVersion'},
    @{Version='25.0.1';Verified=$true;Classification='Fixed';ClassificationVerified=$true;EvidenceCode='AdvisoryRangeMatch'}
) -Actions @(
    @{RuntimeIndex=2;Kind='Update';Status='Proven';Verified=$true;EvidenceVerified=$true;EvidenceCode='InstalledRuntimeValidated';FromVersion='25.0.0';ToVersion='25.0.1'},
    @{RuntimeIndex=1;Kind='Restore';Status='Failed';EvidenceVerified=$true;EvidenceCode='RestoreFailed'},
    @{RuntimeIndex=3;Kind='Update';Status='Failed';EvidenceVerified=$true;EvidenceCode='ValidationFailed';ToVersion='99.0.1'},
    @{RuntimeIndex=1;Kind='Backup';Status='Proven';Verified=$true;BackupVerified=$true;EvidenceVerified=$true;EvidenceCode='EffectiveJvmFlagObserved'}
)
Assert ($alternates.Jvms[0].Classification -eq 'NotAffected') 'verified exclusion'
Assert ($alternates.Jvms[1].Classification -eq 'Fixed') 'verified fixed classification'
Assert ($alternates.Jvms[2].Classification -eq 'Unknown') 'mismatched classification evidence rejected'
$h=ConvertTo-EloTechnicalReportHtml $alternates en
foreach ($text in @('Runtime association: JVM #2','Installed runtime manifest and version probe verified','Restoration failed; manual recovery required','Postcondition validation failed')) { Assert ($h.Contains($text)) "alternate evidence: $text" }
Assert (-not $h.Contains('99.0.1')) 'failed validation not reported as installed version'
$backup = @($alternates.Actions | Where-Object { $_.Kind -eq 'Backup' })[0]
Assert ($backup.Status -eq 'Unknown' -and $backup.EvidenceCode -eq 'Unknown') 'kind-mismatched proof rejected'
Assert ($h -notmatch 'https://www.oracle.com/security-alerts/|https://help.elo.com/') 'generic sources replaced'
foreach ($scopeCode in @('MachineOptionSet','NewlyLaunchedJvmFlagVerified','RunningEloJvmFlagVerified')) {
    $scoped = New-EloTechnicalReport -ResourceCollector $resources -JvmEvidence @(@{Version='17.0.10';Verified=$true;Vendor='Temurin';VendorVerified=$true}) -Actions @(@{RuntimeIndex=1;Kind='Mitigation';Status='Proven';Verified=$true;EvidenceVerified=$true;EvidenceCode=$scopeCode})
    $a=@($scoped.Actions | Where-Object { $_.Kind -eq 'Mitigation' })[0]
    Assert ($a.Status -eq 'Proven') "scoped mitigation $scopeCode"
    foreach ($lang in @('en','de')) {
        $h=ConvertTo-EloTechnicalReportHtml $scoped $lang
        Assert ($h.Contains('https://adoptium.net/temurin/releases') -and $h.Contains('https://adoptium.net/installation/')) 'verified provider links'
        if ($lang -eq 'en') {
            Assert ($h.Contains('not a permanent fix') -and $h.Contains('after ELO compatibility confirmation')) 'temporary and compatibility advice'
            Assert ($h.Contains('does not install a Java runtime')) 'flag-only method identified'
            if ($scopeCode -ne 'RunningEloJvmFlagVerified') { Assert (-not $h.Contains('Current running ELO process flag')) 'no running ELO proof inferred' }
            if ($scopeCode -eq 'MachineOptionSet') {
                Assert ($h.Contains('Machine option set: Verified')) 'machine setting proof'
                Assert (-not $h.Contains('Newly launched JVM flag')) 'machine setting does not prove launch'
            }
            if ($scopeCode -eq 'NewlyLaunchedJvmFlagVerified') { Assert ($h.Contains('Newly launched JVM flag: Verified')) 'launch proof' }
            if ($scopeCode -eq 'RunningEloJvmFlagVerified') { Assert ($h.Contains('Current running ELO process flag: Verified')) 'explicit ELO proof' }
        } else {
            Assert ($h.Contains('keine dauerhafte Behebung') -and $h.Contains('nach ELO-Kompatibilitaetsbestaetigung')) 'German advice'
            Assert ($h.Contains('installiert keine Java-Runtime')) 'German flag-only method'
            if ($scopeCode -ne 'RunningEloJvmFlagVerified') { Assert (-not $h.Contains('Flag des aktuell laufenden ELO-Prozesses')) 'German unknown ELO scope' }
        }
    }
    Assert ($scoped.Jvms[0].Classification -eq 'Unknown') 'mitigation does not classify as fixed'
    Assert ($scoped.Actions[0].Status -eq 'NotPerformed') 'mitigation does not invent update'
}
foreach ($vendor in @('Unknown','Oracle','Temurin','<img>password=secret-token')) {
    $unknownVendor = New-EloTechnicalReport -ResourceCollector $resources -JvmEvidence @(@{Version='17.0.10';Verified=$true;Vendor=$vendor;VendorVerified=$false}) -Actions @(@{RuntimeIndex=1;Kind='Mitigation';Status='Proven';Verified=$true;EvidenceCode='MachineOptionSet';EvidenceVerified='true'})
    foreach ($lang in @('en','de')) {
        $h=ConvertTo-EloTechnicalReportHtml $unknownVendor $lang
        Assert ($h -notmatch 'https://adoptium.net/temurin/releases|https://adoptium.net/installation/|secret-token|<img>') 'unknown vendor no provider replacement or injection'
        if ($lang -eq 'en') { Assert (-not $h.Contains('JVM vendor unknown')) 'an unknown vendor is simply not mentioned' }
        else { Assert (-not $h.Contains('JVM-Anbieter unbekannt')) 'an unknown vendor is simply not mentioned (German)' }
        Assert ($h -notmatch 'Machine option set: Verified|Maschinenoption gesetzt: Nachgewiesen') 'nonboolean scoped proof rejected'
    }
}
$zuluReport = New-EloTechnicalReport -ResourceCollector $resources -JvmEvidence @(@{Version='21.0.1+12-LTS';Verified=$true;ExecutionVerified=$true;Vendor='Azul Zulu';VendorVerified=$true})
Assert ($zuluReport.Jvms[0].Vendor -ceq 'Azul Zulu' -and $zuluReport.Jvms[0].Classification -ceq 'Unknown') 'Zulu vendor survives without fixed classification'
Assert ((ConvertTo-EloTechnicalReportHtml $zuluReport 'en').Contains('https://docs.azul.com/core/install/windows') -and (ConvertTo-EloTechnicalReportHtml $zuluReport 'de').Contains('https://www.azul.com/downloads/'))  'Zulu report links to the vendor download and installation guide'
Assert ($zuluReport.Jvms[0].Version -ceq '21.0.1+12-LTS') 'Zulu version survives report sanitization'
$zuluClaim = New-EloTechnicalReport -ResourceCollector $resources -JvmEvidence @(@{Version='21.0.13.1+2';Verified=$true;Vendor='Azul Zulu';VendorVerified=$true;Classification='Fixed';ClassificationVerified=$true;EvidenceCode='AdvisoryFixedVersion'})
Assert ($zuluClaim.Jvms[0].Classification -ceq 'Unknown') 'No unsupported Zulu fixed classification accepted'
foreach ($lang in @('en','de')) {
    $zuluHtml=ConvertTo-EloTechnicalReportHtml $zuluReport $lang
    Assert ($zuluHtml.Contains('Azul Zulu') -and $zuluHtml -notmatch 'https://adoptium.net/temurin/releases|https://adoptium.net/installation/') 'Zulu guidance does not suggest Temurin as same provider'
}
$otherVendor = New-EloTechnicalReport -ResourceCollector $resources -JvmEvidence @(@{Version='17.0.10';Verified=$true;Vendor='Oracle';VendorVerified=$true})
Assert ($otherVendor.Jvms[0].Vendor -eq 'Unknown') 'unsupported vendor stays unknown even if asserted'
Assert ((ConvertTo-EloTechnicalReportHtml $otherVendor en) -notmatch 'https://adoptium.net/temurin/releases|https://adoptium.net/installation/') 'no provider substitution'
foreach ($state in @('Failed','Unknown','NotPerformed')) {
    $notMitigated = New-EloTechnicalReport -ResourceCollector $resources -JvmEvidence @(@{Version='17.0.10';Verified=$true}) -Actions @(@{RuntimeIndex=1;Kind='Mitigation';Status=$state;Verified=$true;EvidenceVerified=$true;EvidenceCode='RunningEloJvmFlagVerified';ToVersion='99.0.1'})
    $h=ConvertTo-EloTechnicalReportHtml $notMitigated en
    Assert (-not $h.Contains('Current running ELO process flag')) 'non-success never proves running ELO scope'
    Assert ($h -notmatch '99.0.1|-XX:-UseBASE64Intrinsics') 'non-success omits version and applied flag'
}
$legacy = New-EloTechnicalReport -ResourceCollector $resources -JvmEvidence @(@{Version='17.0.10';Verified=$true}) -Actions @(@{RuntimeIndex=1;Kind='Mitigation';Status='Proven';Verified=$true;EvidenceVerified=$true;EvidenceCode='EffectiveJvmFlagObserved'})
$h=ConvertTo-EloTechnicalReportHtml $legacy en
Assert ($h.Contains('scope unspecified, current ELO process not verified')) 'legacy evidence not upgraded to ELO proof'
Assert (-not $h.Contains('Current running ELO process flag')) 'legacy current process unknown'
Assert (-not (ConvertTo-EloTechnicalReportHtml $report en).Contains('JVM vendor unknown')) 'empty scan does not assume a vendor and does not print a placeholder'
$observed = New-EloTechnicalReport -ResourceCollector $resources -OptionsCollector { @{Machine='-XX:-UseBASE64Intrinsics password=secret-token';User='-XX:+UseBASE64Intrinsics';Process='-XX:-UseBASE64Intrinsics'} }
Assert ($observed.Options.Machine -eq 'Present' -and $observed.Options.User -eq 'Conflict' -and $observed.Options.Process -eq 'Present') 'scope observations'
Assert (($observed | ConvertTo-Json -Depth 10) -notmatch 'secret-token') 'options never retained'
foreach ($lang in @('en','de')) { $h=ConvertTo-EloTechnicalReportHtml $observed $lang; Assert ($h -notmatch 'secret-token') 'options not rendered'; Assert ($h.Contains('JAVA_TOOL_OPTIONS')) 'options section' }
$failed = New-EloTechnicalReport -ResourceCollector $resources -Actions @(@{Kind='Update';Status='Failed'})
Assert ((ConvertTo-EloTechnicalReportHtml $failed en).Contains('Manual recovery') -and -not (ConvertTo-EloTechnicalReportHtml $failed en).Contains('Expand-Archive')) 'failed update without evidence shows guidance but no invented command'
$recoverActions=@(@{Kind='Update';Status='Failed';RuntimeIndex=1},@{Kind='Backup';Status='Proven';RuntimeIndex=1;Verified=$true;BackupVerified=$true;EvidenceVerified=$true;EvidenceCode='BackupManifestMatched'})
$evidence=@{Validated=$true;RuntimeIndex=1;Archive="C:\backups\java's.zip";Original='C:\ELO\java';Destination='C:\isolated\recovery'}
$recoveryReport=New-EloTechnicalReport -ResourceCollector $resources -OptionsCollector { $null } -JvmEvidence @(@{Version='17.0.10';Verified=$true}) -Actions $recoverActions -RecoveryEvidence $evidence
foreach ($lang in @('en','de')) {
    $h=ConvertTo-EloTechnicalReportHtml $recoveryReport $lang
    Assert ($h.Contains('Expand-Archive -LiteralPath') -and $h.Contains('java&#39;&#39;s.zip') -and $h.Contains('C:\ELO\java')) 'verified recovery escaped and rendered'
    Assert ($h.Contains('Remove-Item -LiteralPath') -and $h.Contains('Move-Item -LiteralPath') -and $h.Contains('tar -xf') -and $h.Contains('rmdir /s /q') -and $h.Contains('C:\isolated\recovery\tree') -and $h -notmatch '--restore') 'PowerShell and cmd restore commands, no invented CLI'
}
$onlyBackup=New-EloTechnicalReport -ResourceCollector $resources -OptionsCollector { $null } -JvmEvidence @(@{Version='17.0.10';Verified=$true}) -Actions @($recoverActions[1]) -RecoveryEvidence $evidence
Assert ((ConvertTo-EloTechnicalReportHtml $onlyBackup en).Contains('Expand-Archive')) 'restore commands are offered after a successful update too'
$evidence.Validated=$false
$noRecovery=New-EloTechnicalReport -ResourceCollector $resources -OptionsCollector { $null } -JvmEvidence @(@{Version='17.0.10';Verified=$true}) -Actions $recoverActions -RecoveryEvidence $evidence
Assert (-not (ConvertTo-EloTechnicalReportHtml $noRecovery en).Contains('Expand-Archive')) 'unverified archive never yields command'
$conflict=New-EloTechnicalReport -ResourceCollector $resources -OptionsCollector { @{Machine='-XX:-UseBASE64Intrinsics -XX:+UseBASE64Intrinsics';User='-XX:-UseBASE64IntrinsicsExtra';Process=$null} }
Assert ($conflict.Options.Machine -eq 'Conflict' -and $conflict.Options.User -eq 'Absent' -and $conflict.Options.Process -eq 'Absent') 'conflicts and exact token matching'
# ELO version from the installed Indexserver files (read-only, bounded, no network).
$eloScratch=Join-Path ([IO.Path]::GetTempPath()) ('elo-version-test-'+[guid]::NewGuid().ToString('N'))
try {
    foreach ($spec in @(@('inst1','ix-a','Change history of ELO Indexserver',"","25.00.010.476816 2025-12-05","24.00.099.1 2024-01-01"), @('inst2','ix-b','x','25.00.011.000002 2026-01-01'), @('inst3','im-ignored','25.99.999.999 2099-01-01'), @('inst4','ix-c','no version here'))) {
        $dir=Join-Path $eloScratch ('servers\'+$spec[0]+'\webapps\'+$spec[1]); $null=[IO.Directory]::CreateDirectory($dir)
        [IO.File]::WriteAllLines((Join-Path $dir 'version.txt'),[string[]]$spec[2..($spec.Count-1)])
    }
    Assert ((Get-EloInstalledIndexserverVersion @($eloScratch)) -ceq '25.00.011.000002') 'highest installed Indexserver version wins; only ix-* webapps count'
    Assert ($null -eq (Get-EloInstalledIndexserverVersion @((Join-Path $eloScratch 'missing'),$null,''))) 'no ELO files means unknown, never invented'
    $big=Join-Path $eloScratch 'servers\inst5\webapps\ix-big'; $null=[IO.Directory]::CreateDirectory($big)
    [IO.File]::WriteAllText((Join-Path $big 'version.txt'),('x'*(9*1MB))+"`n26.00.000.1`n")
    Assert ((Get-EloInstalledIndexserverVersion @($eloScratch)) -ceq '25.00.011.000002') 'oversized files are ignored'
    $withVersion=New-EloTechnicalReport -ResourceCollector $resources -OptionsCollector { $null } -EloVersionAdapter { @{Verified=$true;Version='25.00.011.000002'} }
    foreach ($lang in @('en','de')) { Assert ((ConvertTo-EloTechnicalReportHtml $withVersion $lang).Contains('25.00.011.000002')) "ELO version rendered ($lang)" }
} finally {
    $full=[IO.Path]::GetFullPath($eloScratch)
    if ($full.StartsWith([IO.Path]::GetFullPath([IO.Path]::GetTempPath()),[StringComparison]::OrdinalIgnoreCase) -and (Split-Path -Leaf $full) -like 'elo-version-test-*') { Remove-Item -LiteralPath $full -Recurse -Force -ErrorAction SilentlyContinue }
}
# Unknown / unavailable values are never printed: no placeholder text, no empty labels.
$sparse = New-EloTechnicalReport -ResourceCollector { $null } -OptionsCollector { $null } -JvmEvidence @(@{Version='17.0.10';Verified=$true;ExecutionVerified=$true}) -Actions @(@{Kind='Mitigation';Status='Unknown'})
foreach ($lang in @('en','de')) {
    $h = ConvertTo-EloTechnicalReportHtml $sparse $lang
    Assert ($h -notmatch 'Unknown / unavailable|Unbekannt / nicht verfuegbar') "no unknown/unavailable placeholder ($lang)"
    Assert ($h -notmatch 'Vulnerability classification|Verwundbarkeitsklassifizierung|Evidence / method|Nachweis / Methode') "no label without a value ($lang)"
    Assert ($h -notmatch '<dl></dl>|<ul></ul>|JAVA_TOOL_OPTIONS') "no empty sections ($lang)"
    Assert ($h.Contains('17.0.10')) "known facts are still reported ($lang)"
}
# Spanish (castellano) report: translated labels, still no placeholders for unknown values.
$esReport = New-EloTechnicalReport -ResourceCollector { @{ServerName='SRV01';WindowsVersion='10.0';WindowsBuild='20348';TotalRamBytes=17179869184;Disks=@(@{Name='C:';TotalBytes=107374182400;FreeBytes=53687091200})} } -OptionsCollector { @{Machine='-XX:-UseBASE64Intrinsics';User=$null;Process=$null} } -JvmEvidence @(@{Version='17.0.10';Verified=$true;ExecutionVerified=$true;Vendor='Temurin';VendorVerified=$true;Classification='PotentiallyVulnerable';ClassificationVerified=$true;EvidenceCode='AdvisoryRangeMatch'}) -Actions @()
$h = ConvertTo-EloTechnicalReportHtml $esReport es
Assert ($h.Contains('<html lang="es">') -and $h.Contains('Informe técnico') -and $h.Contains('Versiones de JVM detectadas') -and $h.Contains('Potencialmente vulnerable') -and $h.Contains('Siguiente paso recomendado') -and $h.Contains('RAM total')) 'the Spanish report is translated'
Assert ($h -notmatch 'Technical report|Recommended next step|Detected JVM versions|Unknown / unavailable|Unbekannt') 'no English or German leftovers in the Spanish report'
Assert ($h.Contains('Opción presente') -and $h.Contains('Los valores del entorno no prueban')) 'option labels and the environment note are Spanish'

# The report says what the update achieved (and only when proven) and how fragile the mitigation is.
$res2 = { @{ServerName='SRV01';WindowsVersion='10.0';WindowsBuild='20348';TotalRamBytes=17179869184;Disks=@()} }
$oldJvm = @{Version='17.0.2+8';Verified=$true;ExecutionVerified=$true;Vendor='Temurin';VendorVerified=$true;Classification='PotentiallyVulnerable';ClassificationVerified=$true;EvidenceCode='AdvisoryRangeMatch'}
$newFixed = @{Version='17.0.21.1+2';Verified=$true;ExecutionVerified=$true;Vendor='Temurin';VendorVerified=$true;Classification='Fixed';ClassificationVerified=$true;EvidenceCode='AdvisoryFixedVersion'}
$newUnknown = @{Version='21.0.1+12';Verified=$true;ExecutionVerified=$true;Vendor='Azul Zulu';VendorVerified=$true;Classification='Unknown'}
$upd = { param($to) @(@{Kind='Backup';Status='Proven';Verified=$true;BackupVerified=$true;RuntimeIndex=1;EvidenceCode='BackupManifestMatched';EvidenceVerified=$true;FromVersion='17.0.2+8';BackupVersion='17.0.2+8'},@{Kind='Update';Status='Proven';Verified=$true;RuntimeIndex=1;EvidenceCode='InstalledRuntimeValidated';EvidenceVerified=$true;FromVersion='17.0.2+8';ToVersion=$to}) }
$fixedReport = New-EloTechnicalReport -ResourceCollector $res2 -JvmEvidence @($oldJvm,$newFixed) -Actions (& $upd '17.0.21.1+2')
$he = ConvertTo-EloTechnicalReportHtml $fixedReport en
Assert ($he.Contains('<h2>Result</h2>') -and $he.Contains('Java runtime updated and verified: 17.0.2+8 to 17.0.21.1+2') -and $he.Contains('listed as fixed according to the matched advisory') -and $he.Contains('ELO compatibility is not verified')) 'a verified update with a fixed result states that Java was installed and the version is fixed (with its limits)'
Assert ($he.Contains('JVM #2: Verified 17.0.21.1+2') -and $he.Contains('Fixed version according to matched advisory')) 'the new runtime is listed as a JVM with its classification'
$hd = ConvertTo-EloTechnicalReportHtml $fixedReport de; $hs = ConvertTo-EloTechnicalReportHtml $fixedReport es
Assert ($hd.Contains('Java-Runtime aktualisiert und geprueft: 17.0.2+8 auf 17.0.21.1+2') -and $hd.Contains('als korrigiert aufgefuehrt') -and $hs.Contains('Runtime de Java actualizado y verificado: 17.0.2+8 a 17.0.21.1+2') -and $hs.Contains('figura como corregida')) 'the result statement exists in German and Spanish'
$unknownReport = New-EloTechnicalReport -ResourceCollector $res2 -JvmEvidence @($oldJvm,$newUnknown) -Actions (& $upd '21.0.1+12')
$hu = ConvertTo-EloTechnicalReportHtml $unknownReport en
Assert ($hu.Contains('Java runtime updated and verified') -and -not $hu.Contains('listed as fixed') -and $hu -notmatch 'Unknown / unavailable') 'when the fix status is not known the report says only that the update was verified, without a fix claim or placeholder'
$mitReport = New-EloTechnicalReport -ResourceCollector $res2 -OptionsCollector { @{Machine='-XX:-UseBASE64Intrinsics';User=$null;Process=$null} } -JvmEvidence @($oldJvm) -Actions @(@{Kind='Mitigation';Status='Proven';Verified=$true;RuntimeIndex=1;EvidenceCode='MachineOptionSet';EvidenceVerified=$true})
foreach ($pair in @(@('en','Limits of the temporary mitigation','This protection is fragile','removed or overwritten','GetEnvironmentVariable'),@('de','Grenzen der vorlaeufigen Risikominderung','Dieser Schutz ist fragil','entfernt oder ueberschrieben','GetEnvironmentVariable'),@('es','Límites de la mitigación temporal','Esta protección es frágil','se elimina o se sobrescribe','GetEnvironmentVariable'))) {
    $hm = ConvertTo-EloTechnicalReportHtml $mitReport $pair[0]
    Assert ($hm.Contains($pair[1]) -and $hm.Contains($pair[2]) -and $hm.Contains($pair[3]) -and $hm.Contains($pair[4])) "the mitigation report warns that the protection is fragile and shows how to check it ($($pair[0]))"
}
Assert (-not (ConvertTo-EloTechnicalReportHtml $fixedReport en).Contains('This protection is fragile')) 'the fragility note appears only when a mitigation was applied'
Assert (-not (ConvertTo-EloTechnicalReportHtml (New-EloTechnicalReport -ResourceCollector $res2 -JvmEvidence @($oldJvm) -Actions @()) en).Contains('<h2>Result</h2>')) 'no result statement without a verified update'
$ramReport = New-EloTechnicalReport -ResourceCollector { @{ServerName='S';TotalRamBytes=1073741824} } -JvmEvidence @()
Assert ((ConvertTo-EloTechnicalReportHtml $ramReport en) -notmatch 'GiB \(Unknown') 'a known RAM size is not followed by an "unknown" status'
Write-Output 'PASS: deterministic bilingual report tests (synthetic adapters only)'
