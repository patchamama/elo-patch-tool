# PowerShell 5.1, embeddable: dot-sourcing defines functions only; no IO on load.
# API: New-EloTechnicalReport -> sanitized evidence DTO;
# ConvertTo-EloTechnicalReportHtml -Report <DTO> -Language en|de -> HTML string.
# No file writes, network, Java execution, credential inputs, or ELO calls.
# ResourceCollector: trusted scriptblock returning ServerName, WindowsVersion,
# WindowsBuild, TotalRamBytes, Disks[{Name,TotalBytes,FreeBytes}]. Default is
# read-only CIM. Inject in tests; never accept scriptblocks from an HTTP client.
# JvmEvidence: trusted backend observations [{Version,Verified(bool),
# ExecutionVerified(bool)}]. ExecutionVerified requires an observed version probe
# or equivalent runtime evidence; detection alone never proves execution.
# Actions: trusted backend [{Kind: Update|Mitigation|Backup|Restore,
# Status: NotPerformed|Unknown|Failed|Proven, Verified(bool), FromVersion,
# ToVersion, BackupVersion, BackupVerified(bool)}]. Verified means independently
# checked postcondition, NOT user intent or process exit alone. BackupVerified
# requires archive/content validation. Versions describe evidence, not promises.
# JVM Classification: PotentiallyVulnerable|NotAffected|Fixed|Unknown, with
# ClassificationVerified(bool) and EvidenceCode AdvisoryRangeMatch|
# AdvisoryExcludesVersion|AdvisoryFixedVersion. No version ranges are inferred here.
# Actions require RuntimeIndex (1-based position in JvmEvidence), EvidenceVerified
# (bool), and EvidenceCode: EffectiveJvmFlagObserved (effective running JVM flag),
# InstalledRuntimeValidated (installed manifest + version probe),
# BackupManifestMatched (archive compared with original), OriginalRuntimeRestored
# (restored manifest + version probe), or DownloadFailed|ValidationFailed|
# RestoreFailed|OperationCancelled. Free-text explanations are never accepted.
# Proven requires the kind-specific positive code, boolean evidence proof and a
# valid JVM association; legacy success flags alone now downgrade to Unknown.
# Caller must map scanner/update results explicitly; their schemas are not assumed.
# EloVersionAdapter: optional trusted scriptblock -> {Verified(bool),Version}.
# Only use after independently validating an installation-specific official API
# contract. This module supplies NO live adapter and never accepts credentials.
# Only allowlisted fields are retained. Do not pass raw logs, paths, identities,
# URLs or secrets. Identifiers themselves must be safe backend observations.
# HTML renderer re-normalizes its input; raw diagnostics are never serialized.
# S10: JVM Vendor='Temurin' with VendorVerified(bool) enables same-provider
# official download/install guidance. All other/unverified vendors stay Unknown.
# Mitigation EvidenceCode additionally accepts MachineOptionSet (machine option
# read back), NewlyLaunchedJvmFlagVerified (effective flag in a new JVM probe),
# RunningEloJvmFlagVerified (effective flag in the identified current ELO JVM).
# These are independent scopes: no scope implies another. Verified means only
# the named postcondition, never a permanent fix or a runtime installation.
# Legacy EffectiveJvmFlagObserved has unspecified scope, NOT proof about ELO.
# No process IDs, command lines or environment dumps are retained.

function ConvertTo-EloReportEscapedText {
    param([AllowNull()][object]$Value)
    ([string]$Value).Replace('&','&amp;').Replace('<','&lt;').Replace('>','&gt;').Replace('"','&quot;').Replace("'",'&#39;')
}
function Get-EloReportVersion {
    param($Value)
    if ($Value -is [string] -and $Value.Length -le 64 -and $Value -cmatch '^\d{1,8}(?:[._+\-]\d{1,8}){0,7}(?:-ea)?$') { return $Value }
    return $null
}
function Test-EloReportProof {
    param($Value)
    return ($Value -is [bool] -and $Value)
}
function Get-EloReportBytes {
    param($Value)
    # Reject strings, NaN, negative, fractional, and implausibly large values.
    if ($Value -isnot [ValueType]) { return $null }
    try {
        $n = [decimal]$Value
        if ($n -ge 0 -and $n -le 1152921504606846976 -and [decimal]::Truncate($n) -eq $n) { return $n }
    } catch { }
    return $null
}
function Get-EloReportWindowsResources {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $computer = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    $disks = @(Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction Stop | ForEach-Object {
        @{Name=$_.DeviceID;TotalBytes=$_.Size;FreeBytes=$_.FreeSpace}
    })
    @{ServerName=$computer.Name;WindowsVersion=$os.Version;WindowsBuild=$os.BuildNumber;TotalRamBytes=$computer.TotalPhysicalMemory;Disks=$disks}
}
function New-EloTechnicalReport {
    param(
        [scriptblock]$ResourceCollector = { Get-EloReportWindowsResources },
        [object[]]$JvmEvidence = @(),
        [object[]]$Actions = @(),
        [scriptblock]$EloVersionAdapter
    )
    $system = @{Status='Unknown';ServerName=$null;WindowsVersion=$null;WindowsBuild=$null;TotalRamBytes=$null;Disks=@()}
    try {
        $raw = & $ResourceCollector
        if ($null -ne $raw) {
            if ($raw.ServerName -is [string] -and $raw.ServerName -cmatch '^[A-Za-z0-9][A-Za-z0-9.-]{0,62}$') { $system.ServerName=$raw.ServerName }
            $system.WindowsVersion=Get-EloReportVersion $raw.WindowsVersion
            if ([string]$raw.WindowsBuild -cmatch '^\d{1,10}$') { $system.WindowsBuild=[string]$raw.WindowsBuild }
            $system.TotalRamBytes=Get-EloReportBytes $raw.TotalRamBytes
            foreach ($disk in @($raw.Disks)) {
                $total=Get-EloReportBytes $disk.TotalBytes; $free=Get-EloReportBytes $disk.FreeBytes
                if ($disk.Name -cmatch '^[A-Z]:$' -and $null -ne $total -and $null -ne $free -and $free -le $total) {
                    $system.Disks+=@{Name=$disk.Name;TotalBytes=$total;FreeBytes=$free}
                }
            }
            if ($null -ne $system.ServerName -and $null -ne $system.WindowsVersion -and $null -ne $system.WindowsBuild -and $null -ne $system.TotalRamBytes -and $system.Disks.Count -gt 0) { $system.Status='Proven' }
        }
    } catch { $system.Status='Failed' }
    $jvms=@()
    foreach ($jvm in $JvmEvidence) {
        $version=$null
        if (Test-EloReportProof $jvm.Verified) { $version=Get-EloReportVersion $jvm.Version }
        $state='Unknown'; if ($null -ne $version) { $state='Proven' }
        $execution='Unknown'
        if ($state -eq 'Proven' -and (Test-EloReportProof $jvm.ExecutionVerified)) { $execution='Proven' }
        $classification='Unknown'; $evidence='Unknown'
        $classCodes=@{PotentiallyVulnerable='AdvisoryRangeMatch';NotAffected='AdvisoryExcludesVersion';Fixed='AdvisoryFixedVersion'}
        if ($state -eq 'Proven' -and (Test-EloReportProof $jvm.ClassificationVerified) -and $jvm.Classification -is [string] -and $classCodes.ContainsKey($jvm.Classification) -and $jvm.EvidenceCode -ceq $classCodes[$jvm.Classification]) {
            $classification=$jvm.Classification; $evidence=$jvm.EvidenceCode
        }
        $vendor='Unknown'
        if ($jvm.Vendor -ceq 'Temurin' -and (Test-EloReportProof $jvm.VendorVerified)) { $vendor='Temurin' }
        $jvms+=@{RuntimeIndex=($jvms.Count+1);Status=$state;Version=$version;ExecutionStatus=$execution;Classification=$classification;ClassificationVerified=($classification -ne 'Unknown');EvidenceCode=$evidence;Vendor=$vendor;VendorVerified=($vendor -eq 'Temurin')}
    }
    $normalized=@()
    foreach ($kind in @('Update','Mitigation','Backup','Restore')) {
        $entries=@($Actions | Where-Object { $_.Kind -ceq $kind })
        if ($entries.Count -eq 0) { $entries=@(@{Status='NotPerformed'}) }
        foreach ($entry in $entries) {
            $state='Unknown'
            if (@('NotPerformed','Unknown','Failed','Proven') -ccontains $entry.Status) { $state=$entry.Status }
            if ($state -eq 'Proven' -and -not (Test-EloReportProof $entry.Verified)) { $state='Unknown' }
            if ($state -eq 'Proven' -and $kind -eq 'Backup' -and -not (Test-EloReportProof $entry.BackupVerified)) { $state='Unknown' }
            $index=$null
            if (($entry.RuntimeIndex -is [int] -or $entry.RuntimeIndex -is [long]) -and $entry.RuntimeIndex -ge 1 -and $entry.RuntimeIndex -le $jvms.Count) { $index=[int]$entry.RuntimeIndex }
            $proofCodes=@{Mitigation='EffectiveJvmFlagObserved';Update='InstalledRuntimeValidated';Backup='BackupManifestMatched';Restore='OriginalRuntimeRestored'}
            $evidence='Unknown'
            $mitigationCodes=@('EffectiveJvmFlagObserved','MachineOptionSet','NewlyLaunchedJvmFlagVerified','RunningEloJvmFlagVerified')
            $codes=@('InstalledRuntimeValidated','BackupManifestMatched','OriginalRuntimeRestored','DownloadFailed','ValidationFailed','RestoreFailed','OperationCancelled') + $mitigationCodes
            if ((Test-EloReportProof $entry.EvidenceVerified) -and $codes -ccontains $entry.EvidenceCode) { $evidence=$entry.EvidenceCode }
            $matchingProof=($evidence -ceq $proofCodes[$kind])
            if ($kind -eq 'Mitigation') { $matchingProof=($mitigationCodes -ccontains $evidence) }
            if ($state -eq 'Proven' -and ($null -eq $index -or -not $matchingProof)) { $state='Unknown' }
            # Never attach positive postcondition evidence to a non-proven outcome.
            if ($state -ne 'Proven' -and ($proofCodes.Values -ccontains $evidence -or $mitigationCodes -ccontains $evidence)) { $evidence='Unknown' }
            $action=@{RuntimeIndex=$index;Kind=$kind;Status=$state;Verified=($state -eq 'Proven');EvidenceCode=$evidence;EvidenceVerified=($evidence -ne 'Unknown');BackupVerified=($state -eq 'Proven' -and $kind -eq 'Backup');FromVersion=$null;ToVersion=$null;BackupVersion=$null}
            if ($state -eq 'Proven') {
                $action.FromVersion=Get-EloReportVersion $entry.FromVersion
                if ($kind -eq 'Update' -or $kind -eq 'Restore') { $action.ToVersion=Get-EloReportVersion $entry.ToVersion }
                if ($kind -eq 'Backup') { $action.BackupVersion=Get-EloReportVersion $entry.BackupVersion }
            }
            $normalized+=$action
        }
    }
    $elo=@{Status='Unknown';Version=$null;MissingContract='Official installation-specific endpoint, authentication method, version operation and response schema are not verified. Java Client IXConnectionIF getVersion/getImplVersion does not establish a universal REST contract.'}
    if ($null -ne $EloVersionAdapter) {
        try {
            $value=& $EloVersionAdapter
            if (Test-EloReportProof $value.Verified) {
                $elo.Version=Get-EloReportVersion $value.Version
                if ($null -ne $elo.Version) { $elo.Status='Proven';$elo.MissingContract=$null }
            }
        } catch { $elo.Status='Failed' }
    }
    @{System=$system;Jvms=$jvms;Actions=$normalized;Elo=$elo}
}
function ConvertTo-EloTechnicalReportHtml {
    param([Parameter(Mandatory=$true)]$Report, [ValidateSet('en','de')][string]$Language='en')
    # Normalize again: renderer never reflects arbitrary DTO fields or messages.
    $r=New-EloTechnicalReport -ResourceCollector { $Report.System }.GetNewClosure() -JvmEvidence @($Report.Jvms | ForEach-Object { @{Version=$_.Version;Verified=($_.Status -ceq 'Proven');ExecutionVerified=($_.ExecutionStatus -ceq 'Proven');Classification=$_.Classification;ClassificationVerified=$_.ClassificationVerified;EvidenceCode=$_.EvidenceCode;Vendor=$_.Vendor;VendorVerified=$_.VendorVerified} }) -Actions $Report.Actions -EloVersionAdapter { @{Version=$Report.Elo.Version;Verified=($Report.Elo.Status -ceq 'Proven')} }.GetNewClosure()
    if ($Report.System.Status -ceq 'Failed') { $r.System.Status='Failed' }
    if ($Report.Elo.Status -ceq 'Failed') { $r.Elo.Status='Failed' }
    $t=@{Title='Technical report';Server='Server';Windows='Windows version / build';Ram='Total RAM';Disk='Disk: total / free';Jvm='Detected JVM versions';Execution='Execution evidence';Elo='ELO version';Unknown='Unknown / unavailable';Failed='Failed';NotPerformed='Not performed';Proven='Verified';Update='Runtime update';Mitigation='Temporary mitigation';Backup='Backup';Restore='Restore';From='Previous version';To='Verified resulting version';BackupVersion='Verified backup JVM version';Sources='Official information sources';Notice='States reflect supplied verified evidence only. Compatibility, vulnerability and successful remediation are not inferred. No credentials or raw diagnostics are included.';Missing='Missing official installation-specific endpoint, authentication method, version operation and response schema. Java Client IXConnectionIF getVersion/getImplVersion is not a universal REST API contract.'}
    if ($Language -eq 'de') {
        $t=@{Title='Technischer Bericht';Server='Server';Windows='Windows-Version / Build';Ram='Gesamter RAM';Disk='Datentraeger: gesamt / frei';Jvm='Erkannte JVM-Versionen';Execution='Ausfuehrungsnachweis';Elo='ELO-Version';Unknown='Unbekannt / nicht verfuegbar';Failed='Fehlgeschlagen';NotPerformed='Nicht ausgefuehrt';Proven='Nachgewiesen';Update='Runtime-Aktualisierung';Mitigation='Vorlaeufige Risikominderung';Backup='Sicherung';Restore='Wiederherstellung';From='Vorherige Version';To='Nachgewiesene Ergebnisversion';BackupVersion='Nachgewiesene JVM-Version der Sicherung';Sources='Offizielle Informationsquellen';Notice='Statusangaben beruhen nur auf uebergebenen Nachweisen. Kompatibilitaet, Verwundbarkeit und erfolgreiche Behebung werden nicht abgeleitet. Keine Zugangsdaten oder Rohdiagnosen enthalten.';Missing='Offizieller installationsspezifischer Endpunkt, Authentifizierungsmethode, Versionsoperation und Antwortschema fehlen. Java Client IXConnectionIF getVersion/getImplVersion ist kein universeller REST-API-Vertrag.'}
    }
    $facts=@{Classification='Vulnerability classification';Evidence='Evidence / method';Association='Runtime association';PotentiallyVulnerable='Potentially vulnerable';NotAffected='Not affected by the matched advisory';Fixed='Fixed version according to matched advisory';AdvisoryRangeMatch='Matched advisory affected-version range';AdvisoryExcludesVersion='Advisory excludes observed version';AdvisoryFixedVersion='Observed version matches advisory fixed release';EffectiveJvmFlagObserved='Effective JVM flag verified';InstalledRuntimeValidated='Installed runtime manifest and version probe verified';BackupManifestMatched='Backup contents matched original manifest';OriginalRuntimeRestored='Original runtime restored and verified';DownloadFailed='Download failed';ValidationFailed='Postcondition validation failed';RestoreFailed='Restoration failed; manual recovery required';OperationCancelled='Operation cancelled';Checked='Source verification date';Fetched='Fetched by parent';Supplied='User-supplied text; site access returned HTTP 403; not independently fetched';Changes='Advisories may change. Source access does not prove applicability or successful remediation.'}
    if ($Language -eq 'de') {
        $facts=@{Classification='Verwundbarkeitsklassifizierung';Evidence='Nachweis / Methode';Association='Runtime-Zuordnung';PotentiallyVulnerable='Potenziell verwundbar';NotAffected='Laut zugeordnetem Hinweis nicht betroffen';Fixed='Korrigierte Version laut zugeordnetem Hinweis';AdvisoryRangeMatch='Betroffene Versionsspanne des Hinweises stimmt ueberein';AdvisoryExcludesVersion='Hinweis schliesst erkannte Version aus';AdvisoryFixedVersion='Erkannte Version entspricht korrigierter Ausgabe laut Hinweis';EffectiveJvmFlagObserved='Wirksames JVM-Flag nachgewiesen';InstalledRuntimeValidated='Installiertes Runtime-Manifest und Versionsprobe nachgewiesen';BackupManifestMatched='Sicherungsinhalt stimmt mit urspruenglichem Manifest ueberein';OriginalRuntimeRestored='Urspruengliche Runtime wiederhergestellt und geprueft';DownloadFailed='Download fehlgeschlagen';ValidationFailed='Pruefung der Nachbedingung fehlgeschlagen';RestoreFailed='Wiederherstellung fehlgeschlagen; manuelle Wiederherstellung erforderlich';OperationCancelled='Vorgang abgebrochen';Checked='Pruefdatum der Quellen';Fetched='Vom uebergeordneten Agenten abgerufen';Supplied='Vom Benutzer bereitgestellter Text; Seitenzugriff HTTP 403; nicht unabhaengig abgerufen';Changes='Hinweise koennen sich aendern. Quellenzugriff beweist weder Anwendbarkeit noch erfolgreiche Behebung.'}
    }
    foreach ($key in $facts.Keys) { $t[$key]=$facts[$key] }
    $guidance=@{Vendor='Verified JVM vendor';Recommendation='Recommended next step';Temporary='Flag-only temporary mitigation; does not install a Java runtime and is not a permanent fix. A machine option does not prove that a newly launched JVM or the current ELO process uses the flag.';Upgrade='Prefer installing a newer vendor-fixed Java release after ELO compatibility confirmation. No particular fixed version or successful installation is inferred.';VendorUnknown='JVM vendor unknown; consult your JVM vendor and ELO for the appropriate fixed release and official download/install instructions. Temurin is not assumed to be a same-provider replacement.';Download='Official Temurin downloads';Install='Official Temurin installation instructions';MachineOptionSet='Machine option set';NewlyLaunchedJvmFlagVerified='Newly launched JVM flag';RunningEloJvmFlagVerified='Current running ELO process flag';EffectiveJvmFlagObserved='JVM flag observed; scope unspecified, current ELO process not verified'}
    if ($Language -eq 'de') {
        $guidance=@{Vendor='Nachgewiesener JVM-Anbieter';Recommendation='Empfohlener naechster Schritt';Temporary='Nur vorlaeufige Flag-Risikominderung; installiert keine Java-Runtime und ist keine dauerhafte Behebung. Eine Maschinenoption beweist nicht, dass eine neu gestartete JVM oder der aktuelle ELO-Prozess das Flag verwendet.';Upgrade='Vorzugsweise eine neuere, vom Anbieter korrigierte Java-Version nach ELO-Kompatibilitaetsbestaetigung installieren. Keine bestimmte korrigierte Version oder erfolgreiche Installation wird abgeleitet.';VendorUnknown='JVM-Anbieter unbekannt; JVM-Anbieter und ELO konsultieren, um die passende korrigierte Version und offizielle Download-/Installationsanleitungen zu erhalten. Temurin wird nicht als Ersatz desselben Anbieters angenommen.';Download='Offizielle Temurin-Downloads';Install='Offizielle Temurin-Installationsanleitung';MachineOptionSet='Maschinenoption gesetzt';NewlyLaunchedJvmFlagVerified='Flag einer neu gestarteten JVM';RunningEloJvmFlagVerified='Flag des aktuell laufenden ELO-Prozesses';EffectiveJvmFlagObserved='JVM-Flag beobachtet; Umfang unbekannt, aktueller ELO-Prozess nicht nachgewiesen'}
    }
    foreach ($key in $guidance.Keys) { $t[$key]=$guidance[$key] }
    $lines=New-Object 'System.Collections.Generic.List[string]'
    $lines.Add('<!doctype html><html lang="'+$Language+'"><head><meta charset="utf-8"><title>'+$t.Title+'</title></head><body><h1>'+$t.Title+'</h1>')
    $lines.Add('<p>'+$t.Notice+'</p><dl>')
    $rows=@(@($t.Server,$r.System.ServerName),@($t.Windows,($r.System.WindowsVersion+' / '+$r.System.WindowsBuild)))
    foreach ($row in $rows) {
        $v=$row[1]; if ([string]::IsNullOrWhiteSpace(($v -replace '[ /]',''))) { $v=$t.Unknown }
        $lines.Add('<dt>'+$row[0]+'</dt><dd>'+(ConvertTo-EloReportEscapedText $v)+'</dd>')
    }
    $ram=$t.Unknown
    if ($null -ne $r.System.TotalRamBytes) { $ram=([double]$r.System.TotalRamBytes / 1GB).ToString('F2',[Globalization.CultureInfo]::InvariantCulture)+' GiB' }
    $lines.Add('<dt>'+$t.Ram+'</dt><dd>'+$ram+' ('+$t[$r.System.Status]+')</dd>')
    if ($r.System.Disks.Count -eq 0) { $lines.Add('<dt>'+$t.Disk+'</dt><dd>'+$t.Unknown+'</dd>') }
    foreach ($d in $r.System.Disks) {
        $space=([double]$d.TotalBytes/1GB).ToString('F2',[Globalization.CultureInfo]::InvariantCulture)+' GiB / '+([double]$d.FreeBytes/1GB).ToString('F2',[Globalization.CultureInfo]::InvariantCulture)+' GiB'
        $lines.Add('<dt>'+$t.Disk+'</dt><dd>'+(ConvertTo-EloReportEscapedText $d.Name)+' '+$space+'</dd>')
    }
    $lines.Add('<dt>'+$t.Elo+'</dt><dd>'+$t[$r.Elo.Status]+' '+(ConvertTo-EloReportEscapedText $r.Elo.Version)+'</dd>')
    $lines.Add('</dl>')
    if ($r.Elo.Status -ne 'Proven') { $lines.Add('<p>'+$t.Missing+'</p>') }
    $lines.Add('<h2>'+$t.Jvm+'</h2><ul>')
    if ($r.Jvms.Count -eq 0) { $lines.Add('<li>'+$t.Unknown+'</li>') }
    foreach ($j in $r.Jvms) { $lines.Add('<li>JVM #'+$j.RuntimeIndex+': '+$t[$j.Status]+' '+(ConvertTo-EloReportEscapedText $j.Version)+'; '+$t.Execution+': '+$t[$j.ExecutionStatus]+'; '+$t.Classification+': '+(ConvertTo-EloReportEscapedText $t[$j.Classification])+'; '+$t.Evidence+': '+(ConvertTo-EloReportEscapedText $t[$j.EvidenceCode])+'</li>') }
    $lines.Add('</ul><h2>'+$t.Recommendation+'</h2><p>'+$t.Temporary+'</p><p>'+$t.Upgrade+'</p><ul>')
    if ($r.Jvms.Count -eq 0) { $lines.Add('<li>'+$t.VendorUnknown+'</li>') }
    foreach ($j in $r.Jvms) {
        $advice=$t.VendorUnknown
        if ($j.Vendor -eq 'Temurin') {
            $advice=$t.Vendor+': Temurin; <a href="https://adoptium.net/temurin/releases">'+$t.Download+'</a>; <a href="https://adoptium.net/installation/">'+$t.Install+'</a>'
        }
        $lines.Add('<li>JVM #'+$j.RuntimeIndex+': '+$advice+'</li>')
    }
    $lines.Add('</ul><h2>'+$t.Update+' / '+$t.Mitigation+' / '+$t.Backup+' / '+$t.Restore+'</h2><ul>')
    foreach ($a in $r.Actions) {
        $association=$t.Unknown
        if ($null -ne $a.RuntimeIndex) { $association='JVM #'+$a.RuntimeIndex }
        $detail='; '+$t.Association+': '+$association+'; '+$t.Evidence+': '+(ConvertTo-EloReportEscapedText $t[$a.EvidenceCode])
        foreach ($key in @('FromVersion','ToVersion','BackupVersion')) {
            if ($a[$key]) {
                $label=$t.BackupVersion; if ($key -eq 'FromVersion') { $label=$t.From }; if ($key -eq 'ToVersion') { $label=$t.To }
                $detail+='; '+$label+': '+(ConvertTo-EloReportEscapedText $a[$key])
            }
        }
        if ($a.Kind -eq 'Mitigation') {
            foreach ($scope in @('MachineOptionSet','NewlyLaunchedJvmFlagVerified','RunningEloJvmFlagVerified')) {
                $scopeState='Unknown'
                if ($a.Status -eq 'Proven' -and $a.EvidenceCode -ceq $scope) { $scopeState='Proven' }
                $detail+='; '+$t[$scope]+': '+$t[$scopeState]
            }
            if ($a.Status -eq 'Proven') { $detail+='; -XX:-UseBASE64Intrinsics' }
        }
        $lines.Add('<li>'+$t[$a.Kind]+': '+$t[$a.Status]+$detail+'</li>')
    }
    $lines.Add('</ul><h2>'+$t.Sources+'</h2><ul>')
    $lines.Add('<li>'+$t.Checked+': 2026-11-23. '+$t.Changes+'</li>')
    foreach ($source in @(@('OpenJDK 2026-11-17','https://openjdk.org/groups/vulnerability/advisories/2026-11-17','Supplied'),@('Oracle CVE-2026-114938','https://linux.oracle.com/cve/CVE-2026-114938.html','Fetched'),@('Adoptium Temurin November 2026 CSPU','https://adoptium.net/news/2026/11/temurin-november-2026-cspu-java4shell/','Fetched'))) {
        $lines.Add('<li><a href="'+$source[1]+'">'+$source[0]+'</a> - '+$t[$source[2]]+'</li>')
    }
    $lines.Add('</ul></body></html>')
    return ($lines -join "`r`n")
}
