# Vulnerability catalog engine (Windows PowerShell 5.1). Dot-source to load; no startup work.
# The catalog (vulndb.json) holds everything about a vulnerability: detection probes (java.exe argument
# lists, never a shell), expect patterns, problem/solution messages, fix actions and report text.
# A catalog entry can only reference a fixed set of action TYPES and a fixed set of argument shapes, so a
# new or AI-drafted entry can never run an arbitrary command. Drafts (status "draft") are validated but
# never used by the scan. Passwords and API keys never belong in the catalog.

$script:EloVulnPlaceholders = @('vendor','version','id','alias','option','runtime','count','vulnerable','n','list','variable','old','new','kind')
$script:EloVulnSeverities = @('high','medium','low')
$script:EloVulnStatuses = @('active','draft','retired')
$script:EloActionTypes = @('runtime-update','jvm-option','restore-backup')
$script:EloVulnCache = $null

function Get-EloVulnDbPath {
    # Reviewed catalog installed by the tool (see Install-EloVulnDb) wins over the packaged one.
    param([string]$ProgramDataRoot = $env:ProgramData)
    if ($ProgramDataRoot) {
        $installed = Join-Path (Join-Path $ProgramDataRoot 'ELO-Patch-Tools') 'vulndb.json'
        if (Test-Path -LiteralPath $installed -PathType Leaf) { return $installed }
    }
    return (Join-Path $PSScriptRoot 'vulndb.json')
}
function Test-EloVulnProbeArgs {
    param($Args_)
    $list = @($Args_)
    if ($list.Count -lt 1 -or $list.Count -gt 6) { return $false }
    foreach ($a in $list) { if ($a -isnot [string] -or $a -cnotmatch '^-[A-Za-z0-9:+=_.\-]{1,64}$') { return $false } }
    return $true
}
function Test-EloRegex {
    param([string]$Pattern)
    if ([string]::IsNullOrEmpty($Pattern) -or $Pattern.Length -gt 512) { return $false }
    try { $null = New-Object Text.RegularExpressions.Regex($Pattern, [Text.RegularExpressions.RegexOptions]::None, [TimeSpan]::FromSeconds(2)); return $true } catch { return $false }
}
function Test-EloBilingualText {
    param($Value, [int]$Max = 4096)
    if ($null -eq $Value) { return $false }
    # English and German are required; Spanish (es) is optional but validated like the others when present.
    $langs=@('en','de'); if ($null -ne $Value.es) { $langs+='es' }
    foreach ($lang in $langs) {
        $t = $Value.$lang
        if ($t -isnot [string] -or $t.Trim().Length -lt 1 -or $t.Length -gt $Max -or $t -match '[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]') { return $false }
        foreach ($m in [regex]::Matches($t, '\{([A-Za-z]+)\}')) { if ($script:EloVulnPlaceholders -cnotcontains $m.Groups[1].Value) { return $false } }
    }
    return $true
}
function Test-EloVulnDb {
    # Returns the list of problems (empty = valid). Pure validation: reads nothing, runs nothing.
    param($Db)
    $errors = New-Object 'System.Collections.Generic.List[string]'
    if ($null -eq $Db -or $Db.schemaVersion -ne 1) { $errors.Add('schemaVersion must be 1'); return $errors.ToArray() }
    foreach ($s in @($Db.sources)) {
        if ($s.url -isnot [string] -or $s.url -cnotmatch '^https://[A-Za-z0-9.\-]+(:[0-9]+)?/[^\s"<>]{0,512}$') { $errors.Add("source '$($s.id)': url must be https") }
        if ($s.PSObject.Properties.Name -contains 'password' -or $s.PSObject.Properties.Name -contains 'apiKey') { $errors.Add("source '$($s.id)': credentials are not allowed in the catalog") }
    }
    $seen = @{}
    $vulns = @($Db.vulnerabilities)
    if ($vulns.Count -gt 200) { $errors.Add('too many vulnerabilities') }
    foreach ($v in $vulns) {
        $id = [string]$v.id
        $where = "vulnerability '$id'"
        if ($id -cnotmatch '^[A-Za-z0-9._\-]{3,64}$') { $errors.Add("${where}: invalid id"); continue }
        if ($seen.ContainsKey($id)) { $errors.Add("${where}: duplicate id") }
        $seen[$id] = $true
        if ($script:EloVulnSeverities -cnotcontains [string]$v.severity) { $errors.Add("${where}: severity must be high, medium or low") }
        if ($script:EloVulnStatuses -cnotcontains [string]$v.status) { $errors.Add("${where}: status must be active, draft or retired") }
        foreach ($field in @('title','problem','solution')) { if (-not (Test-EloBilingualText $v.$field 2048)) { $errors.Add("${where}: $field needs English and German text") } }
        foreach ($adv in @($v.advisories)) {
            if ($adv.url -isnot [string] -or $adv.url -cnotmatch '^https://[A-Za-z0-9.\-]+/[^\s"<>]{0,512}$') { $errors.Add("${where}: advisory '$($adv.id)' url must be https") }
            if (-not (Test-EloBilingualText $adv.title 512)) { $errors.Add("${where}: advisory '$($adv.id)' title needs English and German text") }
        }
        $det = $v.detection
        if ($null -eq $det -or @('version-table','probe-expect') -cnotcontains [string]$det.method) { $errors.Add("${where}: detection.method must be version-table or probe-expect") }
        else {
            $probes = @($det.probes)
            if ($probes.Count -lt 1 -or $probes.Count -gt 4) { $errors.Add("${where}: 1 to 4 probes are required") }
            $probeIds = @{}
            foreach ($p in $probes) {
                if ([string]$p.id -cnotmatch '^[a-z0-9\-]{1,32}$' -or $probeIds.ContainsKey([string]$p.id)) { $errors.Add("${where}: probe id invalid or duplicated") }
                $probeIds[[string]$p.id] = $true
                if (-not (Test-EloVulnProbeArgs $p.args)) { $errors.Add("${where}: probe '$($p.id)' args must be java.exe options such as -version (no shell, no paths)") }
                if ($null -ne $p.timeoutSec -and ([int]$p.timeoutSec -lt 1 -or [int]$p.timeoutSec -gt 60)) { $errors.Add("${where}: probe '$($p.id)' timeoutSec must be 1..60") }
                foreach ($e in @($p.expect)) { if (-not (Test-EloRegex ([string]$e.pattern))) { $errors.Add("${where}: probe '$($p.id)' expect '$($e.id)' is not a valid pattern") } }
            }
            if ([string]$det.method -ceq 'version-table') {
                $vendors = $det.vendors
                if ($null -eq $vendors -or @($vendors.PSObject.Properties).Count -lt 1) { $errors.Add("${where}: version-table needs vendors") }
                else {
                    foreach ($prop in $vendors.PSObject.Properties) {
                        if ($prop.Name -cnotmatch '^[A-Za-z0-9 ]{1,32}$') { $errors.Add("${where}: vendor name invalid"); continue }
                        if (@('temurin-build','zulu-release') -cnotcontains [string]$prop.Value.parser) { $errors.Add("${where}: vendor '$($prop.Name)' parser is not supported") }
                        if ($null -ne $prop.Value.affectedFrom -and [string]$prop.Value.affectedFrom -cnotmatch '^[0-9]{1,3}(\.[0-9]{1,9}){0,3}\+[0-9]{1,9}$') { $errors.Add("${where}: vendor '$($prop.Name)' affectedFrom is not a Java build") }
                        $fixed = @($prop.Value.fixed)
                        if ($fixed.Count -lt 1 -or $fixed.Count -gt 64) { $errors.Add("${where}: vendor '$($prop.Name)' needs 1 to 64 fixed builds") }
                        foreach ($f in $fixed) { if ([string]$f -cnotmatch '^[0-9]{1,3}(\.[0-9]{1,9}){0,3}\+[0-9]{1,9}$') { $errors.Add("${where}: fixed build '$f' is not a Java build such as 17.0.21.1+2") } }
                        if ([string]$prop.Value.fixedSource -cnotmatch '^https://[A-Za-z0-9.\-]+/[^\s"<>]{0,512}$') { $errors.Add("${where}: vendor '$($prop.Name)' fixedSource must be https") }
                    }
                }
            } else {
                $rule = $det.rule
                if ($null -eq $rule -or -not (Test-EloRegex ([string]$rule.vulnerablePattern)) -or ($rule.safePattern -and -not (Test-EloRegex ([string]$rule.safePattern))) -or [string]$rule.probe -cnotmatch '^[a-z0-9\-]{1,32}$' -or -not $probeIds.ContainsKey([string]$rule.probe)) { $errors.Add("${where}: probe-expect needs rule.probe and rule.vulnerablePattern") }
            }
        }
        $actionIds = @{}
        foreach ($a in @($v.actions)) {
            $aid = [string]$a.id
            if ($aid -cnotmatch '^[a-z0-9\-]{1,32}$' -or $actionIds.ContainsKey($aid)) { $errors.Add("${where}: action id invalid or duplicated"); continue }
            $actionIds[$aid] = $true
            if ($script:EloActionTypes -cnotcontains [string]$a.type) { $errors.Add("${where}: action '$aid' type must be one of $($script:EloActionTypes -join ', ')"); continue }
            if (-not (Test-EloBilingualText $a.label 128)) { $errors.Add("${where}: action '$aid' label needs English and German text") }
            if ([string]$a.type -ceq 'jvm-option') {
                if ([string]$a.variable -cne 'JAVA_TOOL_OPTIONS') { $errors.Add("${where}: action '$aid' variable must be JAVA_TOOL_OPTIONS") }
                if ([string]$a.option -cnotmatch '^-XX:[+-][A-Za-z0-9_]{1,64}$') { $errors.Add("${where}: action '$aid' option must be one -XX:+/-Flag") }
                if ([string]$a.conflictPattern -cnotmatch '^[A-Za-z0-9_]{1,64}$') { $errors.Add("${where}: action '$aid' conflictPattern invalid") }
                if (-not (Test-EloBilingualText $a.summary 4096)) { $errors.Add("${where}: action '$aid' summary needs English and German text") }
                if ($null -ne $a.verify) {
                    if (-not (Test-EloVulnProbeArgs $a.verify.args) -or -not (Test-EloRegex ([string]$a.verify.expect)) -or @('true','false') -cnotcontains [string]$a.verify.mustBe) { $errors.Add("${where}: action '$aid' verify is invalid") }
                }
            }
        }
        $actives = @($v.actions | Where-Object { $_.type -ceq 'jvm-option' })
        if ($actives.Count -gt 1) { $errors.Add("${where}: at most one jvm-option action") }
        foreach ($name in @('restoreVulnerable','restoreFixed','restoreUnknown')) { if ($null -ne $v.messages -and $null -ne $v.messages.$name -and -not (Test-EloBilingualText $v.messages.$name 2048)) { $errors.Add("${where}: messages.$name needs English and German text") } }
        if ($null -ne $v.report -and $null -ne $v.report.headline -and -not (Test-EloBilingualText $v.report.headline 512)) { $errors.Add("${where}: report.headline needs English and German text") }
        $sim = $v.simulation
        if ($null -ne $sim) {
            foreach ($prop in @($sim.probes.PSObject.Properties)) { if ($prop.Value -isnot [string] -or $prop.Value.Length -gt 8192) { $errors.Add("${where}: simulation probe '$($prop.Name)' must be text up to 8 KiB") } }
        }
    }
    return $errors.ToArray()
}
function Read-EloVulnDbFile {
    param([Parameter(Mandatory=$true)][string]$Path)
    $info = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($info.PSIsContainer -or ($info.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'vulndb_not_a_file' }
    if ($info.Length -gt 1MB) { throw 'vulndb_too_large' }
    $text = [IO.File]::ReadAllText($info.FullName, (New-Object Text.UTF8Encoding($false,$true)))
    try { $db = $text | ConvertFrom-Json } catch { throw 'vulndb_invalid_json' }
    $problems = @(Test-EloVulnDb $db)
    if ($problems.Count -gt 0) { throw ('vulndb_invalid: ' + (($problems | Select-Object -First 5) -join '; ')) }
    return $db
}
function Get-EloVulnDb {
    param([string]$Path, [switch]$Refresh)
    if (-not $Path -and $script:EloVulnCache -and -not $Refresh) { return $script:EloVulnCache }
    $explicit = [bool]$Path
    if (-not $Path) { $Path = Get-EloVulnDbPath }
    try { $db = Read-EloVulnDbFile $Path }
    catch {
        # A broken installed catalog never disables detection: fall back to the packaged one.
        $packaged = Join-Path $PSScriptRoot 'vulndb.json'
        if ($explicit -or $Path -ceq $packaged) { throw }
        $db = Read-EloVulnDbFile $packaged
    }
    if (-not $explicit) { $script:EloVulnCache = $db }
    return $db
}
function Get-EloActiveVulnerabilities {
    param($Db = (Get-EloVulnDb))
    return @($Db.vulnerabilities | Where-Object { $_.status -ceq 'active' })
}
function Format-EloVulnText {
    # Replaces {name} placeholders from a fixed allowlist; unknown names are left untouched. Never evaluates anything.
    param([AllowNull()][string]$Template, [hashtable]$Values = @{})
    if ($null -eq $Template) { return '' }
    return [regex]::Replace($Template, '\{([A-Za-z]+)\}', {
        param($m)
        $key = $m.Groups[1].Value
        if ($script:EloVulnPlaceholders -ccontains $key -and $Values.ContainsKey($key)) { return [string]$Values[$key] }
        return $m.Value
    })
}
function Get-EloVulnText {
    param($Bilingual, [ValidateSet('en','de','es')][string]$Language = 'en', [hashtable]$Values = @{})
    $text=[string]$Bilingual.$Language; if (-not $text) { $text=[string]$Bilingual.en }
    return (Format-EloVulnText $text $Values)
}
function Get-EloVulnAction {
    param($Vulnerability, [string]$Type)
    return @($Vulnerability.actions | Where-Object { $_.type -ceq $Type }) | Select-Object -First 1
}
function Get-EloScanRules {
    # What the scanner needs per active vulnerability: version-table rules (fixed builds per vendor) and
    # probe-expect rules (a java probe plus the patterns that mean vulnerable / safe).
    param($Db = (Get-EloVulnDb))
    $rules = New-Object 'System.Collections.Generic.List[object]'
    foreach ($v in (Get-EloActiveVulnerabilities $Db)) {
        if ([string]$v.detection.method -ceq 'version-table') {
            foreach ($prop in $v.detection.vendors.PSObject.Properties) {
                $rules.Add(@{ Id = [string]$v.id; Severity = [string]$v.severity; Method = 'version-table'; Vendor = [string]$prop.Name; Parser = [string]$prop.Value.parser
                    Fixed = @($prop.Value.fixed | ForEach-Object { [string]$_ }); AffectedFrom = [string]$prop.Value.affectedFrom; Source = [string]$prop.Value.fixedSource })
            }
        } elseif ([string]$v.detection.method -ceq 'probe-expect') {
            $probe = @($v.detection.probes | Where-Object { $_.id -ceq [string]$v.detection.rule.probe })[0]
            $timeout = 15; if ($probe.timeoutSec) { $timeout = [int]$probe.timeoutSec }
            $source = ''; if (@($v.advisories).Count -gt 0) { $source = [string]@($v.advisories)[0].url }
            $rules.Add(@{ Id = [string]$v.id; Severity = [string]$v.severity; Method = 'probe-expect'; ProbeArgs = @($probe.args | ForEach-Object { [string]$_ }); TimeoutSec = $timeout
                VulnerablePattern = [string]$v.detection.rule.vulnerablePattern; SafePattern = [string]$v.detection.rule.safePattern; Source = $source })
        }
    }
    return $rules.ToArray()
}function Get-EloPrimaryVulnerability {
    param($Db = (Get-EloVulnDb))
    return (Get-EloActiveVulnerabilities $Db | Select-Object -First 1)
}
function Test-EloExpect {
    # Evaluates every expect pattern of a probe against its output: {id -> matched}.
    param($Probe, [AllowEmptyString()][string]$Output)
    $result = [ordered]@{}
    foreach ($e in @($Probe.expect)) {
        $re = New-Object Text.RegularExpressions.Regex([string]$e.pattern, [Text.RegularExpressions.RegexOptions]::None, [TimeSpan]::FromSeconds(2))
        try { $result[[string]$e.id] = $re.IsMatch($Output) } catch { $result[[string]$e.id] = $false }
    }
    return $result
}
function Invoke-EloVulnProbe {
    # Runs one catalog probe through $Runner (real: java.exe with the argument list; simulated: canned text).
    param($Probe, [Parameter(Mandatory=$true)][scriptblock]$Runner)
    if (-not (Test-EloVulnProbeArgs $Probe.args)) { throw 'probe_args_rejected' }
    $output = [string](& $Runner @($Probe.args))
    return @{ Id = [string]$Probe.id; Output = $output; Expect = (Test-EloExpect $Probe $output) }
}
function Invoke-EloVulnSimulation {
    # Replays the entry's simulation probes through the real detection (scan.ps1 must be loaded) and compares the
    # outcome with simulation.expected. This is how a new catalog entry (also a draft) is tested without a vulnerable
    # Java: the entry is evaluated as if it were active, on canned probe output, never on the machine.
    param($Vulnerability, $Db = $null)
    $sim = $Vulnerability.simulation
    if ($null -eq $sim -or $null -eq $sim.expected) { return @{ Passed = $false; Reason = 'no_simulation' } }
    $copy = $Vulnerability | ConvertTo-Json -Depth 20 | ConvertFrom-Json
    $copy.status = 'active'
    $rules = @(Get-EloScanRules ([pscustomobject]@{ vulnerabilities = @($copy) }))
    if ($rules.Count -eq 0) { return @{ Passed = $false; Reason = 'no_rule' } }
    if ([string]$copy.detection.method -ceq 'probe-expect') {
        $rule = $rules[0]
        $prop = $sim.probes.PSObject.Properties[[string]$copy.detection.rule.probe]
        if ($null -eq $prop) { return @{ Passed = $false; Reason = 'no_probe_output' } }
        $re = New-Object Text.RegularExpressions.Regex([string]$rule.VulnerablePattern, [Text.RegularExpressions.RegexOptions]::None, [TimeSpan]::FromSeconds(2))
        $status = 'Inconclusive'
        if ($re.IsMatch([string]$prop.Value)) { $status = 'PotentiallyVulnerable' }
        elseif ($rule.SafePattern -and (New-Object Text.RegularExpressions.Regex([string]$rule.SafePattern, [Text.RegularExpressions.RegexOptions]::None, [TimeSpan]::FromSeconds(2))).IsMatch([string]$prop.Value)) { $status = 'KnownFixed' }
        return @{ Passed = ($status -ceq [string]$sim.expected.status); Status = $status; Vendor = ''; Version = '' }
    }
    $c = Get-EloJavaClassification -Evidence ([string]$sim.probes.version) -Rules $rules
    $ok = ($c.Status -ceq [string]$sim.expected.status -and $c.Vendor -ceq [string]$sim.expected.vendor -and [string]$c.FullVersion -ceq [string]$sim.expected.version)
    return @{ Passed = $ok; Status = $c.Status; Vendor = $c.Vendor; Version = $c.FullVersion }
}
# ---- quarantine: every file the tool is about to modify is copied here first, with a manifest and a hash.
function Get-EloQuarantineRoot {
    param([string]$ProgramDataRoot = $env:ProgramData)
    if ([string]::IsNullOrWhiteSpace($ProgramDataRoot)) { throw 'quarantine_root_unavailable' }
    return (Join-Path (Join-Path $ProgramDataRoot 'ELO-Patch-Tools') 'quarantine')
}
function Get-EloFileSha256 {
    param([string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash
}
function Backup-EloFileToQuarantine {
    # Copies $Path into quarantine\<stamp>-<name>\ (file + manifest.json). Returns the record. Never deletes.
    param([Parameter(Mandatory=$true)][string]$Path, [Parameter(Mandatory=$true)][string]$Reason, [string]$Root = (Get-EloQuarantineRoot))
    $full = [IO.Path]::GetFullPath($Path)
    $info = Get-Item -LiteralPath $full -Force -ErrorAction Stop
    if ($info.PSIsContainer -or ($info.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'quarantine_source_not_a_file' }
    $stamp = [DateTime]::UtcNow.ToString('yyyyMMddHHmmssfff')
    $leaf = ($info.Name -creplace '[^A-Za-z0-9._\-]', '_')
    $id = $stamp + '-' + $leaf
    $dir = Join-Path $Root $id
    $null = [IO.Directory]::CreateDirectory($dir)
    $copy = Join-Path $dir $leaf
    [IO.File]::Copy($info.FullName, $copy, $false)
    $hash = Get-EloFileSha256 $copy
    if ($hash -cne (Get-EloFileSha256 $info.FullName)) { throw 'quarantine_copy_mismatch' }
    $record = [ordered]@{ id = $id; originalPath = $info.FullName; file = $leaf; sha256 = $hash; size = $info.Length; reason = $Reason; createdUtc = [DateTime]::UtcNow.ToString('o') }
    [IO.File]::WriteAllText((Join-Path $dir 'manifest.json'), ($record | ConvertTo-Json), (New-Object Text.UTF8Encoding($false)))
    return [pscustomobject]$record
}
function Get-EloQuarantineEntries {
    param([string]$Root = (Get-EloQuarantineRoot))
    if (-not (Test-Path -LiteralPath $Root -PathType Container)) { return @() }
    $entries = @()
    foreach ($dir in @(Get-ChildItem -LiteralPath $Root -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending | Select-Object -First 200)) {
        $manifest = Join-Path $dir.FullName 'manifest.json'
        if (-not (Test-Path -LiteralPath $manifest -PathType Leaf)) { continue }
        try { $m = [IO.File]::ReadAllText($manifest) | ConvertFrom-Json } catch { continue }
        if ($m.id -cne $dir.Name -or [string]$m.file -cnotmatch '^[A-Za-z0-9._\-]{1,128}$') { continue }
        $entries += $m
    }
    return @($entries)
}
function Restore-EloFileFromQuarantine {
    # Puts a quarantined copy back at its original path. The file being replaced is quarantined first, so a
    # restore can itself be undone. The copy's SHA256 is verified before and after.
    param([Parameter(Mandatory=$true)][string]$Id, [string]$Root = (Get-EloQuarantineRoot))
    if ($Id -cnotmatch '^[0-9]{17}-[A-Za-z0-9._\-]{1,128}$') { throw 'quarantine_id_invalid' }
    $dir = Join-Path $Root $Id
    $manifestPath = Join-Path $dir 'manifest.json'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) { throw 'quarantine_entry_missing' }
    $m = [IO.File]::ReadAllText($manifestPath) | ConvertFrom-Json
    $source = Join-Path $dir ([string]$m.file)
    if ((Get-EloFileSha256 $source) -cne [string]$m.sha256) { throw 'quarantine_hash_mismatch' }
    $target = [string]$m.originalPath
    if ([string]::IsNullOrWhiteSpace($target) -or -not [IO.Path]::IsPathRooted($target)) { throw 'quarantine_target_invalid' }
    $replaced = $null
    if (Test-Path -LiteralPath $target -PathType Leaf) { $replaced = Backup-EloFileToQuarantine -Path $target -Reason ('replaced by restore of ' + $Id) -Root $Root }
    $null = [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($target))
    $temp = $target + '.restore-' + [guid]::NewGuid().ToString('N')
    [IO.File]::Copy($source, $temp, $false)
    if ((Get-EloFileSha256 $temp) -cne [string]$m.sha256) { Remove-Item -LiteralPath $temp -Force; throw 'quarantine_restore_mismatch' }
    if (Test-Path -LiteralPath $target -PathType Leaf) { [IO.File]::Delete($target) }
    [IO.File]::Move($temp, $target)
    return [pscustomobject]@{ restored = $target; from = $Id; replacedCopy = $(if ($replaced) { $replaced.id } else { $null }) }
}
function Install-EloVulnDb {
    # Installs a reviewed catalog: validate -> quarantine the current installed copy -> atomic replace -> verify.
    param([Parameter(Mandatory=$true)][string]$Source, [string]$ProgramDataRoot = $env:ProgramData)
    $null = Read-EloVulnDbFile $Source
    $targetDir = Join-Path $ProgramDataRoot 'ELO-Patch-Tools'
    $target = Join-Path $targetDir 'vulndb.json'
    $null = [IO.Directory]::CreateDirectory($targetDir)
    $backup = $null
    if (Test-Path -LiteralPath $target -PathType Leaf) { $backup = Backup-EloFileToQuarantine -Path $target -Reason 'catalog replaced by install' -Root (Get-EloQuarantineRoot $ProgramDataRoot) }
    $temp = $target + '.new-' + [guid]::NewGuid().ToString('N')
    [IO.File]::Copy($Source, $temp, $false)
    try {
        $null = Read-EloVulnDbFile $temp
        if (Test-Path -LiteralPath $target -PathType Leaf) { [IO.File]::Delete($target) }
        [IO.File]::Move($temp, $target)
    } catch { if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force }; throw }
    if ((Get-EloFileSha256 $target) -cne (Get-EloFileSha256 $Source)) { throw 'vulndb_install_mismatch' }
    $script:EloVulnCache = $null
    return [pscustomobject]@{ installed = $target; quarantined = $(if ($backup) { $backup.id } else { $null }) }
}
