# Deterministic Windows PowerShell 5.1 tests for the vulnerability catalog engine (vulndb.ps1).
# No network, no machine changes: everything runs against temp folders and simulated probe output.
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\vulndb.ps1"
. "$PSScriptRoot\scan.ps1"
$script:Count = 0
function Assert($Condition, $Message) { if (-not $Condition) { throw "FAIL: $Message" }; $script:Count++ }
function Copy-Db($Db) { return ($Db | ConvertTo-Json -Depth 20 | ConvertFrom-Json) }
function Has-Problem($Db, $Pattern) { return (@(Test-EloVulnDb $Db | Where-Object { $_ -match $Pattern }).Count -gt 0) }

$packaged = Join-Path $PSScriptRoot 'vulndb.json'
$db = Read-EloVulnDbFile $packaged
Assert (@(Test-EloVulnDb $db).Count -eq 0) 'the packaged catalog is valid'
Assert ($db.schemaVersion -eq 1 -and @($db.sources).Count -ge 1) 'catalog has a schema version and sources'
$community = @($db.sources | Where-Object { $_.type -ceq 'elo-community' })[0]
Assert ($community.url -cmatch '^https://community\.elo\.com/.+board=KBB103' -and -not ($community.PSObject.Properties.Name -contains 'password')) 'the ELO community URL is shared without credentials'
$text = [IO.File]::ReadAllText($packaged)
Assert ($text -notmatch '(?i)"(password|apiKey|api_key|secret|token)"\s*:') 'the shared catalog never carries passwords or API keys'

# --- active vulnerabilities, rules and actions
$active = @(Get-EloActiveVulnerabilities $db)
Assert ($active.Count -ge 1 -and $active[0].id -ceq 'CVE-2026-114938' -and $active[0].severity -ceq 'high') 'the built-in vulnerability is active with its severity'
$rules = @(Get-EloScanRules $db)
Assert ($rules.Count -eq 2 -and $rules[1].Vendor -ceq 'Azul Zulu' -and $rules[1].AffectedFrom -ceq '17.0.6+0' -and $rules[0].Vendor -ceq 'Temurin' -and $rules[0].Fixed.Count -eq 4 -and $rules[0].Fixed -ccontains '17.0.21.1+2' -and $rules[0].Source -cmatch '^https://adoptium\.net/') 'scan rules come from the catalog'
$mit = Get-EloVulnAction $active[0] 'jvm-option'
Assert ($mit.option -ceq '-XX:-UseBASE64Intrinsics' -and $mit.variable -ceq 'JAVA_TOOL_OPTIONS' -and $mit.verify.mustBe -ceq 'false') 'the mitigation action is defined in the catalog'
Assert ((Get-EloVulnAction $active[0] 'runtime-update').recommended -eq $true -and (Get-EloVulnAction $active[0] 'restore-backup')) 'update and restore actions are defined'

# --- text formatting: placeholders from an allowlist only
Assert ((Format-EloVulnText 'a {vendor} {version} {unknown} {n}' @{vendor='Temurin';version='17';n=2}) -ceq 'a Temurin 17 {unknown} 2') 'known placeholders replaced, unknown ones kept'
Assert ((Format-EloVulnText '{id}' @{id='$& `n'}) -ceq '$& `n') 'replacement values are never interpreted'
Assert ((Get-EloVulnText $active[0].problem 'de' @{n=1;list='x'}) -match '^1 Runtime') 'German text available'

# --- detection engine: expect patterns over simulated probe output
$probe = $active[0].detection.probes[0]
$sim = $active[0].simulation
$r = Invoke-EloVulnProbe $probe { param($a) $sim.probes.version }
Assert ($r.Expect['vendor-temurin'] -eq $true -and $r.Expect['build-token'] -eq $true) 'expect patterns match the simulated java -version output'
$r2 = Invoke-EloVulnProbe $probe { param($a) 'openjdk version "21" Zulu21' }
Assert ($r2.Expect['vendor-temurin'] -eq $false) 'expect patterns do not match another vendor'
$bad = $false; try { $null = Invoke-EloVulnProbe ([pscustomobject]@{id='x';args=@('-version','; calc')}) { param($a) '' } } catch { $bad = $true }
Assert $bad 'probe arguments that are not plain java options are refused at run time'

# --- simulation: the catalog entry makes a runtime look vulnerable through the real classifier
$s = Invoke-EloVulnSimulation $active[0] $db
Assert ($s.Passed -and $s.Status -ceq 'PotentiallyVulnerable' -and $s.Vendor -ceq 'Temurin' -and $s.Version -ceq '17.0.2+8') 'simulation reproduces the vulnerable verdict'
$fixedEvidence = "openjdk version `"17.0.21.1`" 2026-11-17`nOpenJDK Runtime Environment Temurin-17.0.21.1+2 (build 17.0.21.1+2)`nOpenJDK 64-Bit Server VM Temurin-17.0.21.1+2 (build 17.0.21.1+2, mixed mode, sharing)`n"
$c = Get-EloJavaClassification -Evidence $fixedEvidence -Rules $rules
Assert ($c.Status -ceq 'KnownFixed' -and @($c.Findings).Count -eq 1 -and $c.Findings[0].Id -ceq 'CVE-2026-114938') 'a fixed build is classified fixed with a finding per vulnerability'
$none = Get-EloJavaClassification -Evidence $sim.probes.version -Rules @()
Assert ($none.Status -ceq 'Inconclusive') 'without catalog rules nothing is called vulnerable or fixed'
# a second vulnerability with a different fixed build: the worst verdict wins and each finding is kept
$second = @(@{Id='CVE-2027-0001';Severity='medium';Vendor='Temurin';Parser='temurin-build';Fixed=@('17.0.30.1+1');Source='https://example.org/a'}) + $rules
$m = Get-EloJavaClassification -Evidence $fixedEvidence -Rules $second
Assert ($m.Status -ceq 'PotentiallyVulnerable' -and @($m.Findings).Count -eq 2 -and (@($m.Findings | Where-Object { $_.Id -ceq 'CVE-2027-0001' })[0].Status -ceq 'PotentiallyVulnerable')) 'several vulnerabilities: worst verdict wins, one finding each'

# --- schema validation: new or AI-drafted entries cannot smuggle commands, credentials or bad links
$cases = @(
    @{ Name = 'shell metacharacters in probe args'; Edit = { param($d) $d.vulnerabilities[0].detection.probes[0].args = @('-version', '; calc') }; Match = 'probe' },
    @{ Name = 'a path as probe arg'; Edit = { param($d) $d.vulnerabilities[0].detection.probes[0].args = @('C:\evil.exe') }; Match = 'probe' },
    @{ Name = 'unknown action type'; Edit = { param($d) $d.vulnerabilities[0].actions[0].type = 'run-script' }; Match = 'type must be' },
    @{ Name = 'mitigation on another variable'; Edit = { param($d) $d.vulnerabilities[0].actions[1].variable = 'PATH' }; Match = 'JAVA_TOOL_OPTIONS' },
    @{ Name = 'mitigation option that is not one -XX flag'; Edit = { param($d) $d.vulnerabilities[0].actions[1].option = '-javaagent:evil.jar' }; Match = 'option must be' },
    @{ Name = 'invalid severity'; Edit = { param($d) $d.vulnerabilities[0].severity = 'critical' }; Match = 'severity' },
    @{ Name = 'invalid status'; Edit = { param($d) $d.vulnerabilities[0].status = 'enabled' }; Match = 'status' },
    @{ Name = 'missing German text'; Edit = { param($d) $d.vulnerabilities[0].problem.de = '' }; Match = 'problem' },
    @{ Name = 'unknown placeholder'; Edit = { param($d) $d.vulnerabilities[0].problem.en = 'run {evil}' }; Match = 'problem' },
    @{ Name = 'invalid regex in expect'; Edit = { param($d) $d.vulnerabilities[0].detection.probes[0].expect[0].pattern = '([' }; Match = 'not a valid pattern' },
    @{ Name = 'http source'; Edit = { param($d) $d.sources[0].url = 'http://community.elo.com/x' }; Match = 'https' },
    @{ Name = 'credentials in a source'; Edit = { param($d) $d.sources[0] | Add-Member -NotePropertyName password -NotePropertyValue 'x' }; Match = 'credentials' },
    @{ Name = 'http advisory'; Edit = { param($d) $d.vulnerabilities[0].advisories[0].url = 'http://example.org/a' }; Match = 'advisory' },
    @{ Name = 'fixed build in a wrong format'; Edit = { param($d) $d.vulnerabilities[0].detection.vendors.Temurin.fixed = @('latest') }; Match = 'fixed build' },
    @{ Name = 'unsupported vendor parser'; Edit = { param($d) $d.vulnerabilities[0].detection.vendors.Temurin.parser = 'powershell' }; Match = 'parser' },
    @{ Name = 'duplicate id'; Edit = { param($d) $d.vulnerabilities = @($d.vulnerabilities[0], $d.vulnerabilities[0]) }; Match = 'duplicate' },
    @{ Name = 'wrong schema version'; Edit = { param($d) $d.schemaVersion = 2 }; Match = 'schemaVersion' },
    @{ Name = 'too many probes'; Edit = { param($d) $p = $d.vulnerabilities[0].detection.probes[0]; $d.vulnerabilities[0].detection.probes = @($p, $p, $p, $p, $p) }; Match = 'probes' }
)
foreach ($case in $cases) {
    $copy = Copy-Db $db
    & $case.Edit $copy
    Assert (Has-Problem $copy $case.Match) ("catalog validation rejects: " + $case.Name)
}
$draft = Copy-Db $db; $draft.vulnerabilities[0].status = 'draft'
Assert (@(Test-EloVulnDb $draft).Count -eq 0 -and @(Get-EloActiveVulnerabilities $draft).Count -eq 0 -and @(Get-EloScanRules $draft).Count -eq 0) 'a draft entry is valid but never active and never used by the scan'


# --- Spanish (es) texts are optional but validated like the others
Assert ((Get-EloVulnText $active[0].problem 'es' @{n=2;list='x'}) -match '^2 runtime\(s\) son anteriores') 'Spanish problem text with placeholders'
Assert ((Get-EloVulnText ([pscustomobject]@{en='only English';de='nur Deutsch'}) 'es') -ceq 'only English') 'a text without es falls back to English'
$esBad = Copy-Db $db; $esBad.vulnerabilities[0].problem.es = 'ejecuta {evil}'
Assert (Has-Problem $esBad 'problem') 'a Spanish text with an unknown placeholder is rejected'
$esEmpty = Copy-Db $db; $esEmpty.vulnerabilities[0].problem.es = ''
Assert (Has-Problem $esEmpty 'problem') 'an empty Spanish text is rejected'
$noEs = Copy-Db $db; $noEs.vulnerabilities[0].problem.PSObject.Properties.Remove('es')
Assert (@(Test-EloVulnDb $noEs).Count -eq 0) 'a catalog entry without Spanish stays valid'
# --- file reading limits and fallback
$tmp = Join-Path ([IO.Path]::GetTempPath()) ('elo-vulndb-test-' + [guid]::NewGuid().ToString('N'))
$null = [IO.Directory]::CreateDirectory($tmp)
try {
    $bad = Join-Path $tmp 'bad.json'; [IO.File]::WriteAllText($bad, '{ not json')
    $threw = $false; try { $null = Read-EloVulnDbFile $bad } catch { $threw = $_.Exception.Message -ceq 'vulndb_invalid_json' }
    Assert $threw 'invalid JSON is refused'
    $big = Join-Path $tmp 'big.json'; [IO.File]::WriteAllText($big, ('x' * 1100000))
    $threw = $false; try { $null = Read-EloVulnDbFile $big } catch { $threw = $_.Exception.Message -ceq 'vulndb_too_large' }
    Assert $threw 'an oversized catalog is refused'
    $invalid = Copy-Db $db; $invalid.vulnerabilities[0].severity = 'x'
    $invalidPath = Join-Path $tmp 'invalid.json'; [IO.File]::WriteAllText($invalidPath, ($invalid | ConvertTo-Json -Depth 20))
    $threw = $false; try { $null = Read-EloVulnDbFile $invalidPath } catch { $threw = $_.Exception.Message -match '^vulndb_invalid: .*severity' }
    Assert $threw 'a schema violation names the problem'

    # --- quarantine: backup, restore, install with automatic backup
    $pd = Join-Path $tmp 'ProgramData'
    $qroot = Get-EloQuarantineRoot $pd
    $file = Join-Path $tmp 'config.txt'; [IO.File]::WriteAllText($file, 'original')
    $rec = Backup-EloFileToQuarantine -Path $file -Reason 'test' -Root $qroot
    Assert ($rec.sha256 -ceq (Get-EloFileSha256 $file) -and (Test-Path -LiteralPath (Join-Path (Join-Path $qroot $rec.id) 'config.txt')) -and (Test-Path -LiteralPath (Join-Path (Join-Path $qroot $rec.id) 'manifest.json'))) 'a file is copied to quarantine with a manifest and its SHA256'
    [IO.File]::WriteAllText($file, 'modified')
    Assert (@(Get-EloQuarantineEntries -Root $qroot).Count -eq 1) 'quarantine entries are listed'
    $restored = Restore-EloFileFromQuarantine -Id $rec.id -Root $qroot
    Assert ([IO.File]::ReadAllText($file) -ceq 'original' -and $restored.replacedCopy) 'restore puts the original back and quarantines what it replaced'
    Assert (@(Get-EloQuarantineEntries -Root $qroot).Count -eq 2) 'the replaced file is itself restorable'
    $dir = Join-Path $qroot $rec.id
    [IO.File]::WriteAllText((Join-Path $dir 'config.txt'), 'tampered')
    $threw = $false; try { $null = Restore-EloFileFromQuarantine -Id $rec.id -Root $qroot } catch { $threw = $_.Exception.Message -ceq 'quarantine_hash_mismatch' }
    Assert ($threw -and [IO.File]::ReadAllText($file) -ceq 'original') 'a tampered quarantine copy is refused and nothing is changed'
    foreach ($badId in @('..\x', '1', '20260101010101010-..\..\x', '20260101010101010-a b')) {
        $threw = $false; try { $null = Restore-EloFileFromQuarantine -Id $badId -Root $qroot } catch { $threw = $_.Exception.Message -ceq 'quarantine_id_invalid' }
        Assert $threw "quarantine id is validated: $badId"
    }
    $threw = $false; try { $null = Backup-EloFileToQuarantine -Path $tmp -Reason 'dir' -Root $qroot } catch { $threw = $true }
    Assert $threw 'a folder cannot be quarantined as a file'

    $first = Install-EloVulnDb -Source $packaged -ProgramDataRoot $pd
    $installed = Join-Path (Join-Path $pd 'ELO-Patch-Tools') 'vulndb.json'
    Assert ((Test-Path -LiteralPath $installed) -and -not $first.quarantined -and (Get-EloFileSha256 $installed) -ceq (Get-EloFileSha256 $packaged)) 'a reviewed catalog is installed and verified'
    $newer = Copy-Db $db; $newer.updated = '2027-01-01'
    $newerPath = Join-Path $tmp 'newer.json'; [IO.File]::WriteAllText($newerPath, ($newer | ConvertTo-Json -Depth 20))
    $second = Install-EloVulnDb -Source $newerPath -ProgramDataRoot $pd
    Assert ($second.quarantined -and @(Get-EloQuarantineEntries -Root (Get-EloQuarantineRoot $pd) | Where-Object { $_.file -ceq 'vulndb.json' }).Count -eq 1) 'installing over an existing catalog quarantines the previous one first'
    Assert ((Get-EloVulnDb -Path (Get-EloVulnDbPath $pd)).updated -ceq '2027-01-01') 'the installed catalog is the one used'
    $threw = $false; try { $null = Install-EloVulnDb -Source $invalidPath -ProgramDataRoot $pd } catch { $threw = $true }
    Assert ($threw -and (Get-EloFileSha256 $installed) -ceq (Get-EloFileSha256 $newerPath)) 'an invalid catalog is never installed and the current one is untouched'
    $undo = Restore-EloFileFromQuarantine -Id $second.quarantined -Root (Get-EloQuarantineRoot $pd)
    Assert ((Get-EloFileSha256 $installed) -ceq (Get-EloFileSha256 $packaged)) 'the previous catalog can be restored from quarantine'
    # a broken installed catalog falls back to the packaged one instead of disabling detection
    [IO.File]::WriteAllText($installed, '{ broken')
    $script:EloVulnCache = $null
    $path = Get-EloVulnDbPath $pd
    Assert ($path -ceq $installed) 'the installed catalog path wins when present'
} finally {
    $full = [IO.Path]::GetFullPath($tmp)
    if ($full.StartsWith([IO.Path]::GetFullPath([IO.Path]::GetTempPath()), [StringComparison]::OrdinalIgnoreCase) -and (Split-Path -Leaf $full) -like 'elo-vulndb-test-*') { Remove-Item -LiteralPath $full -Recurse -Force -ErrorAction SilentlyContinue }
}
Write-Output "PASS: $script:Count vulnerability catalog assertions"
