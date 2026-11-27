$ErrorActionPreference = 'Stop'
$env:ELO_PATCH_NO_UPDATE_CHECK = '1' # no suite contacts GitHub
Set-StrictMode -Version 2
$launcher = Join-Path $PSScriptRoot 'launcher.bat'
$work = Join-Path $PSScriptRoot ('launcher.test-work\run-' + [guid]::NewGuid().ToString('N'))
$oldTemp = $env:TEMP
$oldTmp = $env:TMP
$oldOutput = $env:ELO_LAUNCHER_TEST_OUTPUT
$oldSource = $env:ELO_PATCH_SOURCE
$passed = 0
function Assert($condition, [string]$message) {
    if (-not $condition) { throw $message }
}
function Invoke-Fixture([string]$text, [string]$arguments = '', [string]$fileName = 'synthetic launcher & test!.bat', [bool]$indirectPath = $false) {
    $case = Join-Path $work ('case space & bang! ' + [guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($case)
    $bat = Join-Path $case $fileName
    [IO.File]::WriteAllText($bat, $text, [Text.Encoding]::ASCII)
    $env:ELO_LAUNCHER_TEST_OUTPUT = Join-Path $case 'result.json'
    $psi = New-Object Diagnostics.ProcessStartInfo
    $psi.FileName = $env:ComSpec
    # cmd expands %NAME% even inside quotes. Expanding a path variable once is
    # the normal cmd mechanism for invoking paths that themselves contain %NAME%.
    $psi.EnvironmentVariables['ELO_LAUNCHER_TEST_BAT'] = $bat
    $psi.EnvironmentVariables['ELO_LAUNCHER_TEST_TOKEN'] = 'expanded-by-cmd'
    $psi.EnvironmentVariables['ELO_LAUNCHER_TEST_LITERAL'] = '%ELO_LAUNCHER_TEST_TOKEN%'
    $invocation = $bat
    if ($indirectPath) { $invocation = '%ELO_LAUNCHER_TEST_BAT%' }
    $psi.Arguments = '/d /v:off /c ""' + $invocation + '" ' + $arguments + '"'
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.RedirectStandardInput = $true
    $psi.EnvironmentVariables['ELO_LAUNCHER_TEST_CLI'] = (Join-Path $PSScriptRoot 'cli.ps1')
    $p = [Diagnostics.Process]::Start($psi)
    $p.StandardInput.Close()
    $stdout = $p.StandardOutput.ReadToEnd()
    $stderr = $p.StandardError.ReadToEnd()
    $p.WaitForExit()
    $result = $null
    if (Test-Path -LiteralPath $env:ELO_LAUNCHER_TEST_OUTPUT) {
        $result = Get-Content -LiteralPath $env:ELO_LAUNCHER_TEST_OUTPUT -Raw | ConvertFrom-Json
    }
    $code = $p.ExitCode
    $p.Dispose()
    [pscustomobject]@{ Code = $code; Result = $result; Text = $stdout + $stderr }
}
try {
    [void][IO.Directory]::CreateDirectory($work)
    $env:TEMP = $work
    $env:TMP = $work
    $env:ELO_PATCH_SOURCE = 'pre-existing value must not be used'
    Assert (Test-Path -LiteralPath $launcher) 'RED: launcher.bat does not exist'
    $source = [IO.File]::ReadAllText($launcher)
    Assert (-not ($source -match '(?i)-ExecutionPolicy\s+Bypass')) 'Launcher must not bypass execution policy'
    $backendPattern = '(?ms)(?<=::ELO_PATCH_BEGIN:BACKEND_PS\r?\n).*?(?=^::ELO_PATCH_END:BACKEND_PS\r?$)'
    $payload = @'
[pscustomobject]@{ Arguments = @($args); Session = $PSScriptRoot; ProcessArguments = @([Environment]::GetCommandLineArgs()) } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $env:ELO_LAUNCHER_TEST_OUTPUT -Encoding UTF8
exit 23
'@
    $synthetic = [regex]::Replace($source, $backendPattern, [System.Text.RegularExpressions.MatchEvaluator]{ param($m) $payload + "`r`n" })
    Assert ($synthetic -ne $source) 'Backend marker was not found'
    $r = Invoke-Fixture $synthetic '"two words" "a&b" "bang!" "(parentheses)" "semi;colon" "dollar$sign" "apostrophe''s" ""'
    Assert ($r.Code -eq 23) ('Backend exit code not preserved: ' + $r.Text)
    Assert ($null -ne $r.Result) ('Payload did not run: ' + $r.Text)
    Assert (@($r.Result.ProcessArguments | Where-Object { $_ -match '^(?i)[-/]noni' }).Count -eq 0) 'Backend process must not use -NonInteractive: live-console confirmation must remain possible'
    $expected = @('two words', 'a&b', 'bang!', '(parentheses)', 'semi;colon', 'dollar$sign', "apostrophe's", '')
    Assert (($r.Result.Arguments | ConvertTo-Json -Compress) -eq ($expected | ConvertTo-Json -Compress)) 'Arguments changed'
    Assert (-not (Test-Path -LiteralPath $r.Result.Session)) 'Ordinary exit left session files'
    $passed++
    # Construct non-ASCII names without relying on Windows PowerShell's script encoding.
    $unicodeName = 'launcher ' + [char]0x65E5 + [char]0x672C + ' 100% ready.bat'
    $r = Invoke-Fixture $synthetic '"100%" "say \"hello\"" "left\"middle\"right"' $unicodeName
    Assert ($r.Code -eq 23 -and $null -ne $r.Result) ('Unicode/percent BAT path failed: ' + $r.Text)
    $expected = @('100%', 'say "hello"', 'left"middle"right')
    Assert (($r.Result.Arguments | ConvertTo-Json -Compress) -ceq ($expected | ConvertTo-Json -Compress)) 'Percent or embedded quotes changed'
    Assert (-not (Test-Path -LiteralPath $r.Result.Session)) 'Unicode/percent run leaked session'
    $passed++
    $pairedName = $unicodeName.Replace('100% ready', '%ELO_LAUNCHER_TEST_TOKEN%')
    $r = Invoke-Fixture $synthetic '"100% complete" "%ELO_LAUNCHER_TEST_TOKEN%" "%ELO_LAUNCHER_TEST_LITERAL%"' $pairedName $true
    Assert ($r.Code -eq 23 -and $null -ne $r.Result) ('Indirect percent BAT path failed: ' + $r.Text)
    $expected = @('100% complete', 'expanded-by-cmd', '%ELO_LAUNCHER_TEST_TOKEN%')
    Assert (($r.Result.Arguments | ConvertTo-Json -Compress) -ceq ($expected | ConvertTo-Json -Compress)) 'Normal cmd percent expansion changed'
    Assert (-not (Test-Path -LiteralPath $r.Result.Session)) 'Paired-percent run leaked session'
    $passed++
    $success = $synthetic.Replace('exit 23', 'exit 0')
    $r = Invoke-Fixture $success '"<in>|out>^" "--ordinary-option"'
    Assert ($r.Code -eq 0) ('Successful backend failed: ' + $r.Text)
    Assert ($r.Result.Arguments[0] -ceq '<in>|out>^' -and $r.Result.Arguments[1] -ceq '--ordinary-option') 'Quoted cmd metacharacters changed'
    Assert (-not (Test-Path -LiteralPath $r.Result.Session)) 'Successful backend leaked session'
    Assert ($r.Result.Session.StartsWith($work + '\', [StringComparison]::OrdinalIgnoreCase)) 'Session escaped redirected TEMP'
    $passed++
    $first = Invoke-Fixture $synthetic '--keep-temp "kept argument"'
    $second = Invoke-Fixture $synthetic '--keep-temp "kept argument"'
    Assert ($first.Code -eq 23 -and $second.Code -eq 23) 'Keep-temp run failed'
    Assert ($first.Result.Session -ne $second.Result.Session) 'Session directories collided'
    Assert (Test-Path -LiteralPath $first.Result.Session) 'Keep-temp did not retain session'
    Assert (@($first.Result.Arguments).Count -eq 1 -and $first.Result.Arguments[0] -eq 'kept argument') 'Keep-temp leaked to backend'
    Assert ($first.Text.Contains($first.Result.Session)) 'Retained session path not reported'
    $passed++
    $badCases = @(
        ($synthetic + "`r`n::ELO_PATCH_BEGIN:BACKEND_PS`r`n"),
        ($synthetic.Replace('::ELO_PATCH_END:BACKEND_PS', '::REMOVED_BACKEND_END')),
        ($synthetic.Replace('::ELO_PATCH_BEGIN:BACKEND_PS', '::ELO_PATCH_BEGIN:BACKEND_PS malformed')),
        ($synthetic.Replace('::ELO_PATCH_END:BOOTSTRAP_PS', '::ELO_PATCH_END:BACKEND_PS')),
        ($synthetic + "`r`n::ELO_PATCH_BEGIN:UNKNOWN_PS`r`n"),
        ($synthetic.Replace('::ELO_PATCH_BEGIN:BOOTSTRAP_PS', '::REMOVED_BOOTSTRAP_BEGIN')),
        ($synthetic + "`r`n::ELO_PATCH_END:BACKEND_PS`r`n"),
        ($synthetic.Replace('::ELO_PATCH_BEGIN:BACKEND_PS', '::ELO_PATCH_BEGIN:backend_ps')),
        ($synthetic + "`r`n ::ELO_PATCH_BEGIN:BACKEND_PS`r`n"),
        ($synthetic + "`r`n::elo_patch_begin:backend_ps`r`n")
    )
    foreach ($bad in $badCases) {
        $before = @(Get-ChildItem -LiteralPath $work -Directory -Filter 'elo-patch-*').Count
        $r = Invoke-Fixture $bad
        Assert ($r.Code -ne 0) 'Malformed extraction succeeded'
        Assert ($null -eq $r.Result) 'Malformed extraction executed backend'
        Assert (@(Get-ChildItem -LiteralPath $work -Directory -Filter 'elo-patch-*').Count -eq $before) 'Malformed extraction leaked session'
        Assert ($r.Text -match 'marker') ('Missing useful extraction error: ' + $r.Text)
        $passed++
    }
    $throwing = [regex]::Replace($synthetic, $backendPattern, "throw 'Synthetic backend failure'`r`n")
    $before = @(Get-ChildItem -LiteralPath $work -Directory -Filter 'elo-patch-*').Count
    $r = Invoke-Fixture $throwing
    Assert ($r.Code -ne 0) 'Backend exception returned success'
    Assert (@(Get-ChildItem -LiteralPath $work -Directory -Filter 'elo-patch-*').Count -eq $before) 'Exception leaked session'
    $passed++
    $r = Invoke-Fixture $source
    Assert ($r.Code -ne 0 -and $r.Text -match 'intermediate') 'Skeleton must explicitly refuse to claim a finished tool'
    $passed++
    # Exercise the actual CLI gate, but inject only synthetic scanner/action adapters.
    # No discovery, admin check, registry write or ELO access can occur here.
    $cliPayload = @'
$cliArguments = @($args)
. (Join-Path (Split-Path -Parent $env:ELO_LAUNCHER_TEST_CLI) 'vulndb.ps1')
. $env:ELO_LAUNCHER_TEST_CLI
$script:applied = $false
$scanner = { param($ManualPath) [pscustomobject]@{ Results = @([pscustomobject]@{ Status = 'PotentiallyVulnerable' }); Cancelled = $false } }
$actions = @{
    IsAdmin = { $true }
    Preview = { param($Result) @{ Summary = 'Synthetic preview only'; Warnings = @('Synthetic warning') } }
    Apply = { param($Preview) $script:applied = $true; @{ ok = $true } }
}
$response = Invoke-EloCli -Arguments $cliArguments -Scanner $scanner -Actions $actions
[pscustomobject]@{
    Session = $PSScriptRoot
    Applied = $script:applied
    Report = ($response.Output | ConvertFrom-Json)
    ProcessArguments = @([Environment]::GetCommandLineArgs())
} | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $env:ELO_LAUNCHER_TEST_OUTPUT -Encoding UTF8
exit $response.ExitCode
'@
    $cliSynthetic = [regex]::Replace($source, $backendPattern, [System.Text.RegularExpressions.MatchEvaluator]{ param($m) $cliPayload + "`r`n" })
    $r = Invoke-Fixture $cliSynthetic '--cli --scan --json --no-browser'
    Assert ($r.Code -eq 0 -and $null -ne $r.Result) ('Headless read-only CLI failed: ' + $r.Text)
    Assert ($r.Result.Report.readOnly -and -not $r.Result.Applied) 'Read-only CLI reached Apply'
    Assert ([string]::IsNullOrWhiteSpace($r.Text)) ('Read-only CLI emitted a prompt: ' + $r.Text)
    Assert (-not (Test-Path -LiteralPath $r.Result.Session)) 'Read-only CLI leaked session'
    $passed++
    $r = Invoke-Fixture $cliSynthetic '--cli --mitigate --target 0 --confirm-admin --confirm-mitigation --json'
    Assert ($r.Code -eq 1 -and $null -ne $r.Result) ('Headless CLI did not fail closed: ' + $r.Text)
    Assert (@($r.Result.ProcessArguments | Where-Object { $_ -match '^(?i)[-/]noni' }).Count -eq 0) 'Headless test must exercise console detection without -NonInteractive'
    Assert ($r.Result.Report.error -match 'noninteractive action refused') 'Headless CLI failed for an unexpected reason'
    Assert ($null -ne $r.Result.Report.action.preview) 'Headless test did not reach the post-preview consent gate'
    Assert (-not $r.Result.Applied -and $r.Result.Report.readOnly) 'Headless CLI reached Apply'
    Assert ([string]::IsNullOrWhiteSpace($r.Text)) ('Headless CLI emitted a prompt: ' + $r.Text)
    Assert (-not (Test-Path -LiteralPath $r.Result.Session)) 'Headless CLI leaked session'
    $passed++
    # The tool may replace its own .bat while it runs (self-update). cmd reads batch files while executing
    # them, so nothing may be read from the file after PowerShell returns: the new content must never run.
    $junk = "'@echo off`r`n' + ('echo HIJACKED& exit /b 99`r`n' * 20000)"
    $replacing = "[IO.File]::WriteAllText(`$env:ELO_PATCH_SOURCE, $junk, [Text.Encoding]::ASCII)"
    $selfReplace = [regex]::Replace($source, $backendPattern, [System.Text.RegularExpressions.MatchEvaluator]{ param($m) $replacing + "`r`nexit 7`r`n" })
    $r = Invoke-Fixture $selfReplace
    Assert ($r.Code -eq 7 -and $r.Text -notmatch 'HIJACKED') ('Template launcher ran content of the replaced file: exit ' + $r.Code)
    $passed++
    $packaged = [IO.File]::ReadAllText((Join-Path (Split-Path -Parent $PSScriptRoot) 'ELO-Patch-Tools.bat'), [Text.Encoding]::UTF8)
    $fake = "param([switch]`$LoadOnly)`r`nfunction Invoke-EloPackagedTool { param([string[]]`$Arguments) $replacing; [pscustomobject]@{ ExitCode=7; Output='replaced' } }`r`n"
    $packagedReplace = [regex]::Replace($packaged, $backendPattern, [System.Text.RegularExpressions.MatchEvaluator]{ param($m) $fake })
    foreach ($code in @(7, 0)) {
        $r = Invoke-Fixture ($packagedReplace.Replace('ExitCode=7', "ExitCode=$code"))
        Assert ($r.Code -eq $code -and $r.Text -match 'replaced' -and $r.Text -notmatch 'HIJACKED') ('Packaged launcher ran content of the replaced file: exit ' + $r.Code + ' ' + $r.Text.Substring(0, [Math]::Min(200, $r.Text.Length)))
        $passed++
    }
    # An unbalanced quote swallows the one-line tail; cmd must stop there instead of running the lines below.
    $packagedPlain = $packagedReplace.Replace($replacing + '; [pscustomobject]', '[pscustomobject]')
    Assert ($packagedPlain -cne $packagedReplace) 'the plain packaged fixture must not replace the file'
    foreach ($text in @($synthetic, $packagedPlain)) {
        $r = Invoke-Fixture $text '--manual-path "C:\open'
        Assert ($r.Text -notmatch '(?i)syntax|unexpected|HIJACKED|is not recognized' -and $r.Code -ne 255) ('Unbalanced quote ran following lines: exit ' + $r.Code + ' ' + $r.Text.Substring(0, [Math]::Min(200, $r.Text.Length)))
        $passed++
    }
    Write-Host "PASS: $passed launcher checks"
} finally {
    $env:TEMP = $oldTemp
    $env:TMP = $oldTmp
    $env:ELO_LAUNCHER_TEST_OUTPUT = $oldOutput
    $env:ELO_PATCH_SOURCE = $oldSource
    if (Test-Path -LiteralPath $work) { Remove-Item -LiteralPath $work -Recurse -Force }
}
