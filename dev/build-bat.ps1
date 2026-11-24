# Rebuilds the embedded resource blocks of ELO-Patch-Tools.bat from their dev/ sources.
# Idempotent: BOOTSTRAP_PS and BACKEND_PS stay as they are in the BAT (they are authored
# there); every other block is replaced by the current source file. Run with PowerShell 5.1+.
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$batPath = Join-Path $root 'ELO-Patch-Tools.bat'
$blocks = [ordered]@{
    SCAN_PS = 'scan.ps1'; CLI_PS = 'cli.ps1'; SERVER_PS = 'server.ps1'; UI_HTML = 'ui.html'
    REPORT_PS = 'report.ps1'; UPDATE_PS = 'update.ps1'
}
$text = [IO.File]::ReadAllText($batPath)
$text = $text -replace "`r`n", "`n"
foreach ($name in $blocks.Keys) {
    $source = [IO.File]::ReadAllText((Join-Path $PSScriptRoot $blocks[$name])).TrimEnd("`r", "`n") -replace "`r`n", "`n"
    if ($source -match '(?m)^::ELO_PATCH_') { throw "$($blocks[$name]) contains an extraction marker" }
    $block = "::ELO_PATCH_BEGIN:$name`n$source`n::ELO_PATCH_END:$name"
    $pattern = '(?ms)^::ELO_PATCH_BEGIN:' + $name + '\n.*?^::ELO_PATCH_END:' + $name + '[ \t]*$'
    if ([regex]::IsMatch($text, $pattern)) {
        $text = [regex]::Replace($text, $pattern, { param($m) $block })
    } else {
        $text = $text.TrimEnd("`n") + "`n`n" + $block + "`n"
    }
}
# Extraction one-liner: allow the update resource.
if (-not $text.Contains("UPDATE_PS='update.ps1'")) {
    $text = $text.Replace("REPORT_PS='report.ps1'}", "REPORT_PS='report.ps1';UPDATE_PS='update.ps1'}")
    $text = $text.Replace('|UI_HTML|REPORT_PS)$', '|UI_HTML|REPORT_PS|UPDATE_PS)$')
}
# Backend loads the update module next to the other trusted modules.
if (-not $text.Contains("'update.ps1')")) {
    $text = $text.Replace(". (Join-Path `$PSScriptRoot 'report.ps1')`n", ". (Join-Path `$PSScriptRoot 'report.ps1')`n. (Join-Path `$PSScriptRoot 'update.ps1')`n")
}
$text = $text.Replace('rem Single-file integration candidate. Automatic runtime update is unavailable.', 'rem Single-file tool. A runtime update runs only after explicit confirmation.')
[IO.File]::WriteAllText($batPath, ($text -replace "`n", "`r`n"), (New-Object Text.UTF8Encoding($false)))
Write-Output 'PASS: ELO-Patch-Tools.bat rebuilt from dev sources'
