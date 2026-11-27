@echo off
setlocal DisableDelayedExpansion
rem Intermediate assembly artifact; BACKEND_PS is the future PowerShell backend.
rem Invoke from cmd using normal Windows quoting/escaping. Do not use CALL expansion.
rem cmd expands percent-delimited variable names even inside quotes; expansion is not undone.
rem For literal percent-delimited names in a BAT path, invoke via a quoted path variable.
rem Embedded argument quotes require native argv backslash-quote syntax, not doubled quotes.
rem No execution-policy override: the host's PowerShell policy remains authoritative.
set "ELO_PATCH_SOURCE=%~f0"
set "ELO_PATCH_SESSION="
for /f "usebackq delims=" %%D in (`powershell.exe -NoProfile -NonInteractive -Command "$ErrorActionPreference='Stop'; $dir=$null; try { $blocks=@{}; $active=$null; $buffer=New-Object 'System.Collections.Generic.List[string]'; foreach($line in [IO.File]::ReadAllLines($env:ELO_PATCH_SOURCE)) { if($line.TrimStart().StartsWith('::ELO_PATCH_',[StringComparison]::OrdinalIgnoreCase)) { if($line -cnotmatch '^::ELO_PATCH_(BEGIN|END):(BOOTSTRAP_PS|BACKEND_PS)$') { throw 'Malformed extraction marker' }; $kind=$Matches[1]; $name=$Matches[2]; if($kind -ceq 'BEGIN') { if($null -ne $active -or $blocks.ContainsKey($name)) { throw 'Duplicate or nested extraction marker' }; $active=$name; $buffer.Clear() } else { if($active -cne $name) { throw 'Unmatched extraction marker' }; $blocks[$name]=[string]::Join([Environment]::NewLine,$buffer); $active=$null } } elseif($null -ne $active) { $buffer.Add($line) } }; if($null -ne $active -or $blocks.Count -ne 2) { throw 'Missing extraction marker' }; $dir=Join-Path ([IO.Path]::GetTempPath()) ('elo-patch-'+[guid]::NewGuid().ToString('N')); [void][IO.Directory]::CreateDirectory($dir); [IO.File]::WriteAllText((Join-Path $dir 'launcher.ps1'),$blocks['BOOTSTRAP_PS'],[Text.Encoding]::UTF8); [IO.File]::WriteAllText((Join-Path $dir 'backend.ps1'),$blocks['BACKEND_PS'],[Text.Encoding]::UTF8); Write-Output $dir } catch { if($null -ne $dir -and [IO.Directory]::Exists($dir)) { [IO.Directory]::Delete($dir,$true) }; [Console]::Error.WriteLine($_.Exception.Message); exit 1 }"`) do set "ELO_PATCH_SESSION=%%D"
if not defined ELO_PATCH_SESSION exit /b 1
rem Preserve the inherited console for CLI confirmation. The backend owns prompt safety:
rem read-only modes never prompt, and actions must refuse redirected/headless consoles.
rem Bootstrap normally cleans up. Also handle policy rejection before it can start.
rem Everything after PowerShell is ONE line: cmd loads it before running it and never reads this file
rem again, so the tool can safely replace this .bat (self-update) while it runs.
powershell.exe -NoProfile -File "%ELO_PATCH_SESSION%\launcher.ps1" %* & call set "ELO_PATCH_EXIT=%%errorlevel%%" & (if exist "%ELO_PATCH_SESSION%\launcher.ps1" if not exist "%ELO_PATCH_SESSION%\keep-temp" powershell.exe -NoProfile -NonInteractive -Command "try { [IO.Directory]::Delete($env:ELO_PATCH_SESSION,$true) } catch { [Console]::Error.WriteLine('Session cleanup failed: '+$_.Exception.Message); exit 1 }") & call exit /b %%ELO_PATCH_EXIT%%
exit /b 2

::ELO_PATCH_BEGIN:BOOTSTRAP_PS
# This block is extracted as launcher.ps1, never executed from the BAT text directly.
$ErrorActionPreference = 'Stop'
$keepTemp = $false
$forward = New-Object 'System.Collections.Generic.List[string]'
$code = 1
try {
    foreach ($argument in $args) {
        if ($argument -ceq '--keep-temp') { $keepTemp = $true }
        else { $forward.Add($argument) }
    }
    if ($keepTemp) {
        [IO.File]::WriteAllText((Join-Path $PSScriptRoot 'keep-temp'), '')
        [Console]::Error.WriteLine('Retaining intermediate session: ' + $PSScriptRoot)
    }
    $global:LASTEXITCODE = 0
    & (Join-Path $PSScriptRoot 'backend.ps1') @forward
    $code = $LASTEXITCODE
} catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    $code = 1
} finally {
    if (-not $keepTemp) {
        try { [IO.Directory]::Delete($PSScriptRoot, $true) }
        catch {
            [Console]::Error.WriteLine('Session cleanup failed: ' + $_.Exception.Message)
            $code = 1
        }
    }
}
exit $code
::ELO_PATCH_END:BOOTSTRAP_PS

::ELO_PATCH_BEGIN:BACKEND_PS
throw 'This is an intermediate launcher skeleton, not the final ELO tool. Assemble the real BACKEND_PS block before delivery.'
::ELO_PATCH_END:BACKEND_PS
