# Starts the REAL local server (dev/ sources) for the browser E2E and writes its private launch URL to -UrlFile.
param([Parameter(Mandatory=$true)][string]$UrlFile)
$ErrorActionPreference = 'Stop'
$dev = Split-Path -Parent $PSScriptRoot
foreach ($module in @('vulndb.ps1','catalog.ps1','update.ps1','scan.ps1','server.ps1','report.ps1','cli.ps1')) { . (Join-Path $dev $module) }
$html = [IO.File]::ReadAllText((Join-Path $dev 'ui.html'), [Text.Encoding]::UTF8)
$source = [IO.File]::ReadAllText((Join-Path $dev 'scan.ps1'), [Text.Encoding]::UTF8)
Start-EloServer -UiHtml $html -ScanSource $source -NoBrowser -LaunchHandler { param($uri) [IO.File]::WriteAllText($UrlFile, $uri) }
