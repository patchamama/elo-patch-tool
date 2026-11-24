# Creates a disposable OLD runtime (Eclipse Temurin 17.0.2+8, vulnerable) at <Root>\java for the browser E2E.
param([Parameter(Mandatory=$true)][string]$Root)
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
Add-Type -AssemblyName System.IO.Compression.FileSystem
$null = New-Item -ItemType Directory $Root
$zip = Join-Path $Root 'old.zip'
(New-Object Net.WebClient).DownloadFile('https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.2%2B8/OpenJDK17U-jdk_x64_windows_hotspot_17.0.2_8.zip', $zip)
if ((Get-FileHash $zip -Algorithm SHA256).Hash -ine 'd083479ca927dce2f586f779373d895e8bf668c632505740279390384edf03fa') { throw 'old runtime hash mismatch' }
[IO.Compression.ZipFile]::ExtractToDirectory($zip, $Root)
Rename-Item (Join-Path $Root 'jdk-17.0.2+8') 'java'
Remove-Item -LiteralPath $zip
