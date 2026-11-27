# Online catalog and tool self-update
Branch feat/online-updates. Delivery: ask-on-risk. Tests: dev/*.tests.ps1 (PowerShell 5.1, stdin closed; ui under pwsh).

## Specs
- S1: "mejora que si no se encuentra el archivo vulndb.json, que el .bat lo descargue de github"; confirmed: with no installed catalog, use the vulndb.json of the latest GitHub release automatically, say on screen which catalog is used. (Assumptions: SHA256 checked against SHA256SUMS.txt, schema validated; packaged fallback on any failure; never from a release older than the running tool, never older than the packaged one, never dropping a packaged vulnerability.)
- S2: "que se compruebe si hay una nueva release y que el .bat permita la actualizacion del mismo si se detecta". (Assumptions: only after explicit confirmation; SHA256 checked; the current .bat is kept as a backup; the new version runs after restarting the tool. ELO_PATCH_NO_UPDATE_CHECK=1 disables all GitHub access.)

## Tasks
- T1 (S1,S2) release client, catalog and install logic: done, inline (same commit)
- T2 (S2) launcher safe to replace while running: done, inline (same commit)
- T3 (S1,S2) web, CLI, docs: done, inline (same commit)

## Log
- L1: "mejora que si no se encuentra el archivo vulndb.json, que el .bat lo descargue de github"
- 2026-11-27: "si, y que se compruebe si hay una nueva release y que el .bat permita la actualizacion del mismo si se detecta."
- 2026-11-27: RED observed for online, server, CLI, UI and launcher tests; the old launcher executed content of a replaced .bat (exit 99). All suites green. Live: real release check and self-update of a scratch copy matched the published SHA256; the published catalog was refused as older than the packaged one.
