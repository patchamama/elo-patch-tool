# ELO service lifecycle around Java changes
Branch fix/elo-service-lifecycle. Delivery: ask-on-risk. Tests: dev/{server,update,ui,scan,vulndb}.tests.ps1 (Windows PowerShell 5.1); BAT rebuilt with dev/build-bat.ps1.

## Specs
- S1: "corregí la herramienta para que reconozca los servicios en Stop Pending". A service in Stop Pending that holds the runtime is a service, not a foreign process. The tool never force-kills it; if it stays stuck it fails with a clear message naming the service.
- S2: "sí al ejecutarse la herramiento no se detecta un problema de seguridad, debe de informarse que no se ha detectado un problema de seguridad". (Assumption: runtimes that cannot be evaluated are named as such, never called safe.)
- S3: "la herramienta también debe de servir para actualizar la versión de java que esté instalada para ELO y para ello debe de parar todos los servicios, hacer la instalación de última versión de java tras parar los servicios de elo y antes haber hecho copia de seguridad y después levantar los servicios nuevamente de elo (tomcat)". (Assumptions: ELO services = named ELO* or installed below the ELO folder that holds the runtime; only the ones that were active are started again; ELO-Basis stops last and starts first. The same applies to restore.)
- S4: "comprobar si se cargan bien, si no se cargan bien, puede ser un problema de compatibilidad con la versión de java nueva instalada y debe de permitir restaurar la version anterior". (Assumption: loaded = Running, still running after a settle time, and the TCP ports it listened on before are listening again. Restore is offered, not automatic.)
- S5: "Actualmente no está saliendo tras comprobar la seguridad resaltado en rojo que se ha detectado una vulnerabilidad, también corrije esto."

## Tasks
- T1 (S1) inline: done (same commit)
- T2 (S3) inline: done (same commit)
- T3 (S4) inline: done (same commit)
- T4 (S2) inline: done (same commit)
- T5 (S5) blocked: needs vendor, version and status of the ELO runtime from the user's scan

## Log
L1: "sí, corregí la herramienta para que reconozca los servicios en Stop Pending. Por otro lado, sí al ejecutarse la herramiento no se detecta un problema de seguridad, debe de informarse que no se ha detectado un problema de seguridad, pero la herramienta también debe de servir para actualizar la versión de java que esté instalada para ELO y para ello debe de parar todos los servicios, hacer la instalación de última versión de java tras parar los servicios de elo y antes haber hecho copia de seguridad y después levantar los servicios nuevamente de elo (tomcat) y comprobar si se cargan bien, si no se cargan bien, puede ser un problema de compatibilidad con la versión de java nueva instalada y debe de permitir restaurar la version anterior. Actualmente no está saliendo tras comprobar la seguridad resaltado en rojo que se ha detectado una vulnerabilidad, también corrije esto."
- 2026-11-27: baseline all suites green. Red alert wiring reads correctly; the catalog only has Temurin 17/21/25/27 fix data, any other vendor or branch is inconclusive.
- 2026-11-27: suites green (server 292, update, ui, scan 138, vulndb 61, report, cli 94, launcher 19, integration 150). RED was not observed: the first run with the new update tests stalled and was stopped. One update run also exceeded 280 s after passing; the next took 6 s. Windows service adapters were not exercised live. README updated, BAT rebuilt.
- 2026-11-27: independent verifier: S1, S2 pass; blockers B1 (restore did not start services that crashed after the update) and B2 (a shared folder such as Program Files was treated as the ELO folder). Correction batch: service record <backup>.services.json, ELO-folder check; RED observed, then green. Open advisory, unverified: the browser may drop an action request that runs for several minutes.
