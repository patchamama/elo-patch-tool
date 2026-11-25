# ELO Patch Tools
Single-file Windows tool; source, security controls, and verification remain in scope.
Branch: feature/elo-patch-tools.

## Specs
S1. "Entrega un solo archivo, por ejemplo `ELO-Patch-Tools.bat`. No entregues archivos auxiliares necesarios para ejecutarlo."
S2. "El escaneo debe ser de solo lectura. Busca instalaciones de ELO en las unidades disponibles, sin asumir una letra de unidad o ruta fija."
S3. "Si una JVM resulta potencialmente vulnerable, ofrece la mitigación temporal con: `-XX:-UseBASE64Intrinsics`"
S4. "Ofrece una opción separada para actualizar el runtime. La sustitución puede afectar compatibilidad y soporte, así que no la ejecutes automáticamente."
S5. "El frontend debe estar en inglés y alemán, con selector de idioma. Traduce botones, estados, errores, advertencias y confirmaciones."
S6. "también brinda una opción en script de hacer el patch manual en el sistema dando las instrucciones"
S7. "Añade pruebas para comparación de versiones, rutas con espacios, variable de entorno preexistente, extracción del BAT, cancelación del escaneo, fallo de descarga, respaldo, sustitución y restauración."
S8. "al final, genera un reporte en inglés y alemán con el nombre del servidor, que version de elo corre si se dan los datos de acceso a elo api con la url del api y el usuario y contraseña de acceso a elo, la version de java que se ejecutó y la actualización hecha, version de backup del antiguo jvm por si se desa restaurar, link con enlaces de información sobre el riesgo y solucion si se tiene, bueno todo un reporte que se pueda poner para informar a los técnicos de lo detectado y solucionado y como se solucionó."
S9. "agrega también en el reporte que se informe la version de windows que se está usando, y recursos del sistema como cantidad de RAM y espacio en disco."
S10. "si se hace el parche sin instalación, informarlo en el reporte de que se patcheo pero es preferible y posible hace rla instalación de la nueva version de java dando el link para descarga e instalación"
S11. "importante, no debe de buscarse la instalación de java en cualquier lugar, sino en todas las torres c: hasta z: para ver si existe en alguna la ruta \java\bin o \ELO\java\bin y habilita la opción de actualizar java y testear que la actualización se hizo bien corriendo un pequeño applet de java que puedes crear y descargar, y siempre hacer un backup en un zip de la instación inicial. Sí no se encuentra java instalado, que brinde la opción de poner el path donde se encuentra pero también que busque si hay varias instalaciones pues puede pasar."

S12. "poner en el reporte que si falla en algun momento la actualización de java, que se puede descomprimir la versión del backup y pon la ruta original donde estaba para informar donde descomprimirla con el comando desde el terminal de como eliminar la nueva versión y descomprimir la version del backup, también poner comando del cli para hacerlo desde el terminal. También el sistema debe de detectar si existe el patch desde la variable de entrono, es decir, si existe: JAVA_TOOL_OPTIONS con los parámetros requeridos y como parte del reporte se puede poner eso en caso de tener una version antigua de java no patcheada."

## Tasks
T1 [S1,S2,S7] Core scanning and classification; route: writer; DONE (a3a4db7, a5ea6eb).
T2 [S1,S5,S6] Web interface; route: writer; DONE (a3a4db7, 5dc134c adds update error messages).
T3 [S1,S3,S4,S6,S7] Integration, mitigation and update safety; route: inline; DONE (1e2e702, 0daed5d, 5dc134c).
T4 [S1-S12] Verification and delivery; route: inline; DONE: all dev/*.tests.ps1 pass (PowerShell 5.1; ui.tests under pwsh 7) and dev/update.live.tests.ps1 passed live (9ffc3f5).
T5 [S8-S10,S12] Bilingual technical report, recovery guidance, environment observation and optional ELO version lookup; route: writer; DONE (5dc134c: PowerShell and cmd restore commands, also after a successful update). ELO API version lookup stays unavailable: no verified installation-specific contract.
T6 [S2,S4,S7,S11] Restricted drive-root discovery and safe verified runtime updates; route: inline; DONE (0daed5d, 5dc134c, 9ffc3f5): Temurin 17.0.21.1+2 pinned, real adapters, Java self-test probe, live update + rollback verified.

T11 [S1-S12] Session survives a refresh (tab-scoped token), backups collapsed and restorable without a scan, red CVE alert with the update solution, highlighted terminal commands, backend window log, restore recorded in the report; route: inline; DONE.
T10 [S1-S12] Restore safety: existing backups show their CVE-2026-114938 status, restore preview warns that ELO Tomcat services are stopped; route: inline; DONE.
Known limits: Temurin and Azul Zulu (latest release of each branch) can be updated; runtime must be below a dedicated directory (not a drive root); quiescence is best effort; ELO compatibility is never assumed.
## Log
L1: "bien, ahora estamos ejecutandonos en un hyperV con windows y elo dms de prueba y todo está a salvo y aquí probaremos la herramienta, empieza con toda la implementación"
L2: "sí" — authorized initialization of Git.
L3: al final, genera un reporte en inglés y alemán con el nombre del servidor, que version de elo corre si se dan los datos de acceso a elo api con la url del api y el usuario y contraseña de acceso a elo, la version de java que se ejecutó y la actualización hecha, version de backup del antiguo jvm por si se desa restaurar, link con enlaces de información sobre el riesgo y solucion si se tiene, bueno todo un reporte que se pueda poner para informar a los técnicos de lo detectado y solucionado y como se solucionó.
L4: agrega también en el reporte que se informe la version de windows que se está usando, y recursos del sistema como cantidad de RAM y espacio en disco.
L5: si se hace el parche sin instalación, informarlo en el reporte de que se patcheo pero es preferible y posible hace rla instalación de la nueva version de java dando el link para descarga e instalación
L6: sí.... importante, no debe de buscarse la instalación de java en cualquier lugar, sino en todas las torres c: hasta z: para ver si existe en alguna la ruta \java\bin o \ELO\java\bin y habilita la opción de actualizar java y testear que la actualización se hizo bien corriendo un pequeño applet de java que puedes crear y descargar, y siempre hacer un backup en un zip de la instación inicial. Sí no se encuentra java instalado, que brinde la opción de poner el path donde se encuentra pero también que busque si hay varias instalaciones pues puede pasar.
L7: Read-only BAT scan returned C:\ELO\java\bin\java.exe, Azul Zulu 21.0.1+12-LTS, inconclusive; reached 10,000-entry budget in ELO temp. The result is incomplete.
L8: poner en el reporte que si falla en algun momento la actualización de java, que se puede descomprimir la versión del backup y pon la ruta original donde estaba para informar donde descomprimirla con el comando desde el terminal de como eliminar la nueva versión y descomprimir la version del backup, también poner comando del cli para hacerlo desde el terminal. También el sistema debe de detectar si existe el patch desde la variable de entrono, es decir, si existe: JAVA_TOOL_OPTIONS con los parámetros requeridos y como parte del reporte se puede poner eso en caso de tener una version antigua de java no patcheada.
L9: user authorized running tests and unblocking the production update gate on this disposable Hyper-V test machine; verified live (real download, self-test, replacement, rollback, restore commands). Bugs found live and fixed: OS_ARCH x86_64, optional JAVA_RUNTIME_VERSION, signed final URL (host pinning), per-request TLS unavailable on .NET Framework, directory mtime in fingerprint.
S13. "Mejora el frontend y hazlo más moderno poniendo iconos minimalistas, un wizard por pasos y estructurando mejor la experiencia IX/IU y el frontend se queda en "Progress unavailable" y no continua así que hay problemas ahí, así que testealo que funcione."
S14. "Mejora el soporte de las diferentes versiones de de java con azul zulu usando siempre la última version de cada branch, 21, 17,... y corrije todos los límites que quedan"
T7 [S13] Wizard frontend with minimalist icons, real progress/completion states, browser-tested (Chrome); route: inline; DONE: ui.html (5 steps, SVG sprite, busy indicator, restore), ui.tests wizard cases, opt-in dev/e2e/wizard.e2e.js (real server + Chrome: scan, update, report, restore, start over).
T8 [S14] Zulu + Temurin, latest release of every branch resolved from the official vendor APIs, 8/11/17/21/25, x86/x64/ARM64, JRE/JDK; route: inline; DONE: dev/catalog.ps1 + generic identity/policy in update.ps1; live-verified Temurin 17, Zulu 17, Zulu 8 (update, restore, rollback).
T9 [S14] Remaining limits: drive-root runtimes, opt-in service stop/restart, automatic restore from backup ZIP, CLI update, ELO version from installed product; route: inline; DONE: all five (unit + live tested, service stop/restart additionally verified with a throwaway real Windows service (never the ELO services)). Still open by nature: SACL backup, ELO compatibility proof.
L10: Mejora el frontend y hazlo más moderno poniendo iconos minimalistas, un wizard por pasos y estructurando mejor la experiencia IX/IU y el frontend se queda en "Progress unavailable" y no continua así que hay problemas ahí, así que testealo que funcione. Mejora el soporte de las diferentes versiones de de java con azul zulu usando siempre la última version de cada branch, 21, 17,... y corrije todos los límites que quedan
L11: Diagnosis (real Chrome + real server): scan completes, but the progress bar stays indeterminate with "Progress unavailable" after completion and nothing guides the user to the next step; results table is unreadable.
L12: Root causes found and fixed while testing for real: Azul API reports a rounded size (exact Content-Length check rejected every Zulu download); PowerShell 5.1 does not unroll JSON arrays (Zulu catalog returned nothing); 'Progress unavailable' was a label that never cleared after the scan (UX, not a hang); ELO version.txt is 90 KB (size cap rejected it).

# Feature: vulnerability catalog as JSON + AI-assisted community analysis (feature id: vulndb-json)
Branch: main (direct, user-requested push); delivery: work-unit commits; runner: dev/*.tests.ps1 (PS 5.1; ui.tests under pwsh 7), Node tests for tools/community.

## Specs (vulndb-json)
V1. "hagas un refactoring de la app de forma que sea más genérica y que en un json esté toda la información, comandos del terminal para determinar vulnerabilidades, posibles respuestas para detectar vulnerabilidades (expect), mensaje de problema de privacidad, acciones para solucionarlo y reporte final, de forma que en el futuro se puedan agregar más acciones ante nuevas vulnerabilidades de forma sencilla."
V2. "Revisa todo lo implementado hasta el momento y adapta todo para usar el json de configuración."
V3. "si se define en la app el uso de una IA como openai, anthropic, ollama, que sea capaz de leer y analizar articulos de reportes de vulnerabilidades del canal de elo community: https://community.elo.com/community/plugin/de.elo.ix.plugin.proxy/wf/apps/app/sol.knowledge.apps.KnowledgeBoard/#/?board=KBB103&page=1"
V4. "que de estos articulos se analice el nivel de la vulnerabilidad (alto, medio, bajo) y si se reportan soluciones y que ayude a generar una entrada en el archivo de acciones de json con reporte para solucionar el problema de la vulnerabilidad y también para testearlo generando quizás mocks o alguna forma de que parezca que la vulnerabilidad está ahí y que ayude a simularlo"
V5. "para acceder a elo community se necesitan datos de acceso como un usuario y contraseña y con playwright y puedes ver como acceder y que se ponga también un límite de artículos a analizar (por ejemplo, último mes, o últimos x meses, años, días y que tras el análisis reporte soluciones)."
V6. "Toda esa información del json y url a elo community (sin contraseñas) debe de compartirse en gh."
V7. "Siempre se harían copia de seguridad de los archivos que se modificarán y opción de restaurar, y estos archivos se deben de copiar a alguna carpeta de cuarentena."

## Tasks (vulndb-json)
T12 [V1,V2,V6] dev/vulndb.json + dev/vulndb.ps1 (loader, schema validation, expect engine, simulation) + tests; route: inline; DONE (vulndb.tests.ps1 56 assertions).
T13 [V1,V2] Adapt scan, server, report, CLI and UI to read rules, messages, actions and sources from the JSON; route: inline; DONE (scan rules incl. probe-expect, server metadata/mitigation/restore messages, report sources, CLI security block, UI alert/severity from API). Known limit: static UI help prose still describes the built-in CVE.
T14 [V7] Quarantine + backup + restore for every file the tool modifies (catalog installs/drafts); route: inline; DONE (Backup/Restore-EloFileFromQuarantine, Install-EloVulnDb, CLI --catalog-*; drafts are written to the quarantine folder).
T15 [V3,V4,V5,V6] tools/community: Playwright fetch with credentials from env only, date/count limits, AI providers (OpenAI, Anthropic, Ollama), draft JSON entry with simulation mock, quarantine of drafts; route: inline; DONE (23 Node tests, drafts validated by the app). NOT verified: board markup after sign-in and real AI answers (no account/keys).
T16 [V1-V7] Docs, rebuild BAT, full suites, commit + push; route: inline; DONE.

## Log (vulndb-json)
L1 2026-11-25 user: "commit + push origin main. Me gustaría que hagas un refactoring ..." (full text in V1-V7).
L2 2026-11-25 decisions: AI/community pipeline is an OPTIONAL Node tool (Playwright cannot run inside the PowerShell BAT); it writes DRAFTS only (never applies); credentials/API keys only from environment variables, never in JSON/GH; JSON commands are argument arrays for java.exe only (no shell, validated) so a draft cannot run arbitrary commands.
L3 2026-11-25 observed: sign-in page of the community is form#eloLoginForm (username/password, button Anmelden) behind /plugin/auth2/sign-in; the board is an AngularJS SPA. Tool quirk: Bash heredocs lose backslashes - write files with the Write/Edit tools.
