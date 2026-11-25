# Standalone UI checks. Requires PowerShell 7 and Node.js; no packages, server or generated files.
$ErrorActionPreference = 'Stop'
$htmlPath = Join-Path $PSScriptRoot 'ui.html'
if (-not (Test-Path -LiteralPath $htmlPath)) { throw 'Missing dev/ui.html' }
if (-not (Get-Command node -ErrorAction SilentlyContinue)) { throw 'Node.js is required for isolated browser-contract tests.' }
# Verify embedded resources against their authoritative development sources.
$batText = [IO.File]::ReadAllText((Join-Path (Split-Path -Parent $PSScriptRoot) 'ELO-Patch-Tools.bat'))
foreach ($resource in @(@('SCAN_PS','scan.ps1'),@('SERVER_PS','server.ps1'),@('CLI_PS','cli.ps1'),@('UI_HTML','ui.html'),@('REPORT_PS','report.ps1'),@('UPDATE_PS','update.ps1'),@('CATALOG_PS','catalog.ps1'),@('VULNDB_PS','vulndb.ps1'),@('VULNDB_JSON','vulndb.json'))) {
    $match = [regex]::Match($batText, '(?ms)^::ELO_PATCH_BEGIN:' + $resource[0] + '\r?\n(.*?)^::ELO_PATCH_END:' + $resource[0] + '\s*$')
    $expected = [IO.File]::ReadAllText((Join-Path $PSScriptRoot $resource[1])).TrimEnd("`r", "`n")
    if (-not $match.Success -or ($match.Groups[1].Value.TrimEnd("`r", "`n") -replace "`r`n", "`n") -cne ($expected -replace "`r`n", "`n")) { throw "Embedded $($resource[0]) differs from source" }
}
$tests = @'
'use strict';
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const html = fs.readFileSync(process.argv[2], 'utf8');
const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)];
assert.equal(scripts.length, 1, 'one inline script');
assert(!/\b(?:src|href)\s*=\s*["']https?:/i.test(html), 'no remote assets');
assert(!/\.innerHTML|\.outerHTML|insertAdjacentHTML|\beval\s*\(|new Function/.test(html), 'no HTML/code injection sinks');
assert(html.includes("connect-src 'self'"), 'same-origin CSP');
assert(html.includes('-XX:-UseBASE64Intrinsics'), 'manual mitigation flag');
class Element {
 constructor(id = '') { this.id=id; this.children=[]; this.textContent=''; this.disabled=false; this.checked=false; this.value=''; this.dataset={}; this.attrs={}; }
 append(child) { this.children.push(child); if (this.children.length === 1 && this.id === 'results') this.value=child.value; }
 replaceChildren() { this.children=[]; this.value=''; }
 setAttribute(key,value) { this.attrs[key]=value; }
 removeAttribute(key) { delete this.attrs[key]; }
 click() { if(this.onclick) return this.onclick(); }
}
const tick = async () => { for(let n=0;n<4;n++) await new Promise(resolve => setImmediate(resolve)); };
const both = (en,de=en) => ({en,de});
const row = (overrides={}) => ({id:'installation_1',path:'C:\\ELO data\\<img onerror=alert(1)>',runtimeRoot:'C:\\ELO data\\jre',version:'17.0.1',vendor:'Example vendor <img>',architecture:'x64',status:'vulnerable',eloRationale:both('ELO service points to this JVM','ELO-Dienst verweist auf diese JVM'),classificationEvidence:both('Version and vendor matched advisory rules','Version und Hersteller entsprechen den Hinweisregeln'),...overrides});
// Fixtures exercise validation, not live advisory verification or applicability.
const securityFixture = () => ({verifiedOn:'2025-01-21',advisories:[{id:'oracle_fixture',title:both('Official Oracle advisory fixture','Offizieller Oracle-Testhinweis'),url:'https://www.oracle.com/security-alerts/cpujan2025.html'}]});
function boot(hash = '#token=test-session-token', storage = null) {
 const elements = new Map([...html.matchAll(/\bid="([^"]+)"/g)].map(m => [m[1],new Element(m[1])]));
 const translated = [...html.matchAll(/data-i18n="([^"]+)"/g)].map(m => { const el=new Element(); el.dataset.i18n=m[1]; return el; });
 const calls=[],downloads=[],timers=[];
 let status={state:'completed',progress:100,checked:4}, results=[row()], security=securityFixture(), backups=null, vulns=null, communityHandler=null;
 let preview={previewId:'preview_1',summary:both('Backup then change <script>unsafe()</script>','Sichern, dann ändern'),warnings:[both('Check compatibility','Kompatibilität prüfen')]};
 let failure=null, errorBody={error:'operation_failed',warnings:[]}, raw=null, ack={ok:true};
 const history={replaceState(...args) { history.args=args; }};
 const document={documentElement:{},getElementById:id => elements.get(id),querySelectorAll:() => translated,createElement:() => new Element()};
 class BrowserURL extends URL {
 static createObjectURL(blob) { downloads.push(blob); return 'blob:local'; }
 static revokeObjectURL() {}
 }
 const context={document,location:{hash,pathname:'/ui',search:''},...(storage ? {sessionStorage:storage} : {}),history,URLSearchParams,Blob,Date,JSON,Number,Set,TextDecoder,URL:BrowserURL,
 setInterval(fn) { timers.push(fn); },setTimeout(fn) { fn(); },
 async fetch(path,options) {
 calls.push({path,options});
 assert.equal(history.args[2],'/ui','fragment removed before first request');
 if(failure === 'network') throw Error('sensitive backend diagnostic');
 if(failure) return new Response(typeof errorBody === 'string' ? errorBody : JSON.stringify(errorBody),{status:failure});
 if(raw !== null) return new Response(raw);
 if(path.includes('/community/')) { const r=communityHandler(path.split('/api/')[1],options.body ? JSON.parse(options.body) : undefined); if (r && r.__status) return new Response(JSON.stringify(r.body),{status:r.__status}); return new Response(JSON.stringify(r)); }
 if(path.endsWith('/report')) {
 const language=JSON.parse(options.body).language;
 assert.deepEqual(Object.keys(JSON.parse(options.body)),['language'],'no client-provided evidence');
 return new Response(JSON.stringify({html:'<!doctype html><html lang="'+language+'"><body>safe report</body></html>'}));
 }
 const body=path.endsWith('/status') ? status : path.endsWith('/results') ? {results,security,...(backups === null ? {} : {backups}),...(vulns === null ? {} : {vulnerabilities:vulns})} : path.endsWith('/preview') ? preview : ack;
 return new Response(JSON.stringify(body));
 }};
 vm.runInNewContext(scripts[0][1],context,{timeout:2000});
 return {el:id => elements.get(id),calls,downloads,history,translated,document,
 poll:async () => { await timers[0](); await tick(); },
 status:value => { status=value; },backups:value => { backups=value; },vulns:value => { vulns=value; },community:value => { communityHandler=value; },results:value => { results=value; },security:value => { security=value; },preview:value => { preview=value; },failure:(value,body={error:'operation_failed',warnings:[]}) => { failure=value; errorBody=body; },raw:value => { raw=value; },ack:value => { ack=value; }};
}
(async () => {
 const technical=boot(); await tick();
 for(const language of ['en','de']) {
 technical.el('language').value=language; technical.el('language').onchange();
 await technical.el('exportTechnical').click();
 const request=technical.calls.at(-1);
 assert.equal(request.path,'/api/report'); assert.equal(request.options.method,'POST');
 assert.equal(request.options.headers['X-Session-Token'],'test-session-token');
 assert.deepEqual(JSON.parse(request.options.body),{language});
 assert((await technical.downloads.at(-1).text()).includes('<html lang="'+language+'">'));
 assert.equal(technical.downloads.at(-1).type,'text/html;charset=utf-8');
 }
 technical.failure(401); const downloadCount=technical.downloads.length;
 await technical.el('exportTechnical').click();
 assert.equal(technical.downloads.length,downloadCount,'authentication failure never downloads');
 const ui=boot(); await tick();
 const searchHelp=ui.translated.find(el => el.dataset.i18n === 'searchHelp');
 for (const language of ['en','de']) {
 ui.el('language').value=language; ui.el('language').onchange();
 const text=searchHelp.textContent;
 assert(text.includes('C:') && text.includes('Z:') && text.includes('X:\\java\\bin\\java.exe') && text.includes('X:\\ELO\\java\\bin\\java.exe'), 'both locales describe exact drive-root layouts');
 assert(language === 'en' ? /ready fixed or removable/i.test(text) && /after.*root/i.test(text) : /bereit.*fest.*wechsel/i.test(text) && /nach.*Stamm/i.test(text), 'both locales describe drive eligibility and manual order');
 }
 ui.el('language').value='en'; ui.el('language').onchange();
 assert.equal(ui.history.args[2],'/ui'); assert.equal(ui.calls.length,2);
 for(const {path,options} of ui.calls) {
 assert(path.startsWith('/api/')); assert(!path.includes('test-session-token'));
 assert.equal(options.headers['X-Session-Token'],'test-session-token');
 assert.equal(options.credentials,'omit'); assert.equal(options.redirect,'error');
 }
 assert(ui.el('details').textContent.includes('<img onerror=alert(1)>'),'untrusted path is literal text');
 assert(ui.el('details').textContent.includes('C:\\ELO data\\jre'));
 assert(ui.el('details').textContent.includes('Example vendor <img>'));
 assert(ui.el('details').textContent.includes('ELO service points to this JVM'));
 assert(ui.el('details').textContent.includes('Version and vendor matched advisory rules'));
 const zuluUi=boot(); await tick();
 zuluUi.results([row({vendor:'Azul Zulu',version:'21.0.1+12-LTS',status:'inconclusive',classificationEvidence:both('OpenJDK Runtime Environment Zulu21.30+15-CA (build 21.0.1+12-LTS)')})]);
 await zuluUi.poll();
 assert(zuluUi.el('details').textContent.includes('Azul Zulu'));
 assert(zuluUi.el('details').textContent.includes('Inconclusive'));
 assert(!zuluUi.el('details').textContent.includes('Patched'));
 assert.equal(ui.el('jvmRows').children.length,1);
 assert.equal(ui.el('jvmRows').children[0].children.length,8,'complete evidence table');
 assert.equal(ui.el('verifiedOn').textContent,'Source verification date (UTC): 2025-01-21');
 const link=ui.el('advisories').children[0].children[0];
 assert.equal(link.href,securityFixture().advisories[0].url);
 assert.equal(link.rel,'noopener noreferrer'); assert.equal(link.referrerPolicy,'no-referrer');
 assert.equal(link.target,'_blank');
 assert(!ui.calls.some(call => call.path.startsWith('https:')),'advisory not fetched automatically');
 assert.equal(ui.el('apply').disabled,true,'no automatic action');
 await ui.el('mitigate').click();
 assert.equal(ui.el('confirm').checked,false); assert.equal(ui.el('apply').disabled,true,'preview alone does not authorize');
 assert(ui.el('preview').textContent.includes('<script>unsafe()</script>'),'preview remains literal text');
 await ui.poll(); assert.equal(ui.el('confirm').disabled,false,'unchanged results preserve preview');
 await ui.el('apply').click(); assert(!ui.calls.some(c => c.path === '/api/action'),'unchecked action blocked');
 ui.el('confirm').checked=true; ui.el('confirm').onchange(); assert.equal(ui.el('apply').disabled,false);
 await ui.el('apply').click();
 const action=ui.calls.find(c => c.path === '/api/action');
 assert.deepEqual(JSON.parse(action.options.body),{actionId:'mitigate',resultId:'installation_1',previewId:'preview_1'});
 assert.equal(ui.el('apply').disabled,true,'single-use local confirmation');
 await ui.el('update').click();
 assert.equal(JSON.parse(ui.calls.at(-1).options.body).actionId,'update-runtime','separate update action ID');
 assert(ui.el('confirmation').textContent.includes('runtime update'));
 ui.el('confirm').checked=true; ui.el('confirm').onchange();
 ui.el('results').onchange(); assert.equal(ui.el('apply').disabled,true,'selection change invalidates confirmation');
 await ui.el('update').click();
 ui.results([row({classificationEvidence:both('Changed evidence','Geänderter Nachweis')})]); await ui.poll();
 assert.equal(ui.el('apply').disabled,true,'evidence change invalidates preview');
 await ui.el('update').click();
 ui.status({state:'scanning',progress:25,checked:1}); await ui.poll();
 assert.equal(ui.el('apply').disabled,true,'scan transition invalidates preview');
 assert.equal(ui.el('cancel').disabled,false); assert.equal(ui.el('searchPath').disabled,true);
 await ui.el('cancel').click();
 assert.equal(ui.calls.at(-1).path,'/api/cancel'); assert.deepEqual(JSON.parse(ui.calls.at(-1).options.body),{});
 assert(ui.el('status').textContent.includes('waiting')); assert.equal(ui.el('cancel').disabled,true);
 ui.status({state:'cancelled'}); await ui.poll(); assert(ui.el('status').textContent.includes('incomplete'));
 ui.el('language').value='de'; ui.el('language').onchange();
 assert.equal(ui.document.documentElement.lang,'de'); assert(ui.el('status').textContent.includes('abgebrochen'));
 assert(ui.el('details').textContent.includes('ELO-Dienst verweist auf diese JVM'));
 assert(ui.el('details').textContent.includes('Geänderter Nachweis'));
 assert(ui.el('verifiedOn').textContent.includes('Prüfdatum'));
 assert(ui.el('advisories').children[0].children[0].textContent.includes('Testhinweis'));
 await ui.el('update').click(); assert(ui.el('preview').textContent.includes('Sichern, dann ändern'));
 assert(ui.el('preview').textContent.includes('Kompatibilität prüfen'));
 assert(ui.el('activity').textContent.includes('Abbruch angefordert'),'log translated on language change');
 assert.equal(ui.el('manual').children.length,6);
 for (const needle of ['Compress-Archive','Expand-Archive','Stop-Service','Start-Service','Get-FileHash','JAVA_TOOL_OPTIONS','-XX:-UseBASE64Intrinsics','Rename-Item']) assert(ui.translated.find(el => el.dataset.i18n === 'manualCommands').textContent.includes(needle),'German manual commands include '+needle);
 assert(ui.translated.find(el => el.dataset.i18n === 'manualCommands').textContent.includes('ADMINISTRATOR-PowerShell'),'comments are localized');
 assert(ui.el('manual').children.some(el => el.textContent.includes('-XX:-UseBASE64Intrinsics')));
 for (const el of ui.translated) assert(el.textContent && el.textContent !== 'Unbekannt','translation exists: '+el.dataset.i18n);
 ui.failure(403,{error:'access_denied',warnings:[both('Check permissions','Berechtigungen prüfen')]}); await ui.poll(); assert(ui.el('error').textContent.includes('Zugriff verweigert'));
 assert(ui.el('error').textContent.includes('Berechtigungen prüfen'));
 assert(!ui.el('error').textContent.includes('Sitzungstoken'));
 assert(!ui.el('error').textContent.includes('sensitive')); assert.equal(ui.el('update').disabled,true);
 ui.failure('network'); await ui.poll(); assert(ui.el('error').textContent.includes('nicht erreichbar'));
 ui.failure(null); ui.status({state:'completed'});
 ui.results([row({path:'test-session-token',vendor:'test-session-token',eloRationale:both('test-session-token'),status:'inconclusive'})]); await ui.poll();
 assert(!ui.el('details').textContent.includes('test-session-token'),'defensive token redaction in all evidence');
 await ui.el('exportJson').click(); await ui.el('exportLog').click();
 const report=await ui.downloads[0].text(), activity=await ui.downloads[1].text(), exported=JSON.parse(report);
 assert(!report.includes('test-session-token')); assert(!activity.includes('test-session-token'));
 assert(!activity.includes('installation_1') && !activity.includes('C:\\'), 'logs contain fixed events, not backend payloads');
 assert.equal(exported.results[0].path,'[redacted]'); assert.equal(exported.results[0].vendor,'[redacted]');
 assert.equal(exported.results[0].runtimeRoot,'C:\\ELO data\\jre');
 assert.equal(exported.assessmentComplete,true); assert(!Number.isNaN(Date.parse(exported.lastSuccessfulRefresh)));
 assert.equal(exported.results[0].classificationEvidence.de,'Version und Hersteller entsprechen den Hinweisregeln');
 assert.deepEqual(exported.security,securityFixture(),'advisory evidence preserved in export');
 // Required classification labels in both languages, one row per JVM even at same ELO path.
 ui.results(['patched','not-affected','inconclusive'].map((status,n) => row({id:'jvm_'+n,status}))); await ui.poll();
 assert.deepEqual(ui.el('jvmRows').children.map(tr => tr.children[5].textContent),['Gepatcht','Nicht betroffen','Nicht eindeutig']);
 ui.el('language').value='en'; ui.el('language').onchange();
 assert.deepEqual(ui.el('jvmRows').children.map(tr => tr.children[5].textContent),['Patched','Not affected','Inconclusive']);
 // Invalid/missing/oversized data must never collapse to a safe-looking row.
 const invalidRows=[
 [row({id:'bad;command'})], [row({status:'future-safe-status'})], [row({runtimeRoot:undefined})],
 [row({vendor:'x'.repeat(257)})], [row({path:'x'.repeat(1025)})], [row({version:'x'.repeat(129)})],
 [row({architecture:'shell'})], [row({vendor:'   '})], [row({eloRationale:both('x'.repeat(2049))})],
 [row({classificationEvidence:both('x'.repeat(4097))})], [row({classificationEvidence:{en:'only English'}})],
 [row({extra:'unexpected'})], [row(),row()], Array.from({length:251},(_,n) => row({id:'jvm_'+n}))
 ];
 for (const results of invalidRows) {
 ui.results([row()]); await ui.poll(); await ui.el('update').click();
 ui.results(results); await ui.poll();
 assert(ui.el('error').textContent.includes('invalid response'),'invalid JVM data rejected');
 assert.equal(ui.el('apply').disabled,true); assert.equal(ui.el('update').disabled,true);
 assert(ui.el('resultNotice').textContent.includes('stale'));
 }
 await ui.el('exportJson').click();
 assert.equal(JSON.parse(await ui.downloads.at(-1).text()).assessmentComplete,false,'invalid refresh exports are marked incomplete');
 ui.results(Array.from({length:250},(_,n) => row({id:'jvm_'+n}))); await ui.poll();
 assert.equal(ui.el('error').textContent,''); assert.equal(ui.el('jvmRows').children.length,250,'bounded maximum accepted');
 ui.results([row()]); await ui.poll();
 const temurinUrl='https://adoptium.net/news/2026/11/temurin-november-2026-cspu-java4shell/';
 const oracleLinuxUrl='https://linux.oracle.com/cve/CVE-2026-114938.html';
 // The catalog decides which sources exist; the UI only refuses links that are not plain https pages.
 const badAdvisoryUrls=[
 oracleLinuxUrl.replace('https:','http:'),
 oracleLinuxUrl.replace('linux.oracle.com','user@linux.oracle.com'),
 oracleLinuxUrl.replace('linux.oracle.com','linux.oracle.com@evil.example'),
 oracleLinuxUrl.replace('linux.oracle.com','linux.oracle.com:444'),
 oracleLinuxUrl.replace('linux.oracle.com','linux.oracle.com:443'),
 oracleLinuxUrl+'?redirect=https://evil.example',
 oracleLinuxUrl+'#fragment',
 oracleLinuxUrl.replace('/cve/','/cve/../cve/'),
 oracleLinuxUrl.replace('CVE-','%43VE-'),
 temurinUrl.replace('/news/','/news/../news/'),
 temurinUrl.replace('temurin','%74emurin'),
 temurinUrl.replace('https:','http:'),
 'javascript:alert(1)','data:text/html,x','ftp://example.org/x',
 'https://www.oracle.com/security-alerts/cpujan2025.html?token=test-session-token',
 'https://www.oracle.com/security-alerts/test-session-token.html',
 'https://exa mple.org/x',
 'https://EXAMPLE.org/x'
 ]; for(const url of badAdvisoryUrls) {
 const security=securityFixture(); security.advisories[0].url=url; ui.security(security); await ui.poll();
 assert(ui.el('error').textContent.includes('invalid response'),'unsafe advisory URL rejected: '+url);
 }
 for(const verifiedOn of ['2025-02-30','2099-01-01','yesterday',null]) {
 ui.security({...securityFixture(),verifiedOn}); await ui.poll(); assert(ui.el('error').textContent.includes('invalid response'),'invalid verification date rejected');
 }
 for(const security of [
 {verifiedOn:'2025-01-21',advisories:[]},
 {...securityFixture(),advisories:Array(17).fill(securityFixture().advisories[0])},
 {...securityFixture(),advisories:[securityFixture().advisories[0],securityFixture().advisories[0]]},
 {...securityFixture(),unexpected:'key'},
 {verifiedOn:'2025-01-21',advisories:[{...securityFixture().advisories[0],title:both('x'.repeat(257))}]}
 ]) { ui.security(security); await ui.poll(); assert(ui.el('error').textContent.includes('invalid response')); }
 ui.security({verifiedOn:null,advisories:[]}); await ui.poll();
 assert(ui.el('verifiedOn').textContent.includes('No verified advisory'));
 assert.equal(ui.el('advisories').children.length,0);
 const openjdk=securityFixture(); openjdk.advisories[0].url='https://openjdk.org/groups/vulnerability/advisories/';
 ui.security(openjdk); await ui.poll(); assert.equal(ui.el('error').textContent,'');
 const temurin=securityFixture(); temurin.advisories[0].url=temurinUrl;
 ui.security(temurin); await ui.poll();
 assert.equal(ui.el('error').textContent,'','exact parent-verified Temurin URL accepted');
 assert.equal(ui.el('advisories').children[0].children[0].href,temurinUrl,'exact Temurin link rendered');
 assert.equal(ui.el('advisories').children[0].children[0].rel,'noopener noreferrer');
 assert(!ui.calls.some(call => call.path.startsWith('https:')),'Temurin link not fetched automatically');
 const oracleLinux=securityFixture(); oracleLinux.advisories[0].url=oracleLinuxUrl;
 ui.security(oracleLinux); await ui.poll();
 assert.equal(ui.el('error').textContent,'','exact parent-verified Oracle Linux URL accepted');
 assert.equal(ui.el('advisories').children[0].children[0].href,oracleLinuxUrl);
 assert.equal(ui.el('advisories').children[0].children[0].rel,'noopener noreferrer');
 ui.security(securityFixture());
 // Preview bounds and confirmation replay handling.
 for(const preview of [
 {previewId:'bad;command',summary:both('x'),warnings:[]},
 {previewId:'preview_2',summary:'English only',warnings:[]},
 {previewId:'preview_2',summary:both('x'.repeat(4097)),warnings:[]},
 {previewId:'preview_2',summary:both('x'),warnings:Array(17).fill(both('x'))},
 {previewId:'preview_2',summary:both('x'),warnings:[both('x'.repeat(2049))]}
 ]) {
 await ui.poll(); ui.preview(preview); await ui.el('update').click();
 assert.equal(ui.el('apply').disabled,true,'invalid preview rejected');
 }
 await ui.poll(); ui.preview({previewId:'preview_2',summary:both('x'),warnings:[]}); await ui.el('update').click();
 ui.el('confirm').checked=true; ui.el('confirm').onchange(); ui.failure(409,{error:'preview_expired_or_mismatched',warnings:[]}); await ui.el('apply').click();
 assert(ui.el('error').textContent.includes('expired')); assert.equal(ui.el('apply').disabled,true);
 ui.failure(null); await ui.poll(); ui.ack({ok:false}); await ui.el('scan').click();
 assert(ui.el('error').textContent.includes('request failed'),'negative acknowledgement not treated as completion');
 ui.ack({ok:true}); await ui.poll();
 for(const status of [{state:'completed',progress:101},{state:'completed',checked:-1},{state:'unexpected'}]) {
 ui.status(status); await ui.poll(); assert(ui.el('error').textContent.includes('invalid response'));
 }
 ui.status({state:'completed'}); ui.raw(' '.repeat(4*1024*1024)+'{}'); await ui.poll();
 assert(ui.el('error').textContent.includes('invalid response'),'oversized transport rejected');
 ui.raw('{invalid json'); await ui.poll(); assert(ui.el('error').textContent.includes('invalid response'));
 const missing=boot(''); await tick();
 assert.equal(missing.calls.length,0,'no requests without token'); assert.equal(missing.el('scan').disabled,true);
 assert(missing.el('error').textContent.includes('session token'));
 // Empty root means discovery. A path with spaces and shell metacharacters stays plain JSON data.
 const scan=boot(); await tick(); await scan.el('scan').click();
 assert.equal(scan.calls.at(-1).path,'/api/scan'); assert.deepEqual(JSON.parse(scan.calls.at(-1).options.body),{});
 assert.equal(scan.el('scan').disabled,true); assert.equal(scan.el('results').children[0].textContent,'No JVMs found');
 const manual=boot(); await tick(); await manual.el('update').click();
 manual.el('confirm').checked=true; manual.el('confirm').onchange();
 manual.el('searchPath').value='C:\\ELO data\\R&D; $(literal)'; manual.el('searchPath').oninput();
 assert.equal(manual.el('apply').disabled,true,'new search root clears confirmation');
 await manual.el('scan').click();
 assert.deepEqual(JSON.parse(manual.calls.at(-1).options.body),{searchPath:'C:\\ELO data\\R&D; $(literal)'});
 assert(!manual.el('activity').textContent.includes('R&D'),'manual root not logged');
 const invalidPath=boot(); await tick();
 for(const value of ['relative','C:relative','\\\\server\\share','\\\\?\\C:\\data','C:\\..\\data','C:\\data\\*','C:\\data\nother','C:\\data:stream','C:\\CON','C:\\data.','C:\\'+ 'x'.repeat(1022)]) {
 invalidPath.el('searchPath').value=value;
 const before=invalidPath.calls.length; await invalidPath.el('scan').click();
 assert.equal(invalidPath.calls.length,before,'invalid root never sent: '+JSON.stringify(value));
 assert(invalidPath.el('error').textContent.includes('absolute local Windows'));
 }
 invalidPath.el('language').value='de'; invalidPath.el('language').onchange();
 assert(invalidPath.el('error').textContent.includes('Windows-Verzeichnis'));
 // Stable error codes, bounded bilingual warnings and sticky critical recovery.
 const changeLocale=(view,value) => { view.el('language').value=value; view.el('language').onchange(); };
 const readyToApply=async view => {
 await view.el('mitigate').click(); view.el('confirm').checked=true; view.el('confirm').onchange();
 assert.equal(view.el('apply').disabled,false);
 };
 const admin=boot(); await tick();
 admin.failure(403,{error:'administrator_required',warnings:[both('Admin warning <img onerror=unsafe()> test-session-token','Adminhinweis <img onerror=unsafe()> test-session-token')]});
 await admin.el('mitigate').click();
 assert(admin.el('error').textContent.includes('elevated administrator session'));
 assert(admin.el('error').textContent.includes('Admin warning <img onerror=unsafe()> [redacted]'),'known warning stays literal text and redacts token');
 assert(!admin.el('error').textContent.includes('Missing or rejected'));
 changeLocale(admin,'de');
 assert(admin.el('error').textContent.includes('erhöhte Administratorsitzung'));
 assert(admin.el('error').textContent.includes('Adminhinweis'));
 assert.equal(admin.el('apply').disabled,true);
 admin.failure(null); await admin.poll();
 assert(admin.el('error').textContent.includes('Administratorsitzung'),'request error survives successful background poll');
 await admin.el('mitigate').click(); assert.equal(admin.el('error').textContent,'','explicit retry clears request error');
 const denied=boot(); await tick();
 denied.failure(403,{error:'access_denied',warnings:[both('Denied fixture','Verweigert-Test')]}); await denied.poll();
 assert(denied.el('error').textContent.includes('Access denied')); assert(!denied.el('error').textContent.includes('session token'));
 changeLocale(denied,'de'); assert(denied.el('error').textContent.includes('Zugriff verweigert')); assert(denied.el('error').textContent.includes('Verweigert-Test'));
 denied.failure(401,{error:'authentication_required',warnings:[]}); await denied.poll();
 assert(denied.el('error').textContent.includes('Sitzungstoken'),'only auth code is labelled authentication');
 denied.failure(403,{error:'host_rejected',warnings:[]}); await denied.poll();
 assert(denied.el('error').textContent.includes('Anfragegrenzen'),'403 boundary denial is not authentication');
 const unavailable=boot(); await tick();
 const unavailableCode='update_unavailable_provenance_compatibility_backup_replacement_rollback_not_verified';
 unavailable.failure(503,{error:unavailableCode,warnings:[both('No replacement was attempted','Keine Ersetzung versucht')]}); await unavailable.el('update').click();
 assert(unavailable.el('error').textContent.includes('Automatic runtime update is unavailable'));
 assert(unavailable.el('error').textContent.includes('No replacement was attempted'));
 changeLocale(unavailable,'de'); assert(unavailable.el('error').textContent.includes('Laufzeit-Update nicht verfügbar')); assert(unavailable.el('error').textContent.includes('Keine Ersetzung versucht'));
 assert.equal(unavailable.el('apply').disabled,true); assert(!unavailable.calls.some(call => call.path === '/api/action'));
 const rolledBack=boot(); await tick(); await readyToApply(rolledBack);
 rolledBack.failure(422,{error:'verification_failed_rolled_back',warnings:[both('Previous value and type restored','Alter Wert und Typ wiederhergestellt')]}); await rolledBack.el('apply').click();
 assert(rolledBack.el('error').textContent.includes('restored and read back'));
 assert.equal(rolledBack.el('recoveryNotice').textContent,'','verified rollback does not claim manual recovery is needed');
 changeLocale(rolledBack,'de'); assert(rolledBack.el('error').textContent.includes('zurückgelesen')); assert(rolledBack.el('error').textContent.includes('Alter Wert und Typ'));
 const recovery=boot(); await tick(); await readyToApply(recovery);
 recovery.failure(500,{error:'rollback_failed_manual_recovery_required',warnings:[both('Restore-exact fixture <b>old type</b> test-session-token','Exakt-wiederherstellen-Test <b>alter Typ</b> test-session-token')]}); await recovery.el('apply').click();
 assert(recovery.el('error').textContent.includes('Rollback failed'));
 assert(recovery.el('recoveryNotice').textContent.includes('CRITICAL: JAVA_TOOL_OPTIONS'));
 assert(recovery.el('recoveryNotice').textContent.includes('value AND registry type'));
 assert(recovery.el('recoveryNotice').textContent.includes('<b>old type</b> [redacted]'));
 assert(!recovery.el('recoveryNotice').textContent.includes('test-session-token'));
 assert.equal(recovery.el('scan').disabled,true); assert.equal(recovery.el('apply').disabled,true); assert.equal(recovery.el('confirm').checked,false);
 recovery.failure(null); await recovery.poll();
 assert(recovery.el('recoveryNotice').textContent.includes('CRITICAL'),'successful poll cannot clear recovery lock');
 recovery.failure('network'); await recovery.poll(); changeLocale(recovery,'de');
 assert(recovery.el('recoveryNotice').textContent.includes('KRITISCH'));
 assert(recovery.el('recoveryNotice').textContent.includes('Exakt-wiederherstellen-Test'));
 assert(recovery.el('recoveryNotice').textContent.includes('Registrierungstyp'));
 recovery.failure(null); await recovery.poll();
 const beforeRecoveryRequests=recovery.calls.length;
 await recovery.el('scan').click(); await recovery.el('update').click(); await recovery.el('mitigate').click(); await recovery.el('apply').click();
 assert.equal(recovery.calls.length,beforeRecoveryRequests,'recovery lock blocks all further mutation requests');
 await recovery.el('exportJson').click(); await recovery.el('exportLog').click();
 const recoveryReport=JSON.parse(await recovery.downloads[0].text()), recoveryLog=await recovery.downloads[1].text();
 assert.equal(recoveryReport.recoveryRequired,true); assert.equal(recoveryReport.assessmentComplete,false);
 assert(!recoveryLog.includes('test-session-token') && !recoveryLog.includes('Restore-exact') && !recoveryLog.includes('Exakt-wiederherstellen'));
 assert(!recoveryLog.includes('rollback_failed') && !recoveryLog.includes('Confirmed action completed'));
 const manualRecovery=boot(); await tick();
 manualRecovery.failure(409,{error:'manual_recovery_required_close_session',warnings:[{en:'INVALID WARNING WITHOUT GERMAN'}]}); await manualRecovery.el('mitigate').click();
 assert(manualRecovery.el('error').textContent.includes('Manual recovery'));
 assert(!manualRecovery.el('error').textContent.includes('expired'),'recovery 409 is never mislabeled expiry');
 assert(manualRecovery.el('recoveryNotice').textContent.includes('CRITICAL'),'critical code stays visible even when its warning is malformed');
 assert(!manualRecovery.el('recoveryNotice').textContent.includes('INVALID WARNING'));
 const unsafe=boot(); await tick();
 for(const body of [
 {error:'unknown_<script>test-session-token</script>',warnings:[both('UNTRUSTED <script>test-session-token</script>')]},
 {error:'__proto__',warnings:[both('UNTRUSTED')]},
 {error:'x'.repeat(129),warnings:[both('UNTRUSTED')]},
 {error:'access_denied',warnings:[{en:'UNTRUSTED'}]},
 {error:'access_denied',warnings:Array(17).fill(both('UNTRUSTED'))},
 {error:'access_denied',warnings:[both('UNTRUSTED'.repeat(300))]},
 {error:'access_denied',warnings:[{en:'UNTRUSTED',de:'UNTRUSTED',extra:'unexpected'}]},
 {error:'access_denied',warnings:[],extra:'UNTRUSTED'},
 'UNTRUSTED non-JSON error test-session-token',
 ' '.repeat(256*1024)+'{"error":"access_denied","warnings":[]}'
 ]) {
 unsafe.failure(500,body); await unsafe.poll();
 assert(!unsafe.el('error').textContent.includes('UNTRUSTED')); assert(!unsafe.el('error').textContent.includes('test-session-token'));
 assert.equal(unsafe.el('apply').disabled,true);
 }
 unsafe.failure(409,{error:'unknown_future_code',warnings:[both('UNTRUSTED')]}); await unsafe.poll();
 assert(unsafe.el('error').textContent.includes('request failed')); assert(!unsafe.el('error').textContent.includes('expired'));
 await unsafe.el('exportLog').click();
 assert(!((await unsafe.downloads[0].text()).includes('UNTRUSTED')));
 // ---- wizard: honest progress, automatic advance, reachable steps, restore.
 const shown=(view,n) => view.el('step'+n).attrs.hidden === undefined;
 const visibleSteps=view => [1,2,3,4,5].filter(n => shown(view,n)).join(',');
 const wiz=boot(); await tick();
 assert.equal(visibleSteps(wiz),'1','the wizard starts on the scan step');
 assert.equal(wiz.el('nav1').attrs['data-state'],'current'); assert.equal(wiz.el('nav4').disabled,true,'confirm step needs a preview');
 assert.equal(wiz.el('progress').attrs.hidden,'', 'no progress bar while idle'); assert(!wiz.el('progressText').textContent.includes('unavailable'));
 await wiz.el('scan').click();
 wiz.status({state:'scanning'}); await wiz.poll();
 assert.equal(wiz.el('progress').attrs.hidden,undefined,'bar visible only while scanning'); assert(wiz.el('progressText').textContent.includes('Scanning drives'));
 assert(!wiz.el('progressText').textContent.includes('Progress unavailable'),'never the dead-end message');
 assert.equal(visibleSteps(wiz),'1'); assert.equal(wiz.el('nav3').disabled,true,'no later step while scanning');
 wiz.status({state:'completed'}); await wiz.poll();
 assert.equal(visibleSteps(wiz),'2','a finished scan advances the wizard on its own');
 assert.equal(wiz.el('progress').attrs.hidden,''); assert.equal(wiz.el('progressText').textContent,'');
 assert(wiz.el('scanSummary').textContent.includes('Java runtimes found: 1'));
 assert.equal(wiz.el('cards').children.length,1); const card=wiz.el('cards').children[0];
 assert.equal(card.attrs['aria-checked'],'true'); assert(card.children[0].textContent.includes('Example vendor <img> 17.0.1'),'runtime card shows text literally');
 await wiz.el('toStep3').click(); assert.equal(visibleSteps(wiz),'3');
 await wiz.el('update').click(); assert.equal(visibleSteps(wiz),'4','a received preview opens the confirm step');
 assert.equal(wiz.el('previewKind').textContent,'Runtime update'); assert.equal(wiz.el('apply').disabled,true);
 await wiz.el('back4').click(); assert.equal(visibleSteps(wiz),'3'); assert.equal(wiz.el('apply').disabled,true,'going back drops the preview');
 await wiz.el('update').click(); wiz.el('confirm').checked=true; wiz.el('confirm').onchange();
 await wiz.el('apply').click();
 assert.equal(visibleSteps(wiz),'5','a completed action opens the report step');
 assert(wiz.el('finalNotice').textContent.includes('updated and verified')); assert.equal(wiz.el('restore').attrs.hidden,undefined,'restore is offered after an update');
 await wiz.el('restore').click(); assert.equal(visibleSteps(wiz),'4');
 assert.equal(JSON.parse(wiz.calls.at(-1).options.body).actionId,'restore-backup'); assert.equal(wiz.el('previewKind').textContent,'Restore from backup');
 assert(wiz.el('confirmation').textContent.includes('restore preview'));
 wiz.el('confirm').checked=true; wiz.el('confirm').onchange(); await wiz.el('apply').click();
 assert.equal(visibleSteps(wiz),'5'); assert(wiz.el('finalNotice').textContent.includes('restored from the backup ZIP')); assert.equal(wiz.el('restore').attrs.hidden,'','restore only after an update in this page session');
 changeLocale(wiz,'de'); assert(wiz.el('finalNotice').textContent.includes('wiederhergestellt'));
 changeLocale(wiz,'en');
 await wiz.el('startOver').click(); assert.equal(visibleSteps(wiz),'1');
 // The shown step falls back when its prerequisite disappears (changed evidence invalidates the preview).
 const fallback=boot(); await tick(); await fallback.el('toStep3').click(); await fallback.el('mitigate').click();
 assert.equal(visibleSteps(fallback),'4');
 fallback.results([row({classificationEvidence:both('Changed evidence','Geänderter Nachweis')})]); await fallback.poll();
 assert.equal(visibleSteps(fallback),'3','a stale preview cannot keep the confirm step open'); assert.equal(fallback.el('apply').disabled,true);
 fallback.results([]); fallback.status({state:'completed'}); await fallback.poll();
 assert.equal(visibleSteps(fallback),'1','no results sends the wizard back to the scan step'); assert.equal(fallback.el('nav2').disabled,true);
 // A cancelled scan or an empty result never advances; empty results explain what to do.
 const cancelled=boot(); await tick(); await cancelled.el('scan').click(); cancelled.status({state:'cancelled'}); await cancelled.poll();
 assert.equal(visibleSteps(cancelled),'1');
 const empty=boot(); await tick(); empty.results([]); await empty.el('scan').click(); empty.status({state:'completed'}); await empty.poll();
 assert.equal(visibleSteps(empty),'1'); assert(empty.el('scanSummary').textContent.includes('No Java runtime found'));
 changeLocale(empty,'de'); assert(empty.el('scanSummary').textContent.includes('Keine Java-Runtime gefunden'));
 // Busy indicator while a request is pending; stable server codes for the new update outcomes.
 const outcomes=boot(); await tick();
 for (const [code,text] of [['update_not_needed','newest release'],['no_backup_for_target','No backup made'],['restore_failed_no_change','restore was rejected'],['update_failed_rolled_back','failed validation'],['update_rejected_no_change','rejected before the runtime was replaced']]) {
   outcomes.failure(code==='update_not_needed'||code==='no_backup_for_target'?409:422,{error:code,warnings:[both('Detail A','Detail B')]}); await outcomes.el('update').click();
   assert(outcomes.el('error').textContent.includes(text),'message for '+code); assert(outcomes.el('error').textContent.includes('Detail A'));
   outcomes.failure(null);
 }
 outcomes.failure(500,{error:'update_manual_recovery_required',warnings:[both('ZIP restore needed','ZIP noetig')]}); await outcomes.el('update').click();
 assert(outcomes.el('recoveryNotice').textContent.includes('CRITICAL')); assert.equal(outcomes.el('apply').disabled,true); assert.equal(outcomes.el('nav2').disabled,true); // ---- existing backups are shown first and restorable by server-side id.
 const bk=(over={}) => ({id:'bk_1',path:'C:\\ELO\\java.backup-20260101120000.zip',runtime:'C:\\ELO\\java',version:'17.0.2+8',vendor:'Temurin',risk:'vulnerable',created:'2026-01-01 12:00',size:205911747,...over});
 const backupsUi=boot(); await tick();
 assert.equal(backupsUi.el('backupsBox').attrs.hidden,'', 'no backups, no box');
 backupsUi.backups([bk(),bk({id:'bk_2',version:'21.0.1'})]); await backupsUi.poll();
 assert.equal(backupsUi.el('backupsBox').attrs.hidden,undefined,'existing backups are shown on the first step'); assert.equal(backupsUi.el('backups').children.length,2);
 const bcard=backupsUi.el('backups').children[0];
 assert(bcard.children[0].textContent.includes('C:\\ELO\\java — 17.0.2+8') && bcard.children[3].textContent.includes('2026-01-01 12:00 UTC · 196 MB'));
 assert(bcard.children[1].dataset.status === 'vulnerable' && bcard.children[1].textContent.includes('vendor fix') && bcard.children[4].textContent.includes('ELO Tomcat'));
 assert.equal(backupsUi.el('backups').children[1].children[1].dataset.status,'vulnerable');
 backupsUi.backups([bk({risk:'unknown',vendor:'Azul Zulu'}),bk({id:'bk_2',risk:'patched'})]); await backupsUi.poll(); assert.equal(backupsUi.el('backups').children[0].children[1].dataset.status,'inconclusive'); assert.equal(backupsUi.el('backups').children[1].children[1].dataset.status,'patched'); backupsUi.backups([bk(),bk({id:'bk_2',version:'21.0.1'})]); await backupsUi.poll();
 await bcard.onclick();
 assert.deepEqual(JSON.parse(backupsUi.calls.at(-1).options.body),{actionId:'restore-backup',resultId:'bk_1'}); assert.equal(visibleSteps(backupsUi),'4');
 assert.equal(backupsUi.el('previewKind').textContent,'Restore from backup');
 backupsUi.el('confirm').checked=true; backupsUi.el('confirm').onchange(); await backupsUi.el('apply').click();
 assert.deepEqual(JSON.parse(backupsUi.calls.at(-1).options.body),{actionId:'restore-backup',resultId:'bk_1',previewId:'preview_1'}); assert.equal(visibleSteps(backupsUi),'5');
 backupsUi.el('language').value='de'; backupsUi.el('language').onchange(); assert(backupsUi.el('backupsSummary').textContent.startsWith('Vorhandene Backups')); changeLocale(backupsUi,'en');
 for (const bad of [[bk({id:'bad;id'})],[bk({size:-1})],[bk({path:''})],[bk({extra:1})],[bk(),bk()],Array.from({length:51},(_,n) => bk({id:'bk_'+n})),'nope']) {
   backupsUi.backups(bad); await backupsUi.poll(); assert(backupsUi.el('error').textContent.includes('invalid response'),'invalid backup list rejected');
 }
 backupsUi.backups([bk()]); await backupsUi.poll(); assert.equal(backupsUi.el('error').textContent,''); // ---- a page refresh keeps the session; a rejected token is forgotten; backups are collapsed; the red advice.
 const store=new Map(), storage={getItem:k => store.has(k) ? store.get(k) : null,setItem:(k,v) => { store.set(k,v); },removeItem:k => { store.delete(k); }};
 const hex64='ab12'.repeat(16);
 const first=boot('#token='+hex64,storage); await first.poll();
 assert.equal(first.calls[0].options.headers['X-Session-Token'],hex64);
 const refreshed=boot('',storage); await refreshed.poll();
 assert.equal(refreshed.calls[0].options.headers['X-Session-Token'],hex64,'refresh without the fragment reuses the tab session token');
 assert.equal(refreshed.el('error').textContent,'','no token error after a refresh');
 refreshed.failure(401,{error:'authentication_required',warnings:[]}); await refreshed.poll();
 assert(refreshed.el('error').textContent.includes('Missing or rejected session token') && !store.has('eloSessionToken'),'a rejected token is forgotten');
 const noToken=boot('',storage); await tick();
 assert(noToken.el('error').textContent.includes('Missing or rejected session token'),'without any token the link must be reopened');
 const throwing=boot('#token='+hex64,{getItem() { throw Error('blocked'); },setItem() { throw Error('blocked'); },removeItem() { throw Error('blocked'); }}); await throwing.poll();
 assert.equal(throwing.calls[0].options.headers['X-Session-Token'],hex64,'blocked storage does not break the fragment token');
 assert(/<details id="backupsBox"(?![^>]*\bopen\b)/.test(html),'existing backups are collapsed by default');
 const adviceUi=boot(); await tick();
 adviceUi.backups([bk(),bk({id:'bk_2',risk:'patched',version:'17.0.21.1+2'})]); await adviceUi.poll();
 assert(adviceUi.el('backupsSummary').textContent.includes('(2)') && adviceUi.el('backupsSummary').textContent.includes('vulnerable'),'collapsed summary shows the count and the risk');
 assert.equal(adviceUi.el('vulnAlert').attrs.hidden,undefined,'a vulnerable runtime shows the red alert on the runtime step');
 assert(adviceUi.el('vulnList').children[0].children[1].textContent.includes('1 runtime(s)') && adviceUi.el('vulnList').children[0].children[1].textContent.includes('ELO data'),'legacy rows still get the generic alert');
 assert.equal(adviceUi.el('vulnRec').attrs.hidden,undefined,'the update recommendation is repeated on the action step');
 assert.equal(adviceUi.el('cards').children[0].dataset.status,'vulnerable','vulnerable runtime card is flagged');
 const cmds=adviceUi.el('terminalCmds').children;
 assert(cmds.length >= 8 && cmds[0].className === 'c-note' && cmds[1].children.some(piece => piece.className === 'c-flag' && piece.textContent === '--update-runtime'),'terminal commands are highlighted (comments and flags)');
 assert(cmds[1].children.map(piece => piece.textContent).join('').startsWith('.\ELO-Patch-Tools.bat --cli --update-runtime'),'the launcher path keeps its backslash');
 assert(adviceUi.el('cmdView').children.length > 10 && adviceUi.el('cmdView').children.some(line => line.className === 'c-note'),'manual PowerShell commands are highlighted');
 adviceUi.results([row({status:'patched'})]); await adviceUi.poll();
 assert.equal(adviceUi.el('vulnAlert').attrs.hidden,'','no red alert when nothing is vulnerable');
 // ---- catalog-driven alert (problem, severity and solution come from vulndb.json through the API).
 const vuln=(over={}) => ({id:'CVE-2026-114938',alias:'Java4Shell',severity:'high',title:both('CVE title','CVE Titel'),problem:both('{n} runtime(s) are affected: {list}.','{n} Runtime(s) betroffen: {list}.'),solution:both('update Java now','Java jetzt aktualisieren'),actions:['update-runtime','mitigate','restore-backup'],...over});
 const finding=(over={}) => ({id:'CVE-2026-114938',severity:'high',status:'vulnerable',...over});
 const catUi=boot(); await tick();
 catUi.vulns([vuln(),vuln({id:'CVE-2027-0001',alias:'',severity:'medium',title:both('Second flaw','Zweite Luecke'),problem:both('{n} affected','{n} betroffen'),solution:both('apply patch B','Patch B einspielen'),actions:['update-runtime']})]);
 catUi.results([row({findings:[finding(),finding({id:'CVE-2027-0001',severity:'medium'})]})]); await catUi.poll();
 const blocks=catUi.el('vulnList').children;
 assert.equal(blocks.length,2,'one alert block per affected vulnerability');
 assert(blocks[0].children[0].children[1].textContent === 'CVE title' && blocks[0].children[0].children[0].dataset.sev === 'high' && blocks[1].children[0].children[0].dataset.sev === 'medium','severity badge and title come from the catalog');
 assert(blocks[0].children[1].textContent.includes('1 runtime(s) are affected') && blocks[0].children[2].children[1].textContent.includes('update Java now') && blocks[1].children[2].children[1].textContent.includes('apply patch B'),'problem and solution come from the catalog');
 assert.equal(catUi.el('vulnRecList').children.length,2,'solutions repeated on the action step');
 changeLocale(catUi,'de'); assert(catUi.el('vulnList').children[0].children[1].textContent.startsWith('1 Runtime(s) betroffen') && catUi.el('vulnList').children[0].children[0].children[0].textContent === 'Hoch'); changeLocale(catUi,'en');
 catUi.results([row({status:'patched',findings:[finding({status:'patched'})]})]); await catUi.poll();
 assert.equal(catUi.el('vulnAlert').attrs.hidden,'','a fixed runtime shows no alert');
 for (const bad of [[vuln({severity:'critical'})],[vuln({extra:1})],[vuln({problem:{en:'x'}})],[vuln({id:'a b'})],Array.from({length:33},(_,n) => vuln({id:'CVE-2027-'+String(1000+n)})),'nope']) { catUi.vulns(bad); await catUi.poll(); assert(catUi.el('error').textContent.includes('invalid response'),'invalid catalog info rejected'); }
 catUi.vulns([vuln()]); catUi.results([row({findings:[finding({severity:'urgent'})]})]); await catUi.poll(); assert(catUi.el('error').textContent.includes('invalid response'),'invalid finding rejected');
 catUi.results([row()]); catUi.security({verifiedOn:'2026-11-23',advisories:[{id:'new_advisory',title:both('New advisory','Neuer Hinweis'),url:'https://example.org/advisory/1'}]}); await catUi.poll(); assert.equal(catUi.el('error').textContent,'','a catalog advisory from any https host is shown');
 catUi.security({verifiedOn:'2026-11-23',advisories:[{id:'bad',title:both('Bad','Schlecht'),url:'http://example.org/advisory/1'}]}); await catUi.poll(); assert(catUi.el('error').textContent.includes('invalid response'),'plain http advisory rejected'); // ---- "without this tool": the same steps by hand, for the selected runtime
 const flat = el => el.children.map(r => r.children.length ? r.children.map(piece => piece.textContent).join('') : r.textContent).join('\n');
 const mit = () => ({variable:'JAVA_TOOL_OPTIONS',option:'-XX:-UseBASE64Intrinsics',verifyArgs:['-XX:+PrintFlagsFinal','-version']});
 const byHand=boot(); await tick();
 byHand.vulns([vuln({mitigation:mit()})]);
 byHand.results([row({vendor:'Eclipse Temurin',version:'17.0.2+8',architecture:'x64',runtimeRoot:'C:\\ELO\\java',path:'C:\\ELO\\java\\bin\\java.exe',findings:[finding()]})]); await byHand.poll();
 assert.equal(byHand.el('behindBox').attrs.hidden,undefined,'the by-hand steps are shown on the action step');
 const upd = flat(byHand.el('behindUpdate'));
 assert(upd.includes("$runtime = 'C:\\ELO\\java'") && upd.includes('Compress-Archive -LiteralPath $runtime') && upd.includes('api.adoptium.net/v3/assets/latest/17/hotspot?architecture=x64&image_type=$type') && upd.includes('Get-FileHash') && upd.includes('Stop-Service') && upd.includes('Rename-Item') && upd.includes('.old-$stamp'),'update steps use the real runtime path, vendor API, backup, hash check, service stop and rename');
 assert(byHand.el('behindUpdate').children.some(line => line.className === 'c-note') && /^# 1\)/.test(byHand.el('behindUpdate').children.find(line => line.className === 'c-note' && /1\)/.test(line.textContent)).textContent),'steps are numbered comments');
 const mt = flat(byHand.el('behindMitigate'));
 assert.equal(byHand.el('behindMitigateBox').attrs.hidden,undefined);
 assert(mt.includes("SetEnvironmentVariable('JAVA_TOOL_OPTIONS', (($old + ' -XX:-UseBASE64Intrinsics').Trim()), 'Machine')") && mt.includes("& 'C:\\ELO\\java\\bin\\java.exe' -XX:+PrintFlagsFinal -version | Select-String 'UseBASE64Intrinsics'") && mt.includes('Restart-Service'),'mitigation steps come from the catalog option and verify arguments');
 byHand.results([row({vendor:'Azul Zulu',version:'21.0.1+12-LTS',architecture:'arm64',runtimeRoot:"C:\\O'Brien\\java",path:"C:\\O'Brien\\java\\bin\\java.exe",findings:[finding()]})]); await byHand.poll();
 const zulu = flat(byHand.el('behindUpdate'));
 assert(zulu.includes('api.azul.com/metadata/v1/zulu/packages/?java_version=21&os=windows&arch=arm&archive_type=zip') && zulu.includes("$runtime = 'C:\\O''Brien\\java'") && zulu.includes('package_uuid'),'Zulu uses the Azul API and a quote in a path cannot break out of the PowerShell string');
 changeLocale(byHand,'de'); assert(flat(byHand.el('behindUpdate')).includes('Nichts wird gelöscht') && !flat(byHand.el('behindUpdate')).includes('Nothing here is deleted')); changeLocale(byHand,'en');
 byHand.vulns([vuln()]); await byHand.poll();
 assert.equal(byHand.el('behindMitigateBox').attrs.hidden,'','no mitigation block when the catalog has no mitigation action');
 for (const bad of [mit(), {...mit(),variable:'PATH'}, {...mit(),option:'-javaagent:x.jar'}, {...mit(),verifyArgs:['C:\\evil.exe']}, {...mit(),extra:1}]) { byHand.vulns([vuln({mitigation:bad})]); await byHand.poll(); if (bad === undefined || JSON.stringify(bad) === JSON.stringify(mit())) assert.equal(byHand.el('error').textContent,''); else assert(byHand.el('error').textContent.includes('invalid response'),'invalid mitigation info rejected: '+JSON.stringify(bad)); } // ---- optional ELO Community + AI panel (opened from the Settings button)
 const cs = (over={}) => ({helper:true,node:true,playwright:true,chrome:true,secrets:{communityUser:true,communityPassword:true,openaiKey:true,anthropicKey:false},ai:{provider:'openai',model:'gpt-x',baseUrl:'https://api.openai.com/v1'},...over});
 const idleJob = () => ({state:'idle',kind:'',log:[],drafts:[],articles:[],runId:'',outDir:''});
 const art = (over={}) => ({index:0,url:'https://community.elo.com/community/x/#/post/(A)',title:'Java4Shell (CVE-2026-114938)',date:'2026-11-18',status:'drafted',error:'',severity:'high',severityReason:'Remote code execution',summary:{en:'English summary',de:'Deutsche Zusammenfassung',es:'Resumen en espanol'},javaRelated:true,scriptWorthwhile:true,scriptReason:'A version check detects it',solutions:[{kind:'update',summary:'Update Java'},{kind:'none',summary:''}],draftId:'CVE-2026-1',issues:1,...over});
 const draftItem = (over={}) => ({id:'CVE-2026-1',severity:'high',title:'Draft title',solutionReported:true,simulation:true,issues:1,detects:true,...over});
 const doneJob = (over={}) => ({state:'completed',kind:'run',log:['Fetched 2 article(s)','Drafted 1 entry'],drafts:[draftItem()],articles:[art(),art({index:1,url:'',title:'Jackson Databind',status:'drafted',severity:'medium',summary:null,scriptWorthwhile:false,scriptReason:'Needs a vendor hotfix',solutions:[],draftId:'',issues:0}),art({index:2,status:'error',error:'ai_http_401: the AI rejected the API key',severity:'',summary:null,severityReason:'',draftId:'',solutions:[]})],runId:'20261125120227',outDir:'C:\\ProgramData\\ELO-Patch-Tools\\quarantine\\drafts\\20261125120227',...over});
 const calls = []; let status = cs(), job = idleJob(), polls = 0, models = {models:['gpt-5','gpt-6-sol','o3'],current:'gpt-x'}, access = {ok:true,articlesOnPage:27}, accessFail = false;
 const backend = (path, body) => {
   calls.push({path,body});
   if (path === 'community/status') return status;
   if (path === 'community/job') { if (job.state === 'running' && ++polls > 2) job = doneJob({kind:job.kind}); return job; }
   if (path === 'community/models') return models;
   if (path === 'community/access') return accessFail ? {__status:502,body:{error:'community_failed',warnings:[both('The ELO Community rejected the user name or password.','Die ELO Community hat Benutzername oder Passwort abgelehnt.')]}} : access;
   if (path === 'community/setup') { job = {...idleJob(),state:'running',kind:'setup'}; polls = 99; return {ok:true}; }
   if (path === 'community/run') { job = {...idleJob(),state:'running',kind:'run',log:['starting']}; polls = 0; return {ok:true}; }
   if (path === 'community/refine') { job = {...job,state:'running',kind:'refine',log:['refining']}; polls = 0; return {ok:true}; }
   if (path === 'community/validate') return {valid:true,error:'',entries:[{id:'CVE-2026-1',status:'draft',passed:true,detected:'PotentiallyVulnerable',reason:''}]};
   if (path === 'community/cancel') { job = {...idleJob(),state:'cancelled',kind:'run'}; return {ok:true}; }
   throw Error('unexpected '+path);
 };
 assert(/<section class="panel community" id="communityBox"[^>]*\bhidden\b/.test(html) && /<button id="settingsBtn"/.test(html) && html.indexOf('id="communityBox"') < html.indexOf('id="step1"'),'a Settings button in the header opens the community panel, which sits above every step and is hidden by default');
 for (const key of ['cUser','cPass','cTest','aiProvider','aiKey','aiBase','aiModel','aiModelsBox','aiLoad','cSince','cMax','cConsent','communityRun','communityArticles','communityValidate']) assert(html.includes('id="'+key+'"'),'panel has '+key);
 assert(/id="cPass" type="password"/.test(html) && /id="aiKey" class="masked" type="text"/.test(html) && /autocomplete="off"[^>]*data-lpignore/.test(html.slice(html.indexOf('id="aiKey"'))),'the API key is a masked text field that password managers do not auto-fill');
 assert(/<details id="aiModelsBox"[^>]*><summary id="aiModelSummary">/.test(html) && /<select id="aiModel" size="8"/.test(html),'the models are a collapsible list box');
 assert(html.includes('data-i18n="communityNeed1"') && html.includes('data-i18n="communityNeed3"'),'the panel states the credentials and the extra software up front');
 const openSettings = async ui => { if (ui.el('settingsBtn').attrs['aria-expanded'] === 'true') await ui.el('settingsBtn').onclick(); await ui.el('settingsBtn').onclick(); await tick(); await tick(); await tick(); };
 const cm = boot(); await tick(); cm.community(backend);
 await openSettings(cm);
 assert.equal(cm.el('communityBox').attrs.hidden,undefined,'the Settings button shows the panel'); assert.equal(cm.el('settingsBtn').attrs['aria-expanded'],'true');
 assert.equal(calls.filter(c => c.path === 'community/status').length,1,'status is loaded when the panel opens');
 const auto = calls.filter(c => c.path === 'community/models');
 assert.equal(auto.length,1,'a saved key loads the model list automatically'); assert.deepEqual(auto[0].body,{provider:'openai',baseUrl:'https://api.openai.com/v1'},'without sending any typed secret');
 assert.deepEqual(cm.el('aiModel').children.map(o => o.value),['gpt-5','gpt-6-sol','o3']); assert.equal(cm.el('aiModel').value,'gpt-5');
 assert(cm.el('aiModelNote').textContent.includes('3 models') && cm.el('aiModelNote').textContent.includes('not offered by this account'),'the page says when the configured model does not exist');
 assert(cm.el('aiModelSummary').textContent.startsWith('gpt-5') && cm.el('aiModelSummary').textContent.includes('(3)'),'the collapsed list shows the selected model');
 assert(cm.el('communityStatus').textContent.includes('Ready') && cm.el('communityStatus').textContent.includes('OPENAI_API_KEY') && !cm.el('communityStatus').textContent.includes('sk-'),'status shows readiness and which secrets exist (names only)');
 cm.el('aiModel').value = 'gpt-6-sol'; cm.el('aiModel').onchange(); assert(cm.el('aiModelSummary').textContent.startsWith('gpt-6-sol')); assert.equal(cm.el('aiModelsBox').open,false,'choosing a model folds the list');
 // test the ELO Community access
 assert.equal(cm.el('cTest').disabled,true,'testing the access needs the consent checkbox');
 await cm.el('cTest').onclick(); await tick(); assert(cm.el('communityError').textContent.includes('consent box')); assert.equal(calls.filter(c => c.path === 'community/access').length,0);
 cm.el('cConsent').checked = true; cm.el('cConsent').onchange(); cm.el('cUser').value = 'me@example.org'; cm.el('cPass').value = 'pw-typed-secret';
 await cm.el('cTest').onclick(); await tick(); await tick();
 assert.deepEqual(calls.find(c => c.path === 'community/access').body,{consent:'yes',user:'me@example.org',password:'pw-typed-secret'},'the access test sends the consent and the typed credentials');
 assert(cm.el('cTestResult').textContent.includes('Signed in') && cm.el('cTestResult').textContent.includes('27'),'the result shows the sign-in and the number of visible articles');
 accessFail = true; await cm.el('cTest').onclick(); await tick(); await tick();
 assert(cm.el('communityError').textContent.includes('rejected the user name or password') && cm.el('cTestResult').textContent === '' && cm.el('error').textContent === '','a failed sign-in is explained inside the panel'); accessFail = false;
 // run + articles
 cm.el('cSince').value = '90d'; cm.el('cMax').value = '7'; cm.el('cPass').value = 'pw-typed-secret'; cm.el('aiKey').value = 'sk-typed-secret';
 polls = 0; await cm.el('communityRun').onclick(); await tick(); await tick(); await tick();
 const run = calls.find(c => c.path === 'community/run');
 assert.deepEqual(run.body,{consent:'yes',provider:'openai',model:'gpt-6-sol',since:'90d',max:'7',user:'me@example.org',password:'pw-typed-secret',apiKey:'sk-typed-secret',baseUrl:'https://api.openai.com/v1'},'the run sends flat strings');
 assert.equal(cm.el('cPass').value,''); assert.equal(cm.el('aiKey').value,'','secrets are cleared after sending');
 assert(cm.el('communityLog').textContent.includes('Finished.'));
 const cards = cm.el('communityArticles').children;
 assert.equal(cards.length,3,'one card per article found'); assert.equal(cm.el('communityArticlesTitle').attrs.hidden,undefined);
 const c0 = cards[0], head0 = c0.children[0];
 assert(head0.children[0].dataset.sev === 'high' && head0.children[0].textContent === 'High' && head0.children[1].textContent === 'Java4Shell (CVE-2026-114938)' && head0.children[1].href.startsWith('https://community.elo.com/') && head0.children[1].rel === 'noopener noreferrer' && head0.children[2].textContent === '2026-11-18','the card shows the severity, the title as a safe link and the date');
 assert.equal(c0.children[1].textContent,'English summary','the AI summary is shown in the current language');
 const text0 = c0.children.map(x => x.textContent).join('\n');
 assert(text0.includes('Why this level: Remote code execution') && text0.includes('A script is worthwhile: yes - A version check detects it') && text0.includes('Solutions in the article: update (Update Java)') && text0.includes('Draft: CVE-2026-1') && text0.includes('simulation: yes') && text0.includes('detects: yes'),'rating reason, script verdict, solutions and the draft line');
 assert(cards[1].children.map(x => x.textContent).join('\n').includes('A script is worthwhile: no - Needs a vendor hotfix') && cards[1].children[0].children[1].href === undefined,'an article without a script says why; a missing link is not a link');
 assert(cards[2].children.map(x => x.textContent).join('\n').includes('Could not analyze: The AI rejected the API key (401)') && cards[2].children[0].children[0].textContent === 'error','an article the AI could not analyze shows a plain-language cause');
 changeLocale(cm,'de'); assert.equal(cm.el('communityArticles').children[0].children[1].textContent,'Deutsche Zusammenfassung','summaries follow the language'); changeLocale(cm,'en');
 // improve with a solution / research
 const refineBtn = c0.children.find(x => x.textContent === 'Improve with a solution or research');
 await refineBtn.onclick(); await tick();
 const box = cm.el('communityArticles').children[0].children.at(-1);
 assert(box.className === 'refine' && box.children[0].maxLength === 4000,'the refine form has a solution box');
 box.children[2].onclick(); await tick(); assert(cm.el('communityError').textContent.includes('Paste a solution text'),'refining needs a solution text or the research box');
 const live = cm.el('communityArticles').children[0].children.at(-1); live.children[0].value = 'Fix: update to 17.0.21.1+2'; live.children[0].oninput(); live.children[1].children[0].checked = true; live.children[1].children[0].onchange();
 cm.el('aiKey').value = 'sk-typed-secret'; polls = 0; await live.children[2].onclick(); await tick(); await tick(); await tick();
 const refine = calls.find(c => c.path === 'community/refine');
 assert.deepEqual(refine.body,{consent:'yes',provider:'openai',model:'gpt-6-sol',run:'20261125120227',article:'0',hint:'Fix: update to 17.0.21.1+2',research:'yes',user:'me@example.org',apiKey:'sk-typed-secret',baseUrl:'https://api.openai.com/v1'},'refining sends the run, the article, the solution text and the research flag');
 // validate drafts
 assert.equal(cm.el('communityValidate').attrs.hidden,undefined,'drafts can be checked once a run finished');
 await cm.el('communityValidate').onclick(); await tick();
 assert.deepEqual(calls.at(-1),{path:'community/validate',body:{run:'20261125120227'}}); assert(cm.el('communityValidation').textContent.includes('CVE-2026-1 [draft]: simulation passed (PotentiallyVulnerable)'),'the app validates and simulates the draft');
 assert.doesNotMatch(JSON.stringify(calls.filter(c => !['community/run','community/models','community/refine','community/access'].includes(c.path))),/pw-typed-secret|sk-typed-secret/,'secrets travel only with the requests that need them');
 // no key available: no automatic model request
 status = cs({secrets:{communityUser:false,communityPassword:false,openaiKey:false,anthropicKey:false}}); const noKey = boot(); await tick(); const before = calls.length; noKey.community(backend); await openSettings(noKey);
 assert.equal(calls.slice(before).filter(c => c.path === 'community/models').length,0,'without a key nothing is requested automatically'); status = cs();
 // invalid backend answers are rejected
 const bad = boot(); await tick();
 for (const wrong of [cs({extra:1}),cs({helper:'yes'}),cs({secrets:{communityUser:true}}),cs({ai:{provider:'evil',model:'m',baseUrl:''}})]) { bad.community((p) => p === 'community/status' ? wrong : idleJob()); await openSettings(bad); assert(bad.el('communityError').textContent.length > 0,'invalid status rejected: '+JSON.stringify(wrong).slice(0,60)); }
 for (const wrongJob of [doneJob({articles:[art({url:'https://evil.example/x'})]}),doneJob({articles:[art({severity:'extreme'})]}),doneJob({articles:[art({solutions:[{kind:'x',summary:''}]})]}),doneJob({articles:[art({summary:{en:'only'}})]}),doneJob({runId:'../x'}),doneJob({articles:[art({extra:1})]})]) {
   const badJob = boot(); await tick(); badJob.community((p) => p === 'community/status' ? cs({secrets:{communityUser:false,communityPassword:false,openaiKey:false,anthropicKey:false}}) : wrongJob); await openSettings(badJob);
   assert(badJob.el('communityError').textContent.length > 0 && badJob.el('communityArticles').children.length === 0,'an invalid job payload is rejected: '+JSON.stringify(wrongJob.articles[0] || wrongJob.runId).slice(0,70));
 }
 const fail = boot(); await tick(); fail.community((p) => { if (p === 'community/models') return {__status:502,body:{error:'community_failed',warnings:[both('The AI provider rejected the API key (HTTP 401).','Der KI-Anbieter hat den API-Schluessel abgelehnt (HTTP 401).')]}}; return p === 'community/status' ? cs() : idleJob(); });
 await openSettings(fail);
 assert(fail.el('communityError').textContent.includes('rejected the API key') && fail.el('error').textContent === '','a rejected key is explained inside the panel, not as a page error');
 changeLocale(fail,'de'); assert(fail.translated.find(el => el.dataset.i18n === 'communityRun').textContent === 'Neueste Sicherheitsartikel analysieren' && fail.translated.find(el => el.dataset.i18n === 'communityTest').textContent === 'ELO-Community-Zugang testen','German labels'); changeLocale(fail,'en');
 const noHelper = boot(); await tick(); noHelper.community((p) => p === 'community/status' ? cs({helper:false,node:false,playwright:false}) : idleJob()); await openSettings(noHelper);
 assert(noHelper.el('communityStatus').textContent.includes('tools/community was not found') && noHelper.el('communityRun').disabled === true && noHelper.el('communitySetup').attrs.hidden === '','without the helper the feature explains itself and the patch tool is unaffected'); // ---- Spanish (castellano) next to English and German
 assert(html.includes('<option value="es">Español</option>'),'the language selector offers Spanish');
 { const src = scripts[0][1], start = src.indexOf('const messages = {'), end = src.indexOf('const $ = id');
   const ctx = {}; vm.runInNewContext(src.slice(start,end)+';this.messages=messages;',ctx);
   const en = Object.keys(ctx.messages.en), de = Object.keys(ctx.messages.de), es = Object.keys(ctx.messages.es);
   assert.deepEqual(en.filter(k => !es.includes(k)),[],'every English message has a Spanish translation'); assert.deepEqual(es.filter(k => !en.includes(k)),[],'no stray Spanish keys'); assert.deepEqual(en.filter(k => !de.includes(k)),[]);
   assert.equal(ctx.messages.es.manual.length,ctx.messages.en.manual.length,'same number of manual steps');
   for (const k of en) if (typeof ctx.messages.en[k] === 'string') { const placeholders = s => (s.match(/\{[a-z]+\}/g) || []).sort().join(','); assert.equal(placeholders(ctx.messages.es[k]),placeholders(ctx.messages.en[k]),'same placeholders in '+k); }
 }
 const spUi = boot(); await tick(); spUi.community(backend);
 spUi.el('language').value = 'es'; spUi.el('language').onchange();
 assert.equal(spUi.translated.find(el => el.dataset.i18n === 'step1').textContent,'Escaneo'); assert.equal(spUi.translated.find(el => el.dataset.i18n === 'communityRun').textContent,'Analizar los últimos artículos de seguridad'); assert.equal(spUi.translated.find(el => el.dataset.i18n === 'settings').textContent,'Ajustes');
 assert.equal(spUi.el('status').textContent,'Escaneo completado','state labels are translated');
 job = doneJob(); status = cs(); await openSettings(spUi);
 assert.equal(spUi.el('communityArticles').children[0].children[1].textContent,'Resumen en espanol','the AI summary is shown in Spanish');
 assert.equal(spUi.el('communityArticles').children[1].children.map(x => x.textContent).join(' ').includes('Vale la pena un script: no'),true,'an article without a Spanish text still renders (fallback), labels are Spanish');
 spUi.results([row({vendor:'Eclipse Temurin',version:'17.0.2+8',architecture:'x64',runtimeRoot:'C:\\ELO\\java',path:'C:\\ELO\\java\\bin\\java.exe',findings:[finding()]})]); spUi.vulns([vuln()]); await spUi.poll();
 assert(flat(spUi.el('behindUpdate')).includes('Ejecuta en una PowerShell de ADMINISTRADOR') && flat(spUi.el('behindUpdate')).includes('Haz una copia del runtime') && !flat(spUi.el('behindUpdate')).includes('Nothing here is deleted'),'the by-hand command comments are in Spanish');
 assert(spUi.el('vulnList').children.length === 1 && spUi.el('vulnList').children[0].children[0].children[1].textContent === 'CVE title','catalog/server texts without a Spanish version fall back to English');
 spUi.preview({previewId:'preview_1',summary:{en:'English summary',de:'Deutsche Zusammenfassung',es:'Resumen en español'},warnings:[both('Check compatibility','Kompatibilität prüfen'),{en:'Only EN',de:'Nur DE',es:'Solo ES'}]});
 spUi.el('language').value = 'en'; spUi.el('language').onchange(); assert.equal(spUi.translated.find(el => el.dataset.i18n === 'step1').textContent,'Scan'); // ---- the temporary mitigation is always available for a scanned runtime
 const mitUi = boot(); await tick();
 mitUi.results([row({status:'inconclusive',vendor:'Azul Zulu',version:'21.0.1+12-LTS'})]); await mitUi.poll();
 assert.equal(mitUi.el('mitigate').disabled,false,'the temporary mitigation stays available for a runtime that is not classified vulnerable');
 assert.equal(mitUi.el('mitigateHint').attrs.hidden,undefined,'and the page explains what that means'); assert.equal(mitUi.el('update').disabled,false,'the update stays available');
 mitUi.results([row({status:'vulnerable'})]); await mitUi.poll();
 assert.equal(mitUi.el('mitigate').disabled,false); assert.equal(mitUi.el('mitigateHint').attrs.hidden,'');
 console.log('PASS: JVM evidence/export, exact advisory allowlist, bounded errors/warnings, admin/access denial, rollback/recovery lock, unavailable update, locales and token security');
})().catch(error => { console.error(error); process.exitCode=1; });
'@
$tests | & node - $htmlPath
if ($LASTEXITCODE -ne 0) { throw "UI tests failed (Node exit $LASTEXITCODE)" }
Write-Output 'PASS: dev/ui.tests.ps1'
