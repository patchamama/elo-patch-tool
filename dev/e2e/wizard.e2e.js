// Opt-in browser E2E against the REAL server and a disposable runtime. Needs: Windows, administrator,
// Google Chrome, network, ~700 MB. Run:  ELO_E2E=1 node dev/e2e/wizard.e2e.js   (after npm install --prefix dev/e2e)
// Flow: scan (with a manual folder) -> choose runtime -> update to the newest release -> report download ->
// restore from the backup ZIP -> start over. It never applies anything to C:\ELO or any service.
'use strict';
if (process.env.ELO_E2E !== '1') { console.log('SKIP: set ELO_E2E=1 to run the browser E2E'); process.exit(0); }
const { chromium } = require('playwright-core');
const fs = require('node:fs'), os = require('node:os'), path = require('node:path'), cp = require('node:child_process');
const assert = require('node:assert/strict');
const scratch = path.join(os.tmpdir(), 'elo-e2e-' + require('node:crypto').randomBytes(8).toString('hex'));
const urlFile = path.join(os.tmpdir(), 'elo-e2e-url-' + process.pid + '.txt');
const javaVersion = () => (cp.spawnSync(path.join(scratch, 'java', 'bin', 'java.exe'), ['-version'], { encoding: 'utf8' }).stderr || '').split('\n')[0];
let server;
(async () => {
  const prep = cp.spawnSync('powershell', ['-NoProfile', '-File', path.join(__dirname, 'prepare-runtime.ps1'), '-Root', scratch], { encoding: 'utf8' });
  assert.equal(prep.status, 0, 'prepare runtime: ' + prep.stderr);
  server = cp.spawn('powershell', ['-NoProfile', '-File', path.join(__dirname, 'start-server.ps1'), '-UrlFile', urlFile], { stdio: 'ignore' });
  for (let i = 0; i < 60 && !fs.existsSync(urlFile); i++) await new Promise(r => setTimeout(r, 500));
  const url = fs.readFileSync(urlFile, 'utf8').trim();
  const browser = await chromium.launch({ channel: 'chrome', headless: true });
  const ctx = await browser.newContext({ acceptDownloads: true, viewport: { width: 1100, height: 820 } });
  const p = await ctx.newPage(); const problems = [];
  p.on('console', m => { if (m.type() === 'error') problems.push('console: ' + m.text()); });
  p.on('pageerror', e => problems.push('pageerror: ' + e.message));
  const step = () => p.evaluate(() => [1, 2, 3, 4, 5].filter(n => !document.getElementById('step' + n).hasAttribute('hidden')).join(','));
  const waitStep = async (want, ms) => {
    const t0 = Date.now();
    for (;;) {
      if ((await step()) === want) return;
      const e = await p.locator('#error').innerText();
      if (e) throw new Error('error while waiting for step ' + want + ': ' + e.slice(0, 400));
      if (Date.now() - t0 > ms) throw new Error('timeout waiting for step ' + want);
      await p.waitForTimeout(400);
    }
  };
  await p.goto(url); await p.waitForTimeout(800);
  assert.equal(await step(), '1', 'starts on the scan step');
  await p.locator('summary', { hasText: 'Advanced' }).click(); await p.fill('#searchPath', scratch);
  await p.locator('#scan').click(); await waitStep('2', 180000);
  const cards = await p.locator('#cards .rt').allInnerTexts();
  const idx = cards.findIndex(c => c.includes(scratch)); assert(idx >= 0, 'scratch runtime listed');
  await p.locator('#cards .rt').nth(idx).click(); await p.locator('#toStep3').click(); assert.equal(await step(), '3');
  await p.locator('#update').click(); assert(await p.locator('#busy').isVisible(), 'busy indicator while preparing the preview');
  await waitStep('4', 180000);
  const preview = await p.locator('#preview').innerText();
  assert(preview.includes('Eclipse Adoptium JDK 17') && !preview.includes('STOPPED'), 'preview for the scratch Temurin 17, no service to stop');
  assert.equal(await p.locator('#apply').isDisabled(), true, 'apply needs the confirmation');
  await p.locator('#confirm').check(); await p.locator('#apply').click(); await waitStep('5', 900000);
  assert(!/"17\.0\.2"/.test(javaVersion()), 'java -version is the new release: ' + javaVersion());
  assert((await p.locator('#finalNotice').innerText()).length > 0, 'outcome message');
  const [download] = await Promise.all([p.waitForEvent('download'), p.locator('#exportTechnical').click()]);
  const html = fs.readFileSync(await download.path(), 'utf8');
  assert(html.includes('Expand-Archive') && html.includes('.backup-'), 'technical report carries the restore commands');
  await p.selectOption('#language', 'de');
  assert((await p.locator('#finalNotice').innerText()).includes('aktualisiert'), 'German UI');
  await p.selectOption('#language', 'en');
  await p.locator('#restore').click(); await waitStep('4', 180000);
  await p.locator('#confirm').check(); await p.locator('#apply').click(); await waitStep('5', 600000);
  assert(javaVersion().includes('"17.0.2"'), 'previous runtime restored: ' + javaVersion());
  await p.locator('#startOver').click(); assert.equal(await step(), '1');
  assert.deepEqual(problems, [], 'no console errors');
  await browser.close();
  console.log('E2E OK');
})().then(() => cleanup(0), e => { console.error('E2E FAILED:', e.message); cleanup(1); });
function cleanup(code) {
  try { if (server) server.kill(); } catch (_) {}
  try { fs.rmSync(urlFile, { force: true }); } catch (_) {}
  // Only this test's own scratch directory (random elo-e2e-<hex> under the temp folder).
  if (path.dirname(scratch) === os.tmpdir() && /^elo-e2e-[0-9a-f]{16}$/.test(path.basename(scratch))) {
    try { fs.rmSync(scratch, { recursive: true, force: true }); } catch (_) {}
  }
  process.exit(code);
}
