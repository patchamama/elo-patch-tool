#!/usr/bin/env node
'use strict';
const { main } = require('../src/cli');
main(process.argv.slice(2)).then(code => { process.exitCode = code; }).catch(error => {
  // Never print stack traces or request details: they can contain tokens or article text.
  process.stderr.write('elo-community: ' + String(error && error.message || error).slice(0, 400) + '\n');
  process.exitCode = 1;
});
