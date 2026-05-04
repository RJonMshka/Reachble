#!/usr/bin/env node
import('../dist/cli.js').then(({ program }) => program.parse()).catch(err => { console.error(err); process.exit(1) })
