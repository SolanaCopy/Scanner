// Backtest-harness: draait de ECHTE Pashov-audit op bekende gehackte BSC-contracten (DeFiHackLabs)
// en meet of de bekende kwetsbaarheid (HIGH/CRITICAL) gevonden wordt.
// Gebruik: node backtest.js
require('dotenv').config();
const fs = require('fs');
const { runPashovAudit, runSecurityCheck } = require('./analyze-worker.js');

const CONCURRENCY = 3;

async function testOne(o) {
  const res = { name: o.name, vuln: o.vuln, lost: o.lost, cname: o.cname };
  try {
    const sec = await runSecurityCheck(o.vuln);
    if (!sec || !sec.sourceCode || sec.sourceCode.length < 100) {
      res.status = 'NO_SOURCE';
      return res;
    }
    const pashov = await runPashovAudit(o.vuln, sec.sourceCode, 100000);
    if (!pashov) { res.status = 'PASHOV_NULL'; return res; }
    const findings = pashov.findings || [];
    const highs = findings.filter(f => f.severity === 'HIGH' || f.severity === 'CRITICAL');
    res.risk = pashov.risk_level;
    res.totalFindings = findings.length;
    res.highCount = highs.length;
    res.status = highs.length > 0 ? 'CAUGHT' : 'MISS';
    res.funcs = highs.map(f => `${f.function || '?'} [${f.severity}]`);
    res.descs = highs.slice(0, 3).map(f => (f.description || '').substring(0, 120));
  } catch (e) {
    res.status = 'ERROR';
    res.err = (e.message || '').substring(0, 150);
  }
  return res;
}

(async () => {
  const incidents = JSON.parse(fs.readFileSync('backtest_incidents.json')).filter(o => o.verified);
  console.log(`\n[BACKTEST] ${incidents.length} verified gehackte contracten\n`);
  const results = [];
  for (let i = 0; i < incidents.length; i += CONCURRENCY) {
    const batch = incidents.slice(i, i + CONCURRENCY);
    const r = await Promise.all(batch.map(testOne));
    for (const x of r) {
      results.push(x);
      const icon = x.status === 'CAUGHT' ? '✅ CAUGHT' : x.status === 'MISS' ? '❌ MISS  ' : '⚠️ ' + x.status;
      console.log(`${icon} | ${(x.cname || x.name).padEnd(22)} | risk=${x.risk || '-'} high=${x.highCount || 0} | ${x.lost}`);
      if (x.funcs && x.funcs.length) console.log(`         functies: ${x.funcs.join(', ')}`);
    }
    fs.writeFileSync('backtest_results.json', JSON.stringify(results, null, 1));
  }
  const caught = results.filter(r => r.status === 'CAUGHT').length;
  const miss = results.filter(r => r.status === 'MISS').length;
  const err = results.filter(r => !['CAUGHT', 'MISS'].includes(r.status)).length;
  console.log(`\n=== RECALL: ${caught}/${results.length} CAUGHT | ${miss} MISS | ${err} error/no-source ===`);
  console.log(`=== Detectie-rate (van bruikbare): ${caught}/${caught + miss} = ${Math.round(caught / (caught + miss) * 100)}% ===`);
  process.exit(0);
})();
