// Validatie van de GENERIEKE approval-detector: VulnApproval via setCode + buildApprovalDrainScript.
require('dotenv').config();
const axios = require('axios');
const fs = require('fs');
const { runOnAnvilFork, runSlither } = require('./analyze-worker.js');
const { pickApprovalCandidates, buildApprovalDrainScript, parseDrains } = require('./drain-detector.js');

const VULN_RT = fs.readFileSync('./tmp/vuln_runtime.txt', 'utf8').trim();
const FIXED = '0x00000000000000000000000000000000dead0002';
const KEY = process.env.BSCSCAN_API_KEY;

(async () => {
  // 1) POSITIEVE CONTROLE
  const cand = { name: 'pull', types: ['address', 'address', 'address', 'uint256'], sig: 'pull(address,address,address,uint256)' };
  const setup = `await provider.send('anvil_setCode', ['${FIXED}', '${VULN_RT}']);\n`;
  const out1 = await runOnAnvilFork(FIXED, setup + buildApprovalDrainScript([cand]));
  const d1 = parseDrains(out1);
  console.log('POSITIEVE CONTROLE:', d1.length ? '✅ APPROVAL-DRAIN gedetecteerd ' + JSON.stringify(d1) : '❌ niet gedetecteerd');
  console.log(out1.split('\n').filter(l => /APPROVAL/.test(l)).join('\n'));

  // 2) NEGATIEVE CONTROLE op een echt contract
  const addr = process.argv[2] || '0x664201579057f50D23820d20558f4b61bd80BDda';
  const r = await axios.get(`https://api.etherscan.io/v2/api?chainid=56&module=contract&action=getabi&address=${addr}&apikey=${KEY}`, { timeout: 15000 });
  if (r.data.status === '1' && r.data.result.startsWith('[')) {
    const abi = JSON.parse(r.data.result);
    const sl = await runSlither(addr).catch(() => ({ findings: [] }));
    const cands = pickApprovalCandidates(abi, sl.findings || []);
    console.log(`\nNEGATIEVE CONTROLE (${addr}): ${cands.length} approval-kandidaten:`, cands.map(c => c.name).join(', '));
    if (cands.length) {
      const out2 = await runOnAnvilFork(addr, buildApprovalDrainScript(cands));
      const d2 = parseDrains(out2);
      console.log(out2.split('\n').filter(l => /APPROVAL-DONE|APPROVAL-DRAIN/.test(l)).join('\n'));
      console.log(d2.length ? '⚠️ ' + d2.length + ' drains' : '✅ geen false-positive');
    }
  } else console.log('\nNEGATIEVE CONTROLE: contract niet verified');
  process.exit(0);
})().catch(e => { console.log('FOUT', e.message); process.exit(1); });
