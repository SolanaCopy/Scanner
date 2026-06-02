// Validatie van de drain-detector: positieve controle (kwetsbaar) + negatieve (veilig live contract).
require('dotenv').config();
const axios = require('axios');
const { runOnAnvilFork, runSlither } = require('./analyze-worker.js');
const { pickDrainCandidates, pickDepositCandidates, buildDrainScript, parseDrains } = require('./drain-detector.js');

const BSC_TOKENS = {
  USDT: '0x55d398326f99059fF775485246999027B3197955',
  USDC: '0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d',
  WBNB: '0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c',
};
const KEY = process.env.BSCSCAN_API_KEY;

// Minimale kwetsbare runtime: stuurt hele saldo naar msg.sender bij ELKE call. Geen compiler nodig.
const VULN_BYTECODE = '0x600d80600b6000396000f3600060006000600047335af100';

async function positiveControl() {
  console.log('\n=== POSITIEVE CONTROLE: kwetsbaar contract (iedereen kan ETH pakken) ===');
  const VULN = '0x00000000000000000000000000000000dead0001';
  const ATTACKER = '0x1111111111111111111111111111111111111111';
  // Runtime (zonder constructor): stuurt hele saldo naar caller bij elke call
  const VULN_RUNTIME = '0x33ff';
  const script = `
    const FS = require('fs');
    const L = m => { try { FS.appendFileSync('C:/bsc-scanner/anvil_dbg.txt', m + '\\n'); } catch(e){} };
    L('--- start script ---');
    const VULN = '${VULN}';
    const ATTACKER = '${ATTACKER}';
    await fund(ATTACKER);
    L('na fund');
    await provider.send('anvil_impersonateAccount', [ATTACKER]);
    await provider.send('anvil_setCode', [VULN, '${VULN_RUNTIME}']);
    await provider.send('anvil_setBalance', [VULN, ethers.toBeHex(ethers.parseEther('10'))]);
    const code = await provider.getCode(VULN);
    console.log('[SETUP] Vuln balans', ethers.formatEther(await provider.getBalance(VULN)), 'codeLen', (code.length-2)/2);

    const before = await provider.getBalance(ATTACKER);
    L('before=' + before.toString());
    try {
      const h = await provider.send('eth_sendTransaction', [{ from: ATTACKER, to: VULN, data: '0x12345678', gas: '0x30d40' }]);
      L('tx verstuurd=' + h);
    } catch(e) { L('SENDFAIL ' + (e.message||'').substring(0,200)); }
    await provider.send('evm_mine', []);
    const after = await provider.getBalance(ATTACKER);
    const vulnAfter = await provider.getBalance(VULN);
    L('vulnAfter=' + vulnAfter.toString() + ' attackerDelta=' + (after - before).toString());
    if (after > before) console.log('[DRAIN] pull NATIVE ' + (after - before).toString());
    else console.log('[NO-DRAIN] delta ' + (after - before).toString());
  `;
  const out = await runOnAnvilFork('0x0000000000000000000000000000000000000000', script);
  const drains = parseDrains(out);
  console.log(out.split('\n').filter(l => l.includes('[SETUP]') || l.includes('[DRAIN]') || l.includes('[NO-DRAIN]') || l.includes('[ANVIL]')).join('\n'));
  console.log(drains.length > 0 ? '✅ POSITIEVE CONTROLE GESLAAGD: drain gedetecteerd' : '❌ MISLUKT: geen drain gezien');
}

async function negativeControl(addr, name) {
  console.log(`\n=== NEGATIEVE CONTROLE: ${name} (${addr}) ===`);
  const r = await axios.get(`https://api.etherscan.io/v2/api?chainid=56&module=contract&action=getabi&address=${addr}&apikey=${KEY}`, { timeout: 15000 });
  if (r.data.status !== '1') { console.log('geen ABI'); return; }
  const abi = JSON.parse(r.data.result);
  const sl = await runSlither(addr).catch(() => ({ findings: [] }));
  const cands = pickDrainCandidates(abi, sl.findings || []);
  console.log(`${cands.length} kandidaat-functies:`, cands.map(c => c.name).slice(0, 10).join(', '));
  if (cands.length === 0) { console.log('geen kandidaten — niks te testen'); return; }
  const out = await runOnAnvilFork(addr, buildDrainScript(cands, pickDepositCandidates(abi), BSC_TOKENS));
  const drains = parseDrains(out);
  console.log(out.split('\n').filter(l => l.includes('DRAIN-TEST-DONE') || l.includes('[DRAIN]')).join('\n'));
  console.log(drains.length === 0 ? '✅ Geen false-positive (0 drains op veilig contract)' : '⚠️ ' + drains.length + ' drains: ' + JSON.stringify(drains));
}

(async () => {
  await positiveControl();
  // Negatieve: een paar recente verified contracten met balans (uit alerted lijst)
  await negativeControl(process.argv[2] || '0x8e76ebb1c71939982c9ac267c0eb25f4aa739535', 'live contract');
  process.exit(0);
})().catch(e => { console.log('TEST FOUT:', e.message); process.exit(1); });
