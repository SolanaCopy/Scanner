// Bredere batch: per contract ZOWEL Slither (statische flags) ALS de drain-detector (dynamisch bewijs).
require('dotenv').config();
const axios = require('axios');
const fs = require('fs');
const { runOnAnvilFork, runSlither } = require('./analyze-worker.js');
const { pickDrainCandidates, pickDepositCandidates, buildDrainScript, parseDrains } = require('./drain-detector.js');

const TOK = {
  USDT: '0x55d398326f99059fF775485246999027B3197955',
  USDC: '0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d',
  WBNB: '0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c',
  BUSD: '0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56',
};
// Hoogste-signaal Slither-detectoren (echte exploit-klassen)
const HOT = new Set(['reentrancy-eth', 'reentrancy-no-eth', 'arbitrary-send-eth', 'arbitrary-send-erc20', 'arbitrary-send-erc20-permit', 'suicidal', 'unprotected-upgrade', 'controlled-delegatecall', 'tx-origin']);
const KEY = process.env.BSCSCAN_API_KEY;
const addrs = JSON.parse(fs.readFileSync('./tmp_batch.json', 'utf8'));

(async () => {
  const flagged = [];
  let n = 0;
  for (const a of addrs) {
    n++;
    const rep = { address: a, drains: [], slither: [] };
    try {
      // Slither (statisch)
      const sl = await runSlither(a).catch(() => ({ success: false, findings: [] }));
      if (sl.success) rep.slither = (sl.findings || []).filter(f => HOT.has(f.check)).map(f => `${f.check}[${f.impact}]`);
      // Drain (dynamisch)
      const r = await axios.get(`https://api.etherscan.io/v2/api?chainid=56&module=contract&action=getabi&address=${a}&apikey=${KEY}`, { timeout: 15000 });
      if (r.data.status === '1' && r.data.result.startsWith('[')) {
        const abi = JSON.parse(r.data.result);
        const cands = pickDrainCandidates(abi, sl.findings || []);
        if (cands.length) {
          const out = await runOnAnvilFork(a, buildDrainScript(cands, pickDepositCandidates(abi), TOK));
          rep.drains = parseDrains(out);
        }
      }
    } catch (e) {}
    const interesting = rep.drains.length > 0 || rep.slither.length > 0;
    if (interesting) { flagged.push(rep); console.log(`${rep.drains.length ? '🔴' : '🟡'} ${a} | drains:${rep.drains.length} | slither:${rep.slither.join(',') || '-'}`); }
    else console.log(`🟢 ${n}/${addrs.length} ${a.slice(0, 12)} schoon`);
  }
  console.log(`\n=== KLAAR: ${addrs.length} contracten | ${flagged.length} met flag/drain ===`);
  const drained = flagged.filter(f => f.drains.length > 0);
  console.log(drained.length ? `🔴 ${drained.length} DRAINBAAR: ` + JSON.stringify(drained, null, 1) : '🟢 0 bewezen drainbaar');
  console.log(flagged.filter(f => f.slither.length).length + ' met Slither-flag (statisch verdacht, niet bewezen)');
  fs.writeFileSync('batch_v2_results.json', JSON.stringify(flagged, null, 1));
  process.exit(0);
})();
