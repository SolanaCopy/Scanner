// Draait de drain-detector op een batch echte high-balance contracten — zoekt een levend kwetsbaar contract.
require('dotenv').config();
const axios = require('axios');
const fs = require('fs');
const { runOnAnvilFork } = require('./analyze-worker.js');
const { pickDrainCandidates, pickDepositCandidates, buildDrainScript, parseDrains } = require('./drain-detector.js');

const TOK = {
  USDT: '0x55d398326f99059fF775485246999027B3197955',
  USDC: '0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d',
  WBNB: '0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c',
  BUSD: '0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56',
};
const KEY = process.env.BSCSCAN_API_KEY;
const addrs = JSON.parse(fs.readFileSync('./tmp_batch.json', 'utf8'));

(async () => {
  let tested = 0, unverified = 0, nocand = 0, safe = 0;
  const hits = [];
  for (const a of addrs) {
    try {
      const r = await axios.get(`https://api.etherscan.io/v2/api?chainid=56&module=contract&action=getabi&address=${a}&apikey=${KEY}`, { timeout: 15000 });
      if (r.data.status !== '1' || !r.data.result.startsWith('[')) { unverified++; continue; }
      const abi = JSON.parse(r.data.result);
      const cands = pickDrainCandidates(abi, []);
      if (!cands.length) { nocand++; continue; }
      tested++;
      const out = await runOnAnvilFork(a, buildDrainScript(cands, pickDepositCandidates(abi), TOK));
      const drains = parseDrains(out);
      if (drains.length) {
        hits.push({ address: a, drains });
        console.log(`🔴 HIT ${a} -> ${JSON.stringify(drains)}`);
      } else {
        safe++;
        console.log(`🟢 ${a.slice(0, 14)} -> ${cands.length} functies, veilig`);
      }
    } catch (e) { console.log(`• ${a.slice(0, 14)} fout: ${(e.message || '').slice(0, 50)}`); }
  }
  console.log(`\n=== KLAAR: ${tested} getest | ${safe} veilig | ${unverified} unverified | ${nocand} geen kandidaten ===`);
  console.log(hits.length ? `🔴🔴 ${hits.length} KWETSBARE CONTRACTEN GEVONDEN:\n` + JSON.stringify(hits, null, 1) : '🟢 geen drainbaar contract in deze batch');
  fs.writeFileSync('batch_drain_results.json', JSON.stringify(hits, null, 1));
  process.exit(0);
})();
