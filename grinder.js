// Backlog-grinder: draait de VOLLEDIGE detector-suite over bekende gefinancierde contracten.
// Doel: één kwetsbaar contract vinden (volume + geduld, geen snelheid). Voortgang persistent.
require('dotenv').config();
const axios = require('axios');
const fs = require('fs');
const { runOnAnvilFork } = require('./analyze-worker.js');
const { pickDrainCandidates, pickDepositCandidates, pickApprovalCandidates, buildDrainScript, buildApprovalDrainScript, parseDrains } = require('./drain-detector.js');

const TOK = {
  USDT: '0x55d398326f99059fF775485246999027B3197955', USDC: '0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d',
  WBNB: '0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c', BUSD: '0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56',
};
const KEY = process.env.BSCSCAN_API_KEY;
const DONE_FILE = './grinder_done.json';
const HITS_FILE = './grinder_hits.json';

// Pool opbouwen: high-value bronnen EERST, dan de volle checked_cache (minus DEX/infra-skips).
function buildPool() {
  const set = new Set();
  for (const f of ['alerted_addresses.json', 'scan_results.json']) {
    try {
      const d = JSON.parse(fs.readFileSync('./' + f, 'utf8'));
      const arr = Array.isArray(d) ? d : Object.values(d);
      for (const x of arr) { const a = (x.address || x); if (typeof a === 'string' && a.startsWith('0x')) set.add(a.toLowerCase()); }
    } catch (e) {}
  }
  // skip-lijst (DEX/infra) uitsluiten
  const skip = new Set();
  try { for (const l of fs.readFileSync('./skip_addresses.txt', 'utf8').split('\n')) { const m = l.match(/0x[a-f0-9]{40}/i); if (m) skip.add(m[0].toLowerCase()); } } catch (e) {}
  // volle checked_cache erbij
  try { for (const l of fs.readFileSync('./checked_cache.txt', 'utf8').split('\n')) { const m = l.match(/0x[a-f0-9]{40}/i); if (m) { const a = m[0].toLowerCase(); if (!skip.has(a)) set.add(a); } } } catch (e) {}
  return [...set];
}

// Balans-filter via Multicall3 (1 RPC-call): houdt het contract nu noemenswaardige waarde vast?
const { ethers } = require('ethers');
const RPC = new ethers.JsonRpcProvider('https://bsc-rpc.publicnode.com');
const MULTICALL = '0xcA11bde05977b3631167028862bE2a173976CA11';
const mc = new ethers.Contract(MULTICALL, ['function aggregate3((address target, bool allowFailure, bytes callData)[] calls) view returns ((bool success, bytes returnData)[])', 'function getEthBalance(address addr) view returns (uint256)'], RPC);
const ercI = new ethers.Interface(['function balanceOf(address) view returns (uint256)']);
const VALUE_TOKENS = [
  { a: TOK.USDT, th: 50n * 10n ** 18n }, { a: TOK.USDC, th: 50n * 10n ** 18n },
  { a: TOK.BUSD, th: 50n * 10n ** 18n }, { a: TOK.WBNB, th: 10n ** 17n },
];
async function hasValue(addr) {
  try {
    const calls = VALUE_TOKENS.map(t => ({ target: t.a, allowFailure: true, callData: ercI.encodeFunctionData('balanceOf', [addr]) }));
    calls.push({ target: MULTICALL, allowFailure: true, callData: mc.interface.encodeFunctionData('getEthBalance', [addr]) });
    const res = await mc.aggregate3(calls);
    for (let i = 0; i < VALUE_TOKENS.length; i++) { if (res[i].success && res[i].returnData !== '0x') { if (ethers.toBigInt(res[i].returnData) >= VALUE_TOKENS[i].th) return true; } }
    const nat = res[VALUE_TOKENS.length].success ? ethers.toBigInt(res[VALUE_TOKENS.length].returnData) : 0n;
    return nat >= 10n ** 17n; // > 0.1 BNB
  } catch (e) { return true; } // bij RPC-twijfel: toch testen
}

const sleep = ms => new Promise(r => setTimeout(r, ms));

// CONTINU: verwerk nieuwe contracten, slaap, herlees de pool (live scanner laat 'm groeien), herhaal.
(async () => {
  let done = {}; try { done = JSON.parse(fs.readFileSync(DONE_FILE, 'utf8')); } catch (e) {}
  let hits = []; try { hits = JSON.parse(fs.readFileSync(HITS_FILE, 'utf8')); } catch (e) {}
  console.log(`[GRINDER] start continu — ${Object.keys(done).length} al gedaan, ${hits.length} hits`);

  while (true) {
    const pool = buildPool().filter(a => !done[a]);
    if (pool.length === 0) { console.log('[GRINDER] geen nieuwe contracten — wacht 10min op verse aanvoer...'); await sleep(600000); continue; }
    console.log(`[GRINDER] ronde: ${pool.length} nieuwe contracten`);
    let n = 0;
    for (const a of pool) {
      n++;
      try {
        const r = await axios.get(`https://api.etherscan.io/v2/api?chainid=56&module=contract&action=getabi&address=${a}&apikey=${KEY}`, { timeout: 15000 });
        if (r.data.status !== '1' || !r.data.result.startsWith('[')) { done[a] = 'unverified'; continue; }
        if (!(await hasValue(a))) { done[a] = 'empty'; continue; }
        const abi = JSON.parse(r.data.result);
        const dc = pickDrainCandidates(abi, []);
        const ac = pickApprovalCandidates(abi, []);
        let drains = [];
        if (dc.length) drains = parseDrains(await runOnAnvilFork(a, buildDrainScript(dc, pickDepositCandidates(abi), TOK)));
        if (ac.length) { try { drains.push(...parseDrains(await runOnAnvilFork(a, buildApprovalDrainScript(ac)))); } catch (e) {} }
        done[a] = drains.length ? 'HIT' : 'safe';
        if (drains.length) { hits.push({ address: a, drains, ts: Date.now() }); fs.writeFileSync(HITS_FILE, JSON.stringify(hits, null, 1)); console.log(`\n🔴🔴 HIT ${a} -> ${JSON.stringify(drains)}\n`); }
        else console.log(`🟢 ${n}/${pool.length} ${a.slice(0, 12)} safe (${dc.length}d/${ac.length}a)`);
      } catch (e) { done[a] = 'err'; }
      if (n % 5 === 0) fs.writeFileSync(DONE_FILE, JSON.stringify(done));
      await sleep(400); // throttle: deel de BscScan-key met de live scanner
    }
    fs.writeFileSync(DONE_FILE, JSON.stringify(done));
    console.log(`[GRINDER] ronde klaar — ${Object.keys(done).length} totaal, ${hits.length} hits. Wacht 10min op verse aanvoer...`);
    await sleep(600000);
  }
})();
