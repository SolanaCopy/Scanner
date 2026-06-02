// Positieve controle Fase 3: dubbele-withdraw accounting-bug.
const { runOnAnvilFork } = require('./analyze-worker.js');
const { buildDrainScript, parseDrains } = require('./drain-detector.js');
const fs = require('fs');
const RT = fs.readFileSync('./tmp/doublebank_rt.txt', 'utf8').trim();
const FIXED = '0x00000000000000000000000000000000dead0003';
const TOK = { USDT: '0x55d398326f99059fF775485246999027B3197955', USDC: '0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d', WBNB: '0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c' };

(async () => {
  const drainCands = [{ name: 'withdraw', types: [], sig: 'withdraw()' }];
  const depCands = [{ name: 'deposit', types: [], sig: 'deposit()' }];
  const setup = `await provider.send('anvil_setCode', ['${FIXED}', '${RT}']); await provider.send('anvil_setBalance', ['${FIXED}', ethers.toBeHex(ethers.parseEther('10'))]);\n`;
  const out = await runOnAnvilFork(FIXED, setup + buildDrainScript(drainCands, depCands, TOK));
  const d = parseDrains(out);
  console.log(out.split('\n').filter(l => /DRAIN|DONE/.test(l)).join('\n'));
  console.log(d.some(x => x.fn.includes('dubbel')) ? '✅ FASE 3 (dubbele withdraw) GEDETECTEERD' : (d.length ? '✅ drain gezien: ' + JSON.stringify(d) : '❌ niet gedetecteerd'));
  process.exit(0);
})().catch(e => { console.log('FOUT', e.message); process.exit(1); });
