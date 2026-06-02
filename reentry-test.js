// Positieve controle reentrancy: kwetsbare bank + generieke aanvaller op een fork.
const { runOnAnvilFork } = require('./analyze-worker.js');
const { parseDrains } = require('./drain-detector.js');
const fs = require('fs');

const BANK_BIN = '0x' + fs.readFileSync('./tmp/bank_bin.txt', 'utf8').trim();
const ATT_BIN = fs.readFileSync('./drain-detector.js', 'utf8').match(/REENTRY_BYTECODE = '(0x[0-9a-f]+)'/)[1];

const script = `
  const FS = require('fs'); const L = m => { try { FS.appendFileSync('C:/bsc-scanner/reentry_dbg.txt', m + '\\n'); } catch(e){} };
  const EOA = '0x1111111111111111111111111111111111111111';
  await fund(EOA); await setBalance(EOA, '1000');
  const signer = await impersonate(EOA);
  const bankF = new ethers.ContractFactory(['function deposit() payable','function withdraw()'], '${BANK_BIN}', signer);
  const bank = await bankF.deploy(); await bank.waitForDeployment();
  const BANK = await bank.getAddress();
  await provider.send('anvil_setBalance', [BANK, ethers.toBeHex(ethers.parseEther('10'))]); // geld van andere gebruikers
  const attF = new ethers.ContractFactory(['function go(address,bytes,bytes) payable'], '${ATT_BIN}', signer);
  const att = await attF.deploy(); await att.waitForDeployment();
  const ATT = await att.getAddress();
  await provider.send('anvil_setBalance', [ATT, ethers.toBeHex(ethers.parseEther('5'))]);
  const natB = await provider.getBalance(ATT);
  const depData = new ethers.Interface(['function deposit()']).encodeFunctionData('deposit', []);
  const wdData = new ethers.Interface(['function withdraw()']).encodeFunctionData('withdraw', []);
  const goC = new ethers.Contract(ATT, ['function go(address,bytes,bytes) payable'], signer);
  const value = ethers.parseEther('1');
  const tx = await goC.go(BANK, depData, wdData, { value, gasLimit: 8000000 });
  const rc = await tx.wait();
  const natA = await provider.getBalance(ATT);
  const eoaA = await provider.getBalance(EOA);
  const bankAfter = await provider.getBalance(BANK);
  let depth = 'n/a';
  try { depth = (await new ethers.Contract(ATT, ['function depth() view returns (uint256)'], provider).depth()).toString(); } catch(e) { depth = 'read-fail:' + e.message.slice(0,40); }
  const cb = await provider.getBalance('0x0000000000000000000000000000000000000000');
  let balAtt = 'n/a';
  try { balAtt = ethers.formatEther(await new ethers.Contract(BANK, ['function bal(address) view returns (uint256)'], provider).bal(ATT)); } catch(e) { balAtt = 'fail'; }
  L('txStatus=' + rc.status + ' depth=' + depth + ' gasUsed=' + rc.gasUsed + ' natA=' + ethers.formatEther(natA) + ' bankNa=' + ethers.formatEther(bankAfter) + ' bank.bal[ATT]=' + balAtt + ' zeroAddr=' + ethers.formatEther(cb) + ' EOA=' + ethers.formatEther(eoaA));
  console.log('[RAW] natB=' + ethers.formatEther(natB) + ' natA=' + ethers.formatEther(natA) + ' eoaNa=' + ethers.formatEther(eoaA) + ' ATT=' + ATT);
  console.log('[RESULT] bankNa=' + ethers.formatEther(bankAfter) + ' attackerWinst=' + ethers.formatEther(natA - natB - value));
  if (natA > natB + value + (10n ** 16n)) console.log('[REENTRANCY-DRAIN] withdraw | NATIVE | ' + ethers.formatEther(natA - natB - value));
  else console.log('[GEEN-DRAIN]');
`;

(async () => {
  const out = await runOnAnvilFork('0x0000000000000000000000000000000000000000', script);
  const lines = out.split('\n').filter(l => l.includes('[RESULT]') || l.includes('REENTRANCY-DRAIN') || l.includes('GEEN-DRAIN') || l.includes('[ANVIL]'));
  console.log(lines.join('\n'));
  const d = parseDrains(out);
  console.log(d.length > 0 ? '\n✅ REENTRANCY POSITIEVE CONTROLE GESLAAGD' : '\n❌ niet gedetecteerd');
  process.exit(0);
})().catch(e => { console.log('FOUT', e.message); process.exit(1); });
