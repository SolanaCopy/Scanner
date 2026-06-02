// Positieve controle approval-drain: slachtoffer approved kwetsbaar contract, aanvaller steelt via transferFrom.
const { runOnAnvilFork } = require('./analyze-worker.js');
const fs = require('fs');

const bins = fs.readFileSync('./tmp/approval_bins.txt', 'utf8').split('\n');
function binOf(name) {
  const i = bins.findIndex(l => l.includes(':' + name + ' '));
  return '0x' + bins[i + 2].trim(); // header, "Binary:", bytecode
}
const TOKEN_BIN = binOf('TestToken');
const VULN_BIN = binOf('VulnApproval');

const script = `
  const FS = require('fs'); const L = m => { try { FS.appendFileSync('C:/bsc-scanner/approval_dbg.txt', m + '\\n'); } catch(e){} };
  const EOA = '0x1111111111111111111111111111111111111111';
  const VICTIM = '0x2222222222222222222222222222222222222222';
  const ATTACKER = '0x3333333333333333333333333333333333333333';
  for (const x of [EOA, VICTIM, ATTACKER]) { await fund(x); await provider.send('anvil_impersonateAccount', [x]); }
  const eoaS = await impersonate(EOA);
  const tokenF = new ethers.ContractFactory(['function mint(address,uint)','function balanceOf(address) view returns(uint)','function approve(address,uint) returns(bool)','function transferFrom(address,address,uint) returns(bool)'], '${TOKEN_BIN}', eoaS);
  const token = await tokenF.deploy(); await token.waitForDeployment(); const TOKEN = await token.getAddress();
  const vulnF = new ethers.ContractFactory(['function pull(address,address,address,uint)'], '${VULN_BIN}', eoaS);
  const vuln = await vulnF.deploy(); await vuln.waitForDeployment(); const VULN = await vuln.getAddress();

  // slachtoffer krijgt 1000 tokens en approved het kwetsbare contract
  await (await token.mint(VICTIM, 1000n)).wait();
  const victimS = await impersonate(VICTIM);
  await (await new ethers.Contract(TOKEN, ['function approve(address,uint) returns(bool)'], victimS).approve(VULN, ethers.MaxUint256)).wait();
  L('setup: victim-bal=' + (await token.balanceOf(VICTIM)));

  // aanvaller trekt het slachtoffer leeg via het kwetsbare contract
  const attS = await impersonate(ATTACKER);
  const vulnAtt = new ethers.Contract(VULN, ['function pull(address,address,address,uint)'], attS);
  await (await vulnAtt.pull(TOKEN, VICTIM, ATTACKER, 1000n, { gasLimit: 2000000 })).wait();
  const attBal = await token.balanceOf(ATTACKER);
  L('na aanval: attacker-token-bal=' + attBal + ' victim-bal=' + (await token.balanceOf(VICTIM)));
  if (attBal >= 1000n) console.log('[APPROVAL-DRAIN] pull | TOKEN | ' + attBal.toString());
  else console.log('[GEEN-DRAIN] attacker=' + attBal.toString());
`;

(async () => {
  fs.rmSync('./approval_dbg.txt', { force: true });
  const out = await runOnAnvilFork('0x0000000000000000000000000000000000000000', script);
  console.log(out.split('\n').filter(l => /APPROVAL-DRAIN|GEEN-DRAIN|ANVIL\] Fork/.test(l)).join('\n'));
  console.log('--- dbg ---'); try { console.log(fs.readFileSync('./approval_dbg.txt', 'utf8')); } catch (e) {}
  console.log(out.includes('[APPROVAL-DRAIN]') ? '✅ APPROVAL-DRAIN POSITIEVE CONTROLE GESLAAGD' : '❌ niet gedetecteerd');
  process.exit(0);
})().catch(e => { console.log('FOUT', e.message); process.exit(1); });
