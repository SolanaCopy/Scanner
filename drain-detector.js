// Gratis, deterministische permissionless-drain detector.
// Doel: vind contracten waar een NIET-owner fondsen kan wegtrekken naar zichzelf.
// Geen AI: kies kandidaat-functies uit de ABI, roep ze op een Anvil-fork aan als een
// willekeurige aanvaller, en meld ALLEEN als er echt geld naar de aanvaller stroomt.

// Functies die typisch fondsen uitbetalen (naam-heuristiek).
const DRAIN_NAME_RE = /withdraw|claim|redeem|sweep|rescue|salvage|transfer|send|emergency|migrate|payout|harvest|collect|drain|exit|unstake|sell|release|distribute|refund|cashout|retrieve|recover|take|grab|pull/i;
// Payable "deposit"-achtige functies — om eerst een positie op te bouwen (multi-step drains).
const DEPOSIT_NAME_RE = /deposit|stake|buy|enter|invest|mint|purchase|fund|provide|supply|lock|bond/i;

// Payable deposit-achtige functies (voor de deposit-dan-withdraw stap).
function pickDepositCandidates(abi) {
  if (!Array.isArray(abi)) return [];
  const out = [];
  for (const item of abi) {
    if (item.type !== 'function' || item.stateMutability !== 'payable') continue;
    const inputs = item.inputs || [];
    if (inputs.length > 2) continue;
    if (!inputs.every(i => /^(uint\d*|int\d*|address|bool)$/.test(i.type))) continue;
    if (DEPOSIT_NAME_RE.test(item.name)) out.push({ name: item.name, types: inputs.map(i => i.type), sig: `${item.name}(${inputs.map(i => i.type).join(',')})` });
  }
  return out.slice(0, 5);
}

// Kies kandidaat-functies: state-changing, simpele args, drain-achtige naam OF door Slither geflagd.
function pickDrainCandidates(abi, slitherFindings) {
  if (!Array.isArray(abi)) return [];
  const slitherFns = new Set(
    (slitherFindings || [])
      .filter(f => /arbitrary-send|suicidal|unchecked-transfer/.test(f.check || ''))
      .map(f => ((f.description || '').match(/\.(\w+)\s*\(/) || [])[1])
      .filter(Boolean)
  );
  const out = [];
  for (const item of abi) {
    if (item.type !== 'function') continue;
    if (item.stateMutability === 'view' || item.stateMutability === 'pure') continue;
    const inputs = item.inputs || [];
    if (inputs.length > 3) continue;
    const simple = inputs.every(i => /^(uint\d*|int\d*|address|bool)$/.test(i.type));
    if (!simple) continue;
    if (DRAIN_NAME_RE.test(item.name) || slitherFns.has(item.name)) {
      const sig = `${item.name}(${inputs.map(i => i.type).join(',')})`;
      out.push({ name: item.name, types: inputs.map(i => i.type), sig });
    }
  }
  // dedup op signatuur, cap op 30 (forktijd beheersbaar)
  const seen = new Set();
  return out.filter(c => !seen.has(c.sig) && seen.add(c.sig)).slice(0, 30);
}

// Bouw het Anvil-fork script (draait binnen runOnAnvilFork; provider/TARGET/impersonate/fund bestaan al).
function buildDrainScript(candidates, depositCands, tokens) {
  return `
  const ATTACKER = '0x1111111111111111111111111111111111111111';
  await fund(ATTACKER); await setBalance(ATTACKER, '1000');
  const signer = await impersonate(ATTACKER);
  const TOKENS = ${JSON.stringify(tokens)};
  const ERC = a => new ethers.Contract(a, ['function balanceOf(address) view returns (uint256)'], provider);
  const CANDS = ${JSON.stringify(candidates)};
  const DEPOSITS = ${JSON.stringify(depositCands || [])};

  const tokBal = {};
  for (const [n, a] of Object.entries(TOKENS)) { try { tokBal[n] = await ERC(a).balanceOf(TARGET); } catch(e) { tokBal[n] = 0n; } }
  const maxTok = Object.values(tokBal).reduce((m, v) => v > m ? v : m, 0n);
  const cNativeStart = await provider.getBalance(TARGET);
  const HUGE = 10n ** 30n;

  // Rijkere arg-fuzzing (meer waarden per type, gecapt op 6 combinaties)
  function argVariants(types) {
    if (types.length === 0) return [[]];
    const per = types.map(t => {
      if (/^(uint|int)/.test(t)) return [...new Set([maxTok > 0n ? maxTok : HUGE, cNativeStart > 0n ? cNativeStart : (10n ** 18n), 1n, HUGE])];
      if (t === 'address') return [ATTACKER, TARGET];
      if (t === 'bool') return [true, false];
      return [0];
    });
    let combos = [[]];
    for (const opts of per) { const next = []; for (const c of combos) for (const o of opts) { if (next.length < 6) next.push([...c, o]); } combos = next; }
    return combos;
  }

  // Meet attacker-winst rond een call-sequence; geeft hits terug of null bij revert
  async function measure(fn) {
    const aTokB = {}; for (const [n, a] of Object.entries(TOKENS)) aTokB[n] = await ERC(a).balanceOf(ATTACKER);
    const cTokB = {}; for (const [n, a] of Object.entries(TOKENS)) cTokB[n] = await ERC(a).balanceOf(TARGET);
    const aNatB = await provider.getBalance(ATTACKER);
    let ok = false; try { await fn(); ok = true; } catch(e) {}
    if (!ok) return null;
    const hits = [];
    for (const [n, a] of Object.entries(TOKENS)) {
      const gain = (await ERC(a).balanceOf(ATTACKER)) - aTokB[n];
      const loss = cTokB[n] - (await ERC(a).balanceOf(TARGET));
      if (gain > 0n && loss > 0n) hits.push({ token: n, amt: ethers.formatUnits(gain, 18) });
    }
    const aNatA = await provider.getBalance(ATTACKER);
    if (aNatA > aNatB + (10n ** 16n)) hits.push({ token: 'NATIVE', amt: ethers.formatEther(aNatA - aNatB) });
    return hits;
  }

  let drains = 0;
  // Fase 1: directe drains met rijke fuzzing
  for (const c of CANDS) {
    const iface = new ethers.Contract(TARGET, ['function ' + c.sig], signer);
    for (const args of argVariants(c.types)) {
      const snap = await provider.send('evm_snapshot', []);
      const hits = await measure(async () => { await iface[c.name](...args, { gasLimit: 4000000, value: c.payable ? (10n ** 18n) : 0n }); });
      await provider.send('evm_revert', [snap]);
      if (hits && hits.length) { for (const h of hits) console.log('[DRAIN] ' + c.name + ' | ' + h.token + ' | ' + h.amt); drains++; break; }
    }
  }
  // Fase 2: deposit-dan-withdraw (multi-step) — eerst positie opbouwen, dan drain proberen
  for (const dep of DEPOSITS.slice(0, 2)) {
    for (const c of CANDS) {
      const depIface = new ethers.Contract(TARGET, ['function ' + dep.sig], signer);
      const drIface = new ethers.Contract(TARGET, ['function ' + c.sig], signer);
      const drArgs = argVariants(c.types)[0] || [];
      const depArgs = argVariants(dep.types)[0] || [];
      const snap = await provider.send('evm_snapshot', []);
      const hits = await measure(async () => {
        await depIface[dep.name](...depArgs, { gasLimit: 4000000, value: 10n ** 18n });
        await drIface[c.name](...drArgs, { gasLimit: 4000000 });
      });
      await provider.send('evm_revert', [snap]);
      if (hits && hits.length) { for (const h of hits) console.log('[DRAIN] deposit+' + c.name + ' | ' + h.token + ' | ' + h.amt); drains++; }
    }
  }
  console.log('[DRAIN-TEST-DONE] ' + CANDS.length + ' functies getest, ' + drains + ' drains');
  `;
}

// Creation-bytecode van de generieke ReentryAttacker (solc 0.8.20, geoptimaliseerd).
const REENTRY_BYTECODE = '0x608060405234801561000f575f80fd5b506106358061001d5f395ff3fe608060405260043610610042575f3560e01c8063551e502e14610059578063631c56ef1461006c578063d4b8399214610094578063e150ef49146100ca57610051565b366100515761004f6100eb565b005b61004f6100eb565b61004f610067366004610332565b61016b565b348015610077575f80fd5b5061008160025481565b6040519081526020015b60405180910390f35b34801561009f575f80fd5b505f546100b2906001600160a01b031681565b6040516001600160a01b03909116815260200161008b565b3480156100d5575f80fd5b506100de610261565b60405161008b91906103ba565b600460025410156101695760028054905f61010583610405565b90915550505f546040516001600160a01b039091169061012790600190610461565b5f604051808303815f865af19150503d805f8114610160576040519150601f19603f3d011682016040523d82523d5f602084013e610165565b606091505b5050505b565b5f80546001600160a01b0319166001600160a01b0387161790556001610192828483610534565b505f60025582156101fd575f856001600160a01b03163486866040516101b99291906105f0565b5f6040518083038185875af1925050503d805f81146101f3576040519150601f19603f3d011682016040523d82523d5f602084013e6101f8565b606091505b505050505b5f856001600160a01b031683836040516102189291906105f0565b5f604051808303815f865af19150503d805f8114610251576040519150601f19603f3d011682016040523d82523d5f602084013e610256565b606091505b505050505050505050565b6001805461026e90610429565b80601f016020809104026020016040519081016040528092919081815260200182805461029a90610429565b80156102e55780601f106102bc576101008083540402835291602001916102e5565b820191905f5260205f20905b8154815290600101906020018083116102c857829003601f168201915b505050505081565b5f8083601f8401126102fd575f80fd5b50813567ffffffffffffffff811115610314575f80fd5b60208301915083602082850101111561032b575f80fd5b9250929050565b5f805f805f60608688031215610346575f80fd5b85356001600160a01b038116811461035c575f80fd5b9450602086013567ffffffffffffffff80821115610378575f80fd5b61038489838a016102ed565b9096509450604088013591508082111561039c575f80fd5b506103a9888289016102ed565b969995985093965092949392505050565b5f6020808352835180828501525f5b818110156103e5578581018301518582016040015282016103c9565b505f604082860101526040601f19601f8301168501019250505092915050565b5f6001820161042257634e487b7160e01b5f52601160045260245ffd5b5060010190565b600181811c9082168061043d57607f821691505b60208210810361045b57634e487b7160e01b5f52602260045260245ffd5b50919050565b5f80835461046e81610429565b60018281168015610486576001811461049b576104c7565b60ff19841687528215158302870194506104c7565b875f526020805f205f5b858110156104be5781548a8201529084019082016104a5565b50505082870194505b50929695505050505050565b634e487b7160e01b5f52604160045260245ffd5b601f821115610165575f81815260208120601f850160051c8101602086101561050d5750805b601f850160051c820191505b8181101561052c57828155600101610519565b505050505050565b67ffffffffffffffff83111561054c5761054c6104d3565b6105608361055a8354610429565b836104e7565b5f601f841160018114610591575f851561057a5750838201355b5f19600387901b1c1916600186901b1783556105e9565b5f83815260209020601f19861690835b828110156105c157868501358255602094850194600190920191016105a1565b50868210156105dd575f1960f88860031b161c19848701351681555b505060018560011b0183555b5050505050565b818382375f910190815291905056fea2646970667358221220142b90aed29d9beb293bd383e58b47b30d4a56584ce65ced6dc02b3128dc1c2264736f6c63430008140033';

// Functies die Slither als reentrancy markeerde (kandidaat voor de reentrancy-aanvaller).
function pickReentrancyTargets(abi, slitherFindings) {
  if (!Array.isArray(abi)) return [];
  const reentFns = new Set(
    (slitherFindings || [])
      .filter(f => /reentrancy/.test(f.check || ''))
      .map(f => ((f.description || '').match(/\.(\w+)\s*\(/) || [])[1])
      .filter(Boolean)
  );
  if (reentFns.size === 0) return [];
  const out = [];
  for (const item of abi) {
    if (item.type !== 'function' || ['view', 'pure'].includes(item.stateMutability)) continue;
    const inputs = item.inputs || [];
    if (inputs.length > 2 || !inputs.every(i => /^(uint\d*|int\d*|address|bool)$/.test(i.type))) continue;
    if (reentFns.has(item.name)) out.push({ name: item.name, types: inputs.map(i => i.type), sig: `${item.name}(${inputs.map(i => i.type).join(',')})` });
  }
  const seen = new Set();
  return out.filter(c => !seen.has(c.sig) && seen.add(c.sig)).slice(0, 12);
}

// Reentrancy-fork-script: deploy aanvaller, voer per target (met/zonder deposit) een re-entry-aanval uit.
function buildReentrancyScript(targets, deposits, tokens) {
  return `
  const EOA = '0x1111111111111111111111111111111111111111';
  await fund(EOA); await setBalance(EOA, '1000');
  const signer = await impersonate(EOA);
  const factory = new ethers.ContractFactory(['function go(address,bytes,bytes) payable'], '${REENTRY_BYTECODE}', signer);
  const att = await factory.deploy();
  await att.waitForDeployment();
  const ATT = await att.getAddress();
  const goC = new ethers.Contract(ATT, ['function go(address,bytes,bytes) payable'], signer);
  const TOKENS = ${JSON.stringify(tokens)};
  const ERC = a => new ethers.Contract(a, ['function balanceOf(address) view returns (uint256)'], provider);
  const TARGETS = ${JSON.stringify(targets)};
  const DEPOSITS = ${JSON.stringify(deposits || [])};
  const argZero = types => (types || []).map(t => t === 'address' ? ATT : (t === 'bool' ? false : 0n));
  const enc = (sig, name, types) => new ethers.Interface(['function ' + sig]).encodeFunctionData(name, argZero(types));

  let drains = 0;
  for (const wd of TARGETS) {
    for (const dep of [null, ...DEPOSITS.slice(0, 2)]) {
      const snap = await provider.send('evm_snapshot', []);
      try {
        await provider.send('anvil_setBalance', [ATT, ethers.toBeHex(ethers.parseEther('5'))]);
        const natB = await provider.getBalance(ATT);
        const tokB = {}; for (const [n, a] of Object.entries(TOKENS)) tokB[n] = await ERC(a).balanceOf(ATT);
        const wdData = enc(wd.sig, wd.name, wd.types);
        let depData = '0x'; let value = 0n;
        if (dep) { depData = enc(dep.sig, dep.name, dep.types); value = ethers.parseEther('1'); }
        await goC.go(TARGET, depData, wdData, { value, gasLimit: 8000000 });
        const natA = await provider.getBalance(ATT);
        // winst = eindsaldo - startsaldo - eigen inleg (msg.value). Inleg-terugkrijgen telt NIET.
        if (natA > natB + value + (10n ** 16n)) { console.log('[REENTRANCY-DRAIN] ' + wd.name + ' | NATIVE | ' + ethers.formatEther(natA - natB - value)); drains++; }
        for (const [n, a] of Object.entries(TOKENS)) { const g = (await ERC(a).balanceOf(ATT)) - tokB[n]; if (g > 0n) { console.log('[REENTRANCY-DRAIN] ' + wd.name + ' | ' + n + ' | ' + ethers.formatUnits(g, 18)); drains++; } }
      } catch (e) {}
      await provider.send('evm_revert', [snap]);
    }
  }
  console.log('[REENTRANCY-DONE] ' + TARGETS.length + ' targets, ' + drains + ' drains');
  `;
}

// Parse output van runOnAnvilFork -> lijst drains
function parseDrains(output) {
  const drains = [];
  for (const line of (output || '').split('\n')) {
    const m = line.match(/\[(?:DRAIN|REENTRANCY-DRAIN)\]\s*([\w+]+)\s*\|\s*(\w+)\s*\|\s*([\d.]+)/);
    if (m) drains.push({ fn: m[1], token: m[2], amount: parseFloat(m[3]), reentrancy: line.includes('REENTRANCY') });
  }
  return drains;
}

module.exports = { pickDrainCandidates, pickDepositCandidates, pickReentrancyTargets, buildDrainScript, buildReentrancyScript, parseDrains, DRAIN_NAME_RE };
