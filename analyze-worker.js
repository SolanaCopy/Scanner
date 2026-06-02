// Analyze Worker — draait Slither + Mythril + Security in apart process
// Wordt geforkt vanuit index.js zodat de scanner niet blokkeert
require('dotenv').config();
const TelegramBot = require('node-telegram-bot-api');
const axios = require('axios');
const { execSync, spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { pickDrainCandidates, pickDepositCandidates, pickApprovalCandidates, buildDrainScript, buildApprovalDrainScript, parseDrains } = require('./drain-detector.js');
// Tokens om drain-stromen te volgen (BSC)
const DRAIN_TOKENS = {
  USDT: '0x55d398326f99059fF775485246999027B3197955',
  USDC: '0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d',
  WBNB: '0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c',
  BUSD: '0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56',
};

// === PASHOV DEDUP CACHE ===
// Voorkomt dat hetzelfde contract met IDENTIEKE source opnieuw (duur) geaudit wordt.
// Contracten komen vaak meermaals langs (balance verandert bij elke transfer) → ~2x verspilling.
const PASHOV_CACHE_FILE = path.join(__dirname, 'pashov_audited.json');
const PASHOV_CACHE_TTL = 7 * 24 * 60 * 60 * 1000; // 7 dagen
let pashovAuditedCache = {};
try {
  pashovAuditedCache = JSON.parse(fs.readFileSync(PASHOV_CACHE_FILE, 'utf8'));
  const cutoff = Date.now() - PASHOV_CACHE_TTL;
  for (const a in pashovAuditedCache) if ((pashovAuditedCache[a].ts || 0) < cutoff) delete pashovAuditedCache[a];
} catch (e) {}
function srcHash(s) { return crypto.createHash('sha1').update(s || '').digest('hex').slice(0, 16); }
function markPashovAudited(address, hash, result) {
  pashovAuditedCache[address.toLowerCase()] = { hash, ts: Date.now(), risk: result?.risk_level || null, findings: (result?.findings || []).length };
  try { fs.writeFileSync(PASHOV_CACHE_FILE, JSON.stringify(pashovAuditedCache)); } catch (e) {}
}

// BscScan rate limit wrapper
let lastBscScanCall = 0;
async function bscScanGet(url) {
  const now = Date.now();
  const wait = Math.max(0, 250 - (now - lastBscScanCall));
  if (wait > 0) await new Promise(r => setTimeout(r, wait));
  lastBscScanCall = Date.now();
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      const res = await axios.get(url, { timeout: 15000 });
      // Retry op ALLE transiente fouten (rate limit, status != 1), zodat een verified
      // contract niet vals als 'geen source' wordt afgeschreven. Echt-unverified niet retryen.
      const reallyUnverified = typeof res.data.result === 'string' && /not verified/i.test(res.data.result);
      if (res.data.status !== '1' && !reallyUnverified && attempt < 3) {
        console.log(`[BSCSCAN] Transient (status=${res.data.status}, msg=${res.data.message}) — retry ${attempt}/3`);
        await new Promise(r => setTimeout(r, 2000));
        continue;
      }
      return res;
    } catch (e) { if (attempt < 3) { await new Promise(r => setTimeout(r, 1000)); continue; } throw e; }
  }
}

const SLITHER_PATH = 'C:/Users/moham/AppData/Local/Python/pythoncore-3.14-64/Scripts/slither.exe';
const SOLC_PATH = 'C:/Users/moham/AppData/Local/Python/pythoncore-3.14-64/Scripts/solc.exe';
const MYTHRIL_DOCKER = 'mythril/myth'; // Mythril via Docker
const ECHIDNA_DOCKER = 'ghcr.io/crytic/echidna/echidna'; // Echidna via Docker
const DOCKER_ENV = { ...process.env, PATH: (process.env.PATH || '') + ';C:\\Program Files\\Docker\\Docker\\resources\\bin' };
const BSCSCAN_KEY = process.env.BSCSCAN_API_KEY;
const CLAUDE_API_KEY = process.env.CLAUDE_API_KEY || '';
const TELEGRAM_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const CHAT_ID = process.env.TELEGRAM_CHAT_ID;
const RESULTS_FILE = path.join(__dirname, 'scan_results.json');
const RENDER_URL = process.env.RENDER_URL || 'https://flexbot-qpf2.onrender.com';
const SCANNER_API_KEY = process.env.SCANNER_API_KEY || '';

// === AUTO-LEARN: laad false positive patronen uit findings history ===
let LEARNED_FP_PATTERNS = '';
let LEARNED_FP_FUNCTIONS = []; // Voor confidence score
try {
  const historyLines = fs.readFileSync(path.join(__dirname, 'findings_history.jsonl'), 'utf8').trim().split('\n').map(l => JSON.parse(l));

  // Verbeterde learning key: agent:functie (specifieker dan alleen functienaam)
  const fnStats = {};
  for (const f of historyLines) {
    const fn = f.function || '?';
    const agent = f.agent || 'unknown';
    const key = `${agent}:${fn}`;
    if (!fnStats[key]) fnStats[key] = { total: 0, proven: 0, rejected: 0, fn, agent };
    fnStats[key].total++;
    if (f.anvilResult === 'PROVEN') fnStats[key].proven++;
    if (f.anvilResult === 'REJECTED') fnStats[key].rejected++;
  }

  // Patronen die 2+ keer voorkomen en NOOIT proven zijn = false positive
  const fpPatterns = Object.entries(fnStats)
    .filter(([key, s]) => s.total >= 2 && s.proven === 0)
    .map(([key, s]) => ({ key, ...s }));

  LEARNED_FP_FUNCTIONS = fpPatterns.map(p => p.fn.toLowerCase());

  if (fpPatterns.length > 0) {
    const fpList = fpPatterns.map(p => `${p.key} (${p.total}x rejected)`);
    LEARNED_FP_PATTERNS = '\n== GELEERDE FALSE POSITIVE PATRONEN (uit ' + historyLines.length + ' eerdere findings) ==\nDeze agent:functie combinaties zijn in het verleden ALTIJD false positive gebleken op Anvil fork. Wees EXTRA sceptisch bij deze patronen:\n' + fpList.join(', ') + '\nAls je deze functies rapporteert, moet je STERK bewijs hebben dat het DEZE keer anders is.\n';
    console.log(`[LEARN] ${fpPatterns.length} false positive patronen geladen uit ${historyLines.length} findings`);
  }

  // Accuracy stats
  const totalProven = historyLines.filter(f => f.anvilResult === 'PROVEN').length;
  const totalRejected = historyLines.filter(f => f.anvilResult === 'REJECTED').length;
  const avgConfProven = historyLines.filter(f => f.anvilResult === 'PROVEN' && f.anvilConfidence).reduce((sum, f) => sum + f.anvilConfidence, 0) / (totalProven || 1);
  const avgConfRejected = historyLines.filter(f => f.anvilResult === 'REJECTED' && f.anvilConfidence).reduce((sum, f) => sum + f.anvilConfidence, 0) / (totalRejected || 1);
  console.log(`[LEARN] Accuracy: ${totalProven} proven (${Math.round(totalProven/historyLines.length*100)}%) | ${totalRejected} rejected (${Math.round(totalRejected/historyLines.length*100)}%)`);
  if (avgConfProven > 0) console.log(`[LEARN] Gem. confidence: proven=${Math.round(avgConfProven)} | rejected=${Math.round(avgConfRejected)}`);
} catch(e) { console.log('[LEARN] Geen history beschikbaar'); }

// Laad attack vectors voor AI analyse
let ATTACK_VECTORS = '';
try {
  const raw = fs.readFileSync('C:/pashov-skills/solidity-auditor/references/attack-vectors/attack-vectors.md', 'utf8');
  // Pak eerste 8000 chars (meest relevante vectors)
  ATTACK_VECTORS = raw.substring(0, 8000);
  console.log(`[VECTORS] ${ATTACK_VECTORS.split('**').filter(s => /^\d+\./.test(s)).length} attack vectors geladen`);
} catch(e) { console.log('[VECTORS] Niet gevonden, AI draait zonder vectors'); }

// === STRIP BOILERPLATE ===
// Verwijdert OpenZeppelin/standaard libraries uit source zodat de AI alleen
// de unieke contract logica ziet. Bespaart 60-90% tokens en voorkomt truncatie.
function stripBoilerplate(sourceCode) {
  if (!sourceCode || sourceCode.length < 5000) return sourceCode;

  // Patronen voor bekende libraries die we kunnen wegknippen
  // Match: "contract X" / "library X" / "abstract contract X" / "interface X"
  const BOILERPLATE_NAMES = new Set([
    // OpenZeppelin core
    'Context', 'Ownable', 'Ownable2Step', 'AccessControl', 'AccessControlEnumerable',
    'IAccessControl', 'IERC165', 'ERC165', 'Pausable', 'ReentrancyGuard',
    // OpenZeppelin tokens
    'IERC20', 'IERC20Metadata', 'IERC20Permit', 'ERC20', 'ERC20Burnable',
    'ERC20Pausable', 'ERC20Permit', 'ERC20Snapshot', 'ERC20Votes', 'ERC20Capped',
    'IERC721', 'IERC721Metadata', 'IERC721Enumerable', 'IERC721Receiver',
    'ERC721', 'ERC721Burnable', 'ERC721Enumerable', 'ERC721URIStorage',
    'IERC1155', 'IERC1155MetadataURI', 'IERC1155Receiver', 'ERC1155',
    'IERC777', 'ERC777',
    // OpenZeppelin utils
    'SafeERC20', 'SafeMath', 'Address', 'Strings', 'Math', 'SignedMath',
    'EnumerableSet', 'EnumerableMap', 'BitMaps', 'MerkleProof',
    'ECDSA', 'EIP712', 'SignatureChecker', 'MessageHashUtils',
    'Counters', 'Arrays', 'StorageSlot', 'Create2', 'Clones',
    // Proxy patterns
    'Proxy', 'ERC1967Proxy', 'ERC1967Upgrade', 'TransparentUpgradeableProxy',
    'BeaconProxy', 'UpgradeableBeacon', 'ProxyAdmin',
    'Initializable', 'UUPSUpgradeable',
    // Older versions
    'SafeMathUpgradeable', 'OwnableUpgradeable', 'ContextUpgradeable',
    'ERC20Upgradeable', 'IERC20Upgradeable', 'PausableUpgradeable',
    'ReentrancyGuardUpgradeable', 'AccessControlUpgradeable',
    'AddressUpgradeable', 'StringsUpgradeable',
    // Common libs
    'SafeCast', 'FullMath', 'TickMath', 'FixedPoint', 'FixedPoint96',
    'LowGasSafeMath', 'TransferHelper', 'BoringMath', 'BoringERC20',
  ]);

  // Vind alle contract/library/interface/abstract definities
  // Pattern: "contract Name " of "contract Name is" of "library Name {" etc
  const blocks = [];
  const re = /(?:^|\n)\s*(?:abstract\s+)?(contract|library|interface)\s+(\w+)/g;
  let match;
  while ((match = re.exec(sourceCode)) !== null) {
    blocks.push({
      type: match[1],
      name: match[2],
      start: match.index + (match[0].startsWith('\n') ? 1 : 0),
    });
  }

  if (blocks.length === 0) return sourceCode;

  // Voor elke block: vind de matching closing brace
  for (let i = 0; i < blocks.length; i++) {
    const blockStart = blocks[i].start;
    const openBrace = sourceCode.indexOf('{', blockStart);
    if (openBrace === -1) { blocks[i].end = sourceCode.length; continue; }
    let depth = 1;
    let pos = openBrace + 1;
    while (pos < sourceCode.length && depth > 0) {
      const ch = sourceCode[pos];
      if (ch === '{') depth++;
      else if (ch === '}') depth--;
      pos++;
    }
    blocks[i].end = pos;
  }

  // Bouw nieuwe source: behoud header (pragma/imports) + niet-boilerplate blocks
  const firstBlockStart = blocks[0].start;
  const header = sourceCode.substring(0, firstBlockStart).trim();

  let stripped = header + '\n\n';
  let strippedCount = 0;
  let keptCount = 0;

  for (const block of blocks) {
    if (BOILERPLATE_NAMES.has(block.name)) {
      // Vervang door 1-regel placeholder zodat AI weet dat het bestaat
      stripped += `// [BOILERPLATE STRIPPED] ${block.type} ${block.name} — standaard OpenZeppelin/library, AI kent deze\n\n`;
      strippedCount++;
    } else {
      stripped += sourceCode.substring(block.start, block.end) + '\n\n';
      keptCount++;
    }
  }

  // Logging zodat we kunnen zien wat er gebeurt
  const before = sourceCode.length;
  const after = stripped.length;
  if (strippedCount > 0) {
    console.log(`[STRIP] ${strippedCount} libraries geknipt, ${keptCount} contracten behouden | ${before} → ${after} chars (${Math.round((1 - after / before) * 100)}% kleiner)`);
  }

  return stripped;
}

// === FETCH CROSS-CONTRACT DEPENDENCIES ===
// Detecteert hardcoded contract adressen in source en fetcht hun source van BSCScan
// zodat de AI cross-contract attacks kan vinden
// Cache: dependencies hergebruiken binnen sessie (max 200 entries)
const DEP_CACHE = new Map();
const STANDARD_TOKENS = new Set([
  '0x55d398326f99059ff775485246999027b3197955', // USDT BSC
  '0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d', // USDC BSC
  '0xe9e7cea3dedca5984780bafc599bd69add087d56', // BUSD
  '0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c', // WBNB
  '0x2170ed0880ac9a755fd29b2688956bd959f933f8', // ETH BSC
  '0x7130d2a12b9bcbfae4f2634d864a1ee1ce3ead9c', // BTCB
  '0xcc42724c6683b7e57334c4e856f4c9965ed682bd', // MATIC
  '0x1ce0c2827e2ef14d5c4f29a091d735a204794041', // AVAX
  '0x3ee2200efb3400fabb9aacf31297cbdd1d435d47', // ADA
  '0x4338665cbb7b2485a8855a139b75d5e34ab0db94', // LTC
  '0xba2ae424d960c26247dd6c32edc70b295c744c43', // DOGE
  '0x4b0f1812e5df2a09796481ff14017e6005508003', // TWT
  '0xfb6115445bff7b52feb98650c87f44907e58f802', // AAVE
  '0xf8a0bf9cf54bb92f17374d9e9a321e6a111a51bd', // LINK
  '0x0000000000000000000000000000000000000000', // zero address
  '0x000000000000000000000000000000000000dead', // burn
]);

async function fetchDependencyContracts(sourceCode, mainAddress) {
  if (!sourceCode || !BSCSCAN_KEY) return '';

  // SLIMME CHECK: alleen fetchen als contract ECHT DeFi-achtig is
  // Skip simpele tokens, presales, staking zonder externe afhankelijkheden
  const lc = sourceCode.toLowerCase();
  const DEFI_INDICATORS = [
    'oracle', 'router', 'vault', 'strategy', 'controller', 'lendingpool',
    'pricefeed', 'aggregator', 'masterchef', 'gauge', 'curve', 'pancake',
    'flashloan', 'borrow', 'repay', 'liquidate', 'collateral',
    'getamountsout', 'swapexact', 'getreserves', 'latestanswer',
    'getprice', 'getrate', 'exchangerate', 'sharesToAssets', 'previewdeposit',
    'idelegate', 'icontroller', 'istrategy', 'irouter', 'ioracle', 'ivault',
  ];
  const hasDeFiPattern = DEFI_INDICATORS.some(kw => lc.includes(kw));

  // Vind alle 40-char hex addresses in de source
  const addrRegex = /0x[a-fA-F0-9]{40}/g;
  const found = new Set();
  let m;
  while ((m = addrRegex.exec(sourceCode)) !== null) {
    const addr = m[0].toLowerCase();
    if (addr === mainAddress.toLowerCase()) continue;
    if (STANDARD_TOKENS.has(addr)) continue;
    found.add(addr);
  }

  // Skip-regels — geen dependencies fetchen als:
  // 1. Geen DeFi indicators én weinig adressen → simpel contract
  // 2. 0 unieke adressen → niks te fetchen
  if (found.size === 0) return '';
  if (!hasDeFiPattern && found.size < 3) {
    console.log(`[DEPS] Skip — simpel contract (geen DeFi indicators, ${found.size} addresses)`);
    return '';
  }

  // Max 3 dependencies om kosten/tokens te beperken (was 5)
  const MAX_DEPS = 3;
  const deps = Array.from(found).slice(0, MAX_DEPS);
  console.log(`[DEPS] ${found.size} unieke addresses, DeFi pattern: ${hasDeFiPattern}, fetch max ${MAX_DEPS}...`);

  // Parallel fetch met cache check
  const fetchOne = async (addr) => {
    if (DEP_CACHE.has(addr)) {
      console.log(`[DEPS] Cache hit: ${addr.slice(0, 10)}...`);
      return DEP_CACHE.get(addr);
    }
    try {
      const url = `https://api.etherscan.io/v2/api?chainid=56&module=contract&action=getsourcecode&address=${addr}&apikey=${BSCSCAN_KEY}`;
      const res = await bscScanGet(url);
      if (res.data.status !== '1' || !res.data.result?.[0]?.SourceCode) {
        DEP_CACHE.set(addr, null);
        return null;
      }
      const c = res.data.result[0];
      let depSource = c.SourceCode;
      if (depSource.startsWith('{{')) {
        try {
          const parsed = JSON.parse(depSource.slice(1, -1));
          const sources = parsed.sources || parsed;
          depSource = Object.values(sources).map(s => s.content || s).join('\n');
        } catch (e) {}
      }
      const stripped = stripBoilerplate(depSource);
      // Per dependency max 6000 chars (was 8000) — slanker
      const trimmed = stripped.length > 6000 ? stripped.substring(0, 6000) + '\n// ... [dep truncated]' : stripped;
      const entry = { name: c.ContractName || 'Unknown', source: trimmed };
      DEP_CACHE.set(addr, entry);
      // Cache trim — houd max 200 entries
      if (DEP_CACHE.size > 200) {
        const firstKey = DEP_CACHE.keys().next().value;
        DEP_CACHE.delete(firstKey);
      }
      console.log(`[DEPS] Opgehaald: ${entry.name} @ ${addr.slice(0, 10)}... (${trimmed.length} chars)`);
      return entry;
    } catch (e) {
      DEP_CACHE.set(addr, null);
      return null;
    }
  };

  const fetched = await Promise.all(deps.map(fetchOne));
  const results = fetched
    .map((entry, i) => entry ? `### Dependency: ${entry.name} @ ${deps[i]}\n\`\`\`solidity\n${entry.source}\n\`\`\`` : null)
    .filter(Boolean);

  if (results.length === 0) return '';
  return `\n\n## CROSS-CONTRACT DEPENDENCIES (contracten waar het hoofdcontract van afhankelijk is):\n\n${results.join('\n\n')}\n\n⚠️ Check ook of de aanvaller via deze dependencies het hoofdcontract kan exploiten (bv. manipuleerbare oracle, malicious router, controleerbare vault).`;
}

// Telegram bot (alleen voor berichten sturen, geen polling)
const bot = new TelegramBot(TELEGRAM_TOKEN);

async function safeSend(text) {
  // Telegram max = 4096 chars, splits op newlines
  const MAX = 4000;
  const chunks = [];
  if (text.length <= MAX) {
    chunks.push(text);
  } else {
    let remaining = text;
    while (remaining.length > 0) {
      if (remaining.length <= MAX) { chunks.push(remaining); break; }
      let cut = remaining.lastIndexOf('\n', MAX);
      if (cut < MAX * 0.3) cut = MAX; // geen goede newline gevonden, harde knip
      chunks.push(remaining.substring(0, cut));
      remaining = remaining.substring(cut).trimStart();
    }
  }
  for (const chunk of chunks) {
    try {
      await bot.sendMessage(CHAT_ID, chunk, { parse_mode: 'Markdown', disable_web_page_preview: true });
    } catch (err) {
      try {
        await bot.sendMessage(CHAT_ID, chunk.replace(/[*_`\[\]]/g, ''), { disable_web_page_preview: true });
      } catch (err2) {
        console.error('[WORKER-TG] Fout:', err2.message);
      }
    }
  }
}

// === SLITHER ===
// FP-filter: alleen high-signal, exploiteerbare detectoren (geen style/info/naming-ruis).
const SLITHER_SECURITY_CHECKS = new Set([
  'reentrancy-eth', 'reentrancy-no-eth', 'arbitrary-send-eth', 'arbitrary-send-erc20',
  'arbitrary-send-erc20-permit', 'suicidal', 'controlled-delegatecall', 'delegatecall-loop',
  'controlled-array-length', 'unchecked-transfer', 'unchecked-lowlevel', 'unchecked-send',
  'tx-origin', 'unprotected-upgrade', 'weak-prng', 'incorrect-equality', 'uninitialized-state',
  'uninitialized-storage', 'writes-after-write', 'msg-value-loop', 'shadowing-state',
]);
async function runSlither(address) {
  try {
    const url = `https://api.etherscan.io/v2/api?chainid=56&module=contract&action=getsourcecode&address=${address}&apikey=${BSCSCAN_KEY}`;
    const res = await bscScanGet(url);
    if (res.data.status !== '1' || !res.data.result[0].SourceCode) return { success: false, error: 'Source niet beschikbaar' };

    const contract = res.data.result[0];
    const contractName = contract.ContractName || 'Contract';
    const compilerVersion = contract.CompilerVersion || '';
    let sourceCode = contract.SourceCode;

    const tmpDir = path.join(__dirname, 'tmp_slither', address);
    fs.mkdirSync(tmpDir, { recursive: true });

    if (sourceCode.startsWith('{{')) {
      try {
        const parsed = JSON.parse(sourceCode.slice(1, -1));
        const sources = parsed.sources || parsed;
        for (const [filePath, fileData] of Object.entries(sources)) {
          const fullPath = path.join(tmpDir, filePath);
          fs.mkdirSync(path.dirname(fullPath), { recursive: true });
          fs.writeFileSync(fullPath, fileData.content || fileData);
        }
      } catch (e) { fs.writeFileSync(path.join(tmpDir, `${contractName}.sol`), sourceCode); }
    } else {
      fs.writeFileSync(path.join(tmpDir, `${contractName}.sol`), sourceCode);
    }

    const versionMatch = compilerVersion.match(/v?(\d+\.\d+\.\d+)/);
    const solcVersion = versionMatch ? versionMatch[1] : '0.8.20';

    // Slither draait in WSL (Ubuntu 24.04, Python 3.12) — de Windows-.exe crasht op Python 3.14 (DLL exit 3221225786).
    // Via wrapper-script run-slither.sh (absolute paden) zodat inline-shell-quoting geen roet gooit.
    const toWsl = p => p.replace(/^([A-Za-z]):/, (m, d) => '/mnt/' + d.toLowerCase()).replace(/\\/g, '/');
    const wslDir = toWsl(tmpDir);
    const wrapperWsl = toWsl(path.join(__dirname, 'run-slither.sh'));
    let output = '';
    try {
      output = await new Promise((resolve) => {
        const child = spawn('wsl', ['-d', 'Ubuntu-24.04', '--', 'bash', wrapperWsl, wslDir, solcVersion], { timeout: 180000 });
        let stdout = '';
        child.stdout.on('data', d => stdout += d);
        child.on('close', () => resolve(stdout));
        child.on('error', () => resolve(''));
      });
    } catch (e) { output = ''; }

    fs.rmSync(tmpDir, { recursive: true, force: true });

    let findings = [];
    try {
      const json = JSON.parse(output.substring(Math.max(0, output.indexOf('{'))));
      if (json.results && json.results.detectors) {
        const all = json.results.detectors.map(d => ({ check: d.check, impact: d.impact, confidence: d.confidence, description: (d.description || '').substring(0, 300) }));
        // FP-filter: alleen high-signal security-detectoren, geen Low-confidence/style/info-ruis
        findings = all.filter(f => SLITHER_SECURITY_CHECKS.has(f.check) && (f.impact === 'High' || f.impact === 'Medium') && f.confidence !== 'Low');
        const dropped = all.length - findings.length;
        if (dropped > 0) console.log(`[SLITHER] ${all.length} findings → ${findings.length} security (${dropped} ruis weggefilterd)`);
      }
    } catch (e) {
      return { success: false, error: 'Parse fout', contractName, compilerVersion };
    }

    return { success: true, findings, contractName, compilerVersion };
  } catch (err) { return { success: false, error: err.message }; }
}

function formatSlitherReport(address, result) {
  if (!result.success) {
    const safeError = (result.error || '').replace(/[`*_\[\]()~>#+=|{}.!\\-]/g, ' ').substring(0, 300);
    return `❌ *Slither Analyse Mislukt*\n\`${address}\`\nFout: ${safeError}`;
  }
  const findings = result.findings;
  const high = findings.filter(f => f.impact === 'High').length;
  const medium = findings.filter(f => f.impact === 'Medium').length;
  const low = findings.filter(f => f.impact === 'Low').length;
  const info = findings.filter(f => f.impact === 'Informational' || f.impact === 'Optimization').length;

  let riskLevel = '🟢 LAAG RISICO';
  if (high > 0) riskLevel = '🔴 HOOG RISICO';
  else if (medium > 0) riskLevel = '🟡 MEDIUM RISICO';

  let msg = `🔬 *Slither Analyse*\n\n━━━━━━━━━━━━━━━━━━━━\n📋 *Contract:* ${result.contractName || 'Onbekend'}\n\`${address}\`\n${riskLevel}\n━━━━━━━━━━━━━━━━━━━━\n\n📊 *Issues:* 🔴 ${high} | 🟡 ${medium} | 🟢 ${low} | ℹ️ ${info}\n`;

  const important = findings.filter(f => f.impact === 'High' || f.impact === 'Medium').slice(0, 5);
  if (important.length > 0) {
    msg += `\n⚠️ *Top Issues:*\n`;
    for (const f of important) {
      const icon = f.impact === 'High' ? '🔴' : '🟡';
      const desc = (f.description || '').substring(0, 150).replace(/[`*_]/g, '');
      msg += `${icon} *${f.check}*\n   ${desc}\n\n`;
    }
  }
  msg += `━━━━━━━━━━━━━━━━━━━━\n🔗 [BSCScan](https://bscscan.com/address/${address})`;
  return msg;
}

// === MYTHRIL ===
async function runMythril(address) {
  try {
    const url = `https://api.etherscan.io/v2/api?chainid=56&module=contract&action=getsourcecode&address=${address}&apikey=${BSCSCAN_KEY}`;
    const res = await bscScanGet(url);
    if (res.data.status !== '1' || !res.data.result[0].SourceCode) return { success: false, error: 'Source niet beschikbaar' };

    const contract = res.data.result[0];
    const contractName = contract.ContractName || 'Contract';
    const compilerVersion = contract.CompilerVersion || '';
    let sourceCode = contract.SourceCode;

    const tmpDir = path.join(__dirname, 'tmp_mythril', address);
    fs.mkdirSync(tmpDir, { recursive: true });

    let mainFile = path.join(tmpDir, `${contractName}.sol`);
    if (sourceCode.startsWith('{{')) {
      try {
        const parsed = JSON.parse(sourceCode.slice(1, -1));
        const sources = parsed.sources || parsed;
        const files = Object.keys(sources);
        const imports = {};
        for (const f of files) {
          const content = sources[f].content || sources[f];
          imports[f] = [];
          for (const line of content.split('\n')) {
            const m = line.trim().match(/^import\s+.*["'](.+?)["']/);
            if (m) {
              const imp = m[1];
              let resolved = imp;
              if (imp.startsWith('.')) {
                const dir = f.substring(0, f.lastIndexOf('/'));
                const parts = (dir + '/' + imp).split('/');
                const normalized = [];
                for (const p of parts) { if (p === '..') normalized.pop(); else if (p !== '.') normalized.push(p); }
                resolved = normalized.join('/');
              }
              const match = files.find(k => k === resolved) || files.find(k => k === imp) || files.find(k => k.endsWith(resolved));
              if (match && !imports[f].includes(match)) imports[f].push(match);
            }
          }
        }
        const ordered = []; const visited = new Set();
        function visit(f) { if (visited.has(f)) return; visited.add(f); for (const dep of (imports[f] || [])) visit(dep); ordered.push(f); }
        for (const f of files) visit(f);
        let flatCode = ''; let licenseAdded = false; let pragmaAdded = false;
        for (const filePath of ordered) {
          const content = sources[filePath].content || sources[filePath];
          for (const line of content.split('\n')) {
            const trimmed = line.trim();
            if (trimmed.startsWith('import ')) continue;
            if (trimmed.startsWith('// SPDX-License')) { if (licenseAdded) continue; licenseAdded = true; }
            if (trimmed.startsWith('pragma solidity')) { if (pragmaAdded) continue; pragmaAdded = true; }
            flatCode += line + '\n';
          }
        }
        fs.writeFileSync(mainFile, flatCode);
      } catch (e) { fs.writeFileSync(mainFile, sourceCode); }
    } else { fs.writeFileSync(mainFile, sourceCode); }

    const versionMatch = compilerVersion.match(/v?(\d+\.\d+\.\d+)/);
    let solcVersion = '0.8.20';
    if (versionMatch) solcVersion = versionMatch[1];

    // Docker mount: tmpDir -> /tmp/mythril in container
    const dockerTmpDir = tmpDir.replace(/\\/g, '/');
    const containerFile = `/tmp/mythril/${contractName}.sol`;
    let output = '';

    for (const solcArgs of ['', ' --solc-args "--via-ir --optimize"']) {
      const cmd = `docker run --rm -v "${dockerTmpDir}:/tmp/mythril" ${MYTHRIL_DOCKER} analyze ${containerFile} --solv ${solcVersion} -o json --execution-timeout 120${solcArgs}`;
      try {
        output = execSync(cmd, { timeout: 300000, encoding: 'utf-8', env: DOCKER_ENV, windowsHide: true });
        break;
      } catch (e) {
        output = e.stdout || e.stderr || '';
        output = output.replace(/[^\x20-\x7E\n\r\t{}[\]:,"]/g, '');
        if (!solcArgs && output.toLowerCase().includes('stack too deep')) continue;
        break;
      }
    }

    setTimeout(() => { try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch(e) {} }, 5000);

    let issues = [];
    try {
      if (!output || !output.trim()) return { success: false, error: 'Geen output', contractName, compilerVersion };
      const jsonStart = output.indexOf('{');
      if (jsonStart < 0) return { success: false, error: output.substring(0, 200), contractName, compilerVersion };
      if (jsonStart > 0) output = output.substring(jsonStart);
      const json = JSON.parse(output);
      if (json.success && json.issues) {
        issues = json.issues.map(i => ({ title: i.title, severity: i.severity, swcId: i['swc-id'], description: (i.description || '').substring(0, 300), function: i.function, code: i.code }));
      } else if (json.error) {
        const errLines = json.error.trim().split('\n');
        const meaningful = errLines.find(l => l.trim().length > 5 && !l.trim().match(/^[\s\^|~]+$/)) || errLines[0];
        let shortErr = (meaningful || '').trim().substring(0, 200);
        if (json.error.includes('Stack too deep')) shortErr = 'Contract te complex (stack too deep)';
        return { success: false, error: shortErr, contractName, compilerVersion };
      }
    } catch (e) { return { success: false, error: 'Parse fout' }; }

    return { success: true, issues, contractName, compilerVersion };
  } catch (err) { return { success: false, error: err.message }; }
}

function formatMythrilReport(address, result) {
  if (!result.success) {
    const safeError = (result.error || '').replace(/[`*_\[\]()~>#+=|{}.!\\-]/g, ' ').substring(0, 300);
    return `❌ *Mythril Analyse Mislukt*\n\`${address}\`\nFout: ${safeError}`;
  }
  const issues = result.issues;
  const high = issues.filter(i => i.severity === 'High').length;
  const medium = issues.filter(i => i.severity === 'Medium').length;
  const low = issues.filter(i => i.severity === 'Low').length;

  let riskLevel = '🟢 LAAG RISICO';
  if (high > 0) riskLevel = '🔴 HOOG RISICO';
  else if (medium > 0) riskLevel = '🟡 MEDIUM RISICO';

  let msg = `🔮 *Mythril Deep Analyse*\n\n━━━━━━━━━━━━━━━━━━━━\n📋 *Contract:* ${result.contractName || 'Onbekend'}\n\`${address}\`\n${riskLevel}\n━━━━━━━━━━━━━━━━━━━━\n\n📊 *Vulnerabilities:* 🔴 ${high} | 🟡 ${medium} | 🟢 ${low}\n`;

  if (issues.length === 0) msg += `\n✅ Geen kwetsbaarheden gevonden!\n`;

  const important = issues.filter(i => i.severity === 'High' || i.severity === 'Medium').slice(0, 5);
  if (important.length > 0) {
    msg += `\n⚠️ *Top Issues:*\n`;
    for (const i of important) {
      const icon = i.severity === 'High' ? '🔴' : '🟡';
      const swc = i.swcId ? ` (SWC-${i.swcId})` : '';
      const desc = (i.description || '').substring(0, 200).replace(/[`*_]/g, '');
      msg += `${icon} *${i.title}*${swc}\n   ${desc}\n\n`;
    }
  }
  msg += `━━━━━━━━━━━━━━━━━━━━\n🔗 [BSCScan](https://bscscan.com/address/${address})`;
  return msg;
}

// === SECURITY CHECK ===
async function runSecurityCheck(address) {
  try {
    const url = `https://api.etherscan.io/v2/api?chainid=56&module=contract&action=getsourcecode&address=${address}&apikey=${BSCSCAN_KEY}`;
    const res = await bscScanGet(url);
    if (res.data.status !== '1' || !res.data.result[0].SourceCode) return { success: false, error: 'Source niet beschikbaar', findings: [] };

    let sourceCode = res.data.result[0].SourceCode;
    const contractName = res.data.result[0].ContractName || 'Contract';
    if (sourceCode.startsWith('{{')) {
      try {
        const parsed = JSON.parse(sourceCode.slice(1, -1));
        const sources = parsed.sources || parsed;
        sourceCode = Object.values(sources).map(s => s.content || s).join('\n');
      } catch (e) {}
    }

    const code = sourceCode.toLowerCase();
    const findings = [];

    // Rugpull
    if (/function\s+mint\s*\(/.test(sourceCode) && /onlyowner|_owner|owner\(\)/.test(code)) {
      const hasMax = /maxsupply|max_supply|cap/.test(code);
      findings.push({ category: 'RUGPULL', severity: hasMax ? 'MEDIUM' : 'HIGH', title: 'Owner Mint', detail: hasMax ? 'Mint met cap' : 'Onbeperkte mint door owner' });
    }
    const feeSetters = sourceCode.match(/function\s+set(Fee|Tax|Rate|Commission|Slippage)\w*\s*\([^)]*\)/gi) || [];
    for (const fn of feeSetters) {
      const fnBody = sourceCode.substring(sourceCode.indexOf(fn), sourceCode.indexOf(fn) + 500);
      if (!/require\s*\(.*[<>]=?\s*\d+|max(fee|tax|rate)|<= ?\d+/.test(fnBody.toLowerCase())) {
        findings.push({ category: 'RUGPULL', severity: 'HIGH', title: `Fee Manipulatie: ${fn.match(/set\w+/)[0]}`, detail: 'Owner kan fees naar 100% zetten' });
      }
    }
    if (/function\s+(blacklist|addblacklist|blocklist|ban)\s*\(/i.test(sourceCode)) findings.push({ category: 'RUGPULL', severity: 'HIGH', title: 'Blacklist', detail: 'Owner kan adressen blokkeren' });
    if (/function\s+pause\s*\(/i.test(sourceCode) && /whennotpaused|_paused/i.test(code)) findings.push({ category: 'RUGPULL', severity: 'MEDIUM', title: 'Pause', detail: 'Owner kan transfers pauzeren' });
    if (/selfdestruct|suicide/i.test(code)) findings.push({ category: 'RUGPULL', severity: 'HIGH', title: 'Selfdestruct', detail: 'Contract kan vernietigd worden' });
    if (/delegatecall|upgradeto|_implementation|transparentproxy|uupsproxy/i.test(code)) findings.push({ category: 'RUGPULL', severity: 'MEDIUM', title: 'Upgradeable', detail: 'Logica kan vervangen worden' });
    if (/mapping.*isbot|mapping.*isblocked/i.test(code) && /require\s*\(\s*!.*bot|require\s*\(\s*!.*blocked/i.test(sourceCode)) {
      findings.push({ category: 'RUGPULL', severity: 'HIGH', title: 'Honeypot', detail: 'Bot/blocked mapping kan verkoop blokkeren' });
    }

    // Exploit
    const withdrawFns = sourceCode.match(/function\s+(withdraw|emergencyWithdraw|sweep|drain|claim|rescue)\w*\s*\([^)]*\)[^{]*/gi) || [];
    for (const fn of withdrawFns) {
      const fnName = fn.match(/function\s+(\w+)/)[1];
      const fnBody = sourceCode.substring(sourceCode.indexOf(fn), sourceCode.indexOf(fn) + 800);
      const hasAuth = /onlyowner|require\s*\(\s*msg\.sender\s*==\s*(owner|_owner|admin)|onlyrole|hasrole/i.test(fnBody);
      // claim/withdraw die op msg.sender werken zijn veilig (user claimt eigen rewards)
      const usesMsgSender = /\[msg\.sender\]|balances\[msg\.sender|rewards\[msg\.sender|userInfo\[msg\.sender|stakes\[msg\.sender/i.test(fnBody);
      if (!hasAuth && !usesMsgSender) {
        findings.push({ category: 'EXPLOIT', severity: 'HIGH', title: `Onbeschermde ${fnName}()`, detail: `Iedereen kan ${fnName}() aanroepen` });
      }
    }
    if (/\.call\{value:|\.call\.value\(/.test(sourceCode) && !/reentrancyguard|nonreentrant|_status|_locked/i.test(code)) {
      findings.push({ category: 'EXPLOIT', severity: 'HIGH', title: 'Reentrancy', detail: 'External call zonder guard' });
    }
    if (/require\s*\(\s*tx\.origin\s*==/.test(sourceCode)) findings.push({ category: 'EXPLOIT', severity: 'HIGH', title: 'tx.origin Auth', detail: 'Kwetsbaar voor phishing' });
    if (/function\s+set(Owner|Admin|Operator)\s*\(/i.test(sourceCode)) {
      const fnMatch = sourceCode.match(/function\s+set(Owner|Admin|Operator)\s*\([^)]*\)[^{]*/i);
      if (fnMatch) {
        const fnBody = sourceCode.substring(sourceCode.indexOf(fnMatch[0]), sourceCode.indexOf(fnMatch[0]) + 500);
        if (!/onlyowner|require|modifier/i.test(fnBody)) {
          findings.push({ category: 'EXPLOIT', severity: 'HIGH', title: 'Open Owner Transfer', detail: 'Iedereen kan owner worden' });
        }
      }
    }

    // Logic — alleen flash loan kwetsbaar als spot balance direct in swap/price functie zit
    if (/balanceof\s*\(\s*address\s*\(\s*this\s*\)\s*\)/i.test(sourceCode) && !/twap|timeweighted|oracle|chainlink/i.test(code)
      && /function\s+(swap|getPrice|calcPrice|getRate|getAmountOut|quote)\s*\(/i.test(sourceCode)) {
      findings.push({ category: 'LOGIC', severity: 'MEDIUM', title: 'Flash Loan Risico', detail: 'Spot balance in swap/price functie zonder TWAP/oracle' });
    }
    if (/rewardpertoken|rewardrate|earned\s*\(/i.test(code) && !/1e18|1e12|precision/i.test(code)) {
      findings.push({ category: 'LOGIC', severity: 'MEDIUM', title: 'Reward Afrondingsfout', detail: 'Geen precision scaling' });
    }

    return { success: true, findings, contractName, sourceCode };
  } catch (err) { return { success: false, error: err.message, findings: [] }; }
}

function formatSecurityReport(address, result) {
  if (!result.success) return `❌ *Security Check Mislukt*\n\`${address}\`\nFout: ${(result.error || '').substring(0, 200)}`;
  const findings = result.findings;
  if (findings.length === 0) return `✅ *Security Check Schoon*\n\`${address}\`\nGeen rugpull patronen of exploits gevonden.`;

  const rugpulls = findings.filter(f => f.category === 'RUGPULL');
  const exploits = findings.filter(f => f.category === 'EXPLOIT');
  const logic = findings.filter(f => f.category === 'LOGIC');
  const highCount = findings.filter(f => f.severity === 'HIGH').length;

  let verdict = '🟢 RELATIEF VEILIG';
  if (highCount >= 3) verdict = '🔴 ZEER GEVAARLIJK';
  else if (highCount >= 1) verdict = '🟡 VERDACHT';

  let msg = `🛡️ *Security & Rugpull Check*\n\n━━━━━━━━━━━━━━━━━━━━\n📋 *Contract:* ${result.contractName || 'Onbekend'}\n\`${address}\`\n${verdict}\n━━━━━━━━━━━━━━━━━━━━\n\n`;

  if (rugpulls.length > 0) {
    msg += `🚩 *Rugpull (${rugpulls.length}):*\n`;
    for (const f of rugpulls) msg += `${f.severity === 'HIGH' ? '🔴' : '🟡'} *${f.title}* — ${f.detail}\n`;
    msg += '\n';
  }
  if (exploits.length > 0) {
    msg += `💀 *Exploits (${exploits.length}):*\n`;
    for (const f of exploits) msg += `${f.severity === 'HIGH' ? '🔴' : '🟡'} *${f.title}* — ${f.detail}\n`;
    msg += '\n';
  }
  if (logic.length > 0) {
    msg += `🧠 *Logic (${logic.length}):*\n`;
    for (const f of logic) msg += `${f.severity === 'HIGH' ? '🔴' : '🟡'} *${f.title}* — ${f.detail}\n`;
  }
  msg += `\n━━━━━━━━━━━━━━━━━━━━\n🔗 [BSCScan](https://bscscan.com/address/${address})`;
  return msg;
}

// === AI ANALYSE (Sonnet 4.6 + Pashov attack vectors + extended thinking) ===
async function runAIAnalysis(address, sourceCode, slitherFindings, mythrilIssues, securityFindings) {
  if (!CLAUDE_API_KEY) return null;
  try {
    const stripped = stripBoilerplate(sourceCode);
    const trimmedSource = stripped.length > 60000 ? stripped.substring(0, 60000) + '\n// ... [TRUNCATED]' : stripped;
    const previousFindings = [];
    if (slitherFindings.length > 0) previousFindings.push('Slither: ' + slitherFindings.slice(0, 5).map(f => `${f.impact} - ${f.check}`).join(', '));
    if (mythrilIssues.length > 0) previousFindings.push('Mythril: ' + mythrilIssues.slice(0, 5).map(i => `${i.severity} - ${i.title}`).join(', '));
    if (securityFindings.length > 0) previousFindings.push('Security: ' + securityFindings.slice(0, 5).map(f => `${f.severity} ${f.title}`).join(', '));

    const vectorSection = ATTACK_VECTORS ? `\n\n== BEKENDE ATTACK VECTORS (check elk hiervan) ==\n${ATTACK_VECTORS}\n== EINDE VECTORS ==` : '';

    const prompt = `Je bent een elite blockchain security auditor. Er zit geld in dit contract. Jouw ENIGE vraag is:

👉 KAN IEMAND DIE GEEN EIGENAAR IS — VIA WELKE TRUC DAN OOK — GELD UIT DIT CONTRACT KRIJGEN?

==== EERDER GEVONDEN DOOR STATIC ANALYSERS ====
Slither/Mythril/Security tools hebben deze findings gerapporteerd. JE TAAK: voor ELK van deze findings, valideer letterlijk in de source — bevestig of weerleg met code citaat. Slither vindt vaak echte bugs maar ook false positives door pattern matching. Mythril is symbolic execution en preciezer. Behandel ze als TIPS, niet als waarheid.

${previousFindings.join('\n') || 'Geen static findings'}

INSTRUCTIE: Begin je antwoord met een sectie "STATIC FINDINGS REVIEW" waar je elke bovenstaande finding markeert als:
- ✅ BEVESTIGD: bug bestaat echt, citaat: "..."
- ❌ FALSE POSITIVE: bug bestaat niet omdat: ...
- ⚠️ UITGEBREID: bug bestaat in andere vorm, hier is hoe...
${vectorSection}

Contract: ${address}
\`\`\`solidity
${trimmedSource}
\`\`\`

==== ANTI-HALLUCINATIE REGELS (NEGEREN = JE FAALT) ====
1. Alleen functies met visibility \`external\` of \`public\` tellen als ENTRYPOINT voor de aanvaller. \`internal\`/\`private\` functies kan een aanvaller niet rechtstreeks aanroepen — alleen als ze door een external functie heen bereikbaar zijn.
2. Functies met \`onlyOwner\`/\`onlyAdmin\`/\`onlyRole\`/\`require(msg.sender == owner)\` zijn voor de aanvaller GESLOTEN — niet als directe finding rapporteren (tenzij de aanvaller via een andere weg dezelfde state kan beïnvloeden).
3. VERZIN GEEN functienamen. Functienaam moet letterlijk in de source staan. Geen exacte match → niet rapporteren.
4. Source bevat "// TRUNCATED" of je ziet de functie body niet? Antwoord ⚠️ INSUFFICIENT_DATA. GOK NIET.
5. Elke finding moet bevatten: entrypoint functie (external/public, exact uit source) + welke stappen + welke state wordt misbruikt + hoeveel geld eruit kan.

==== ZOEK BEIDE TYPES BUGS ====

**TYPE A — Directe access control bugs (de simpele):**
- External/public functie die geld verstuurt zonder check op msg.sender
- Vergeten \`onlyOwner\` modifier op transfer/withdraw

**TYPE B — Business logic / trucjes (de gevaarlijke):** ← HIER LIGT MEESTAL HET ECHTE GELD
Een aanvaller hoeft GEEN withdraw functie aan te roepen. Hij gebruikt bedoelde functies op een onbedoelde manier:

1. **Reward/yield manipulatie** — Deposit + claim cyclus die meer uitbetaalt dan ingelegd. First depositor inflation, share price manipulatie via direct token transfer naar contract.
2. **Flash loan aanvallen** — Leen $10M, manipuleer iets (oracle/reserves/share price/voting), trek winst, betaal terug.
3. **Reentrancy patronen** — Cross-function reentrancy: claim() roept extern aan, je re-entered via deposit() of een andere functie en breekt accounting.
4. **Oracle/price manipulatie** — Contract leest spot price van een DEX pool die je in dezelfde tx kan kantelen.
5. **Accounting bugs** — Variabele wordt verkeerd verhoogd/verlaagd. Bijv. \`balance += amount\` zonder \`amount > 0\` check, of double-counting bij meerdere assets.
6. **Signature/replay bugs** — Permit/meta-tx zonder nonce check, of signature die op meerdere chains werkt.
7. **Slippage/MEV ontbreken** — Functie zonder min-out check waardoor sandwich/extractie mogelijk is.
8. **Timing/order trucs** — Functies die op block.timestamp/blockNumber vertrouwen zonder TWAP/cooldown.
9. **Token quirks misbruiken** — Fee-on-transfer, rebase tokens, dubbele entry tokens (BSC heeft veel rare tokens).
10. **Unchecked external calls** — Return value van .call() of token transfer niet gechecked → state diverges van werkelijkheid.
11. **Initialisatie bugs** — initialize() zonder access control, of initializer die opnieuw aanroepbaar is.
12. **Storage collisions** — Proxy patroon met overlappende slots.
13. **Approval/allowance misbruik** — Contract houdt approvals van users, en jij kan een functie aanroepen die in NAAM van die users transferFrom doet.
14. **Multi-step exploit chains** — Geen enkele functie is op zichzelf bug, maar 3 functies achter elkaar (deposit → vote → claim) breken een invariant.

BIJ ELKE EXTERNAL/PUBLIC FUNCTIE: vraag jezelf "kan ik via deze functie — eventueel in combinatie met andere functies of een flash loan — funds uit dit contract halen die niet van mij zijn?"

DE ENIGE VRAAG IS: kan een niet-eigenaar via welke truc dan ook funds uit dit contract krijgen? Niet "is er een bug in theorie", niet "is dit suboptimaal gecodeerd". Alleen: kan er geld uit waar de aanvaller geen recht op heeft?

ANTWOORD FORMAT:
- 🔴 EXPLOITABLE — type (A of B), entrypoint(s), exacte aanvalsstappen, geschatte buit
- 🟡 VERDACHT — zwakke plek met code citaat, waarom je niet zeker bent
- ✅ VEILIG — niet-eigenaar kan via geen enkele combinatie geld eruit halen
- ⚠️ INSUFFICIENT_DATA — source afgeknipt

Max 5 findings. Alleen echte paden. Nederlands.`;

    let response = null;
    for (let attempt = 1; attempt <= 3; attempt++) {
      try {
        response = await axios.post('https://api.anthropic.com/v1/messages', {
          model: 'claude-sonnet-4-6',
          max_tokens: 16000,
          thinking: { type: 'enabled', budget_tokens: 10000 },
          messages: [{ role: 'user', content: prompt }]
        }, {
          headers: { 'x-api-key': CLAUDE_API_KEY, 'anthropic-version': '2023-06-01', 'anthropic-beta': 'interleaved-thinking-2025-05-14', 'content-type': 'application/json' },
          timeout: 180000
        });
        break;
      } catch (e) {
        const status = e.response?.status;
        const isRetryable = status === 529 || status === 503 || status === 500 || e.code === 'ECONNABORTED' || e.code === 'ETIMEDOUT';
        if (isRetryable && attempt < 3) {
          const waitTime = attempt * 60000;
          console.log(`[AI-DEEP] API ${status || e.code} — retry ${attempt}/3 in ${waitTime/1000}s...`);
          await new Promise(r => setTimeout(r, waitTime));
        } else { throw e; }
      }
    }
    // Extract text blocks (skip thinking blocks)
    const textBlocks = response.data.content.filter(b => b.type === 'text');
    return textBlocks.map(b => b.text).join('\n');
  } catch (err) { console.error('[WORKER-AI] Fout:', err.response?.status, JSON.stringify(err.response?.data?.error || err.message)); return null; }
}

// === ANVIL FORK RUNNER (crash-proof) ===
const ANVIL_PATH = 'C:/Users/moham/.foundry/bin/anvil.exe';
let anvilPort = 18546; // aparte port voor scanner (niet conflicten met dashboard)

// Meerdere BSC RPC's voor fallback — als er een down is, probeer een ander
const BSC_RPCS = [
  process.env.BSC_RPC || 'https://bsc-dataseed1.binance.org',
  'https://bsc-dataseed2.binance.org',
  'https://bsc-dataseed3.binance.org',
  'https://bsc-dataseed.bnbchain.org',
  'https://rpc.ankr.com/bsc',
];

// Track lopende anvil processes zodat we ze ALTIJD kunnen killen
const ACTIVE_ANVILS = new Set();

// Cleanup ALLE anvil processes bij scanner exit — voorkomt orphan processes
function killAllAnvils() {
  for (const anvil of ACTIVE_ANVILS) {
    try { anvil.kill('SIGKILL'); } catch (e) {}
  }
  ACTIVE_ANVILS.clear();
}
process.on('exit', killAllAnvils);
process.on('SIGINT', () => { killAllAnvils(); process.exit(0); });
process.on('SIGTERM', () => { killAllAnvils(); process.exit(0); });
process.on('uncaughtException', (e) => {
  console.error('[WORKER-CRASH] uncaughtException:', e.message);
  killAllAnvils();
  // Niet exit — laat PM2 dat doen als nodig
});
process.on('unhandledRejection', (e) => {
  console.error('[WORKER-CRASH] unhandledRejection:', e?.message || e);
});

// Check of poort vrij is
async function isPortFree(port) {
  return new Promise(resolve => {
    const net = require('net');
    const server = net.createServer();
    server.once('error', () => resolve(false));
    server.once('listening', () => {
      server.close();
      resolve(true);
    });
    server.listen(port, '127.0.0.1');
  });
}

// Vind een vrije poort uit de range
async function findFreePort() {
  for (let attempt = 0; attempt < 50; attempt++) {
    const port = anvilPort++;
    if (anvilPort > 18600) anvilPort = 18546;
    if (await isPortFree(port)) return port;
  }
  return null;
}

// Health check Anvil
async function isAnvilReady(port, maxWaitMs = 25000) {
  const startTime = Date.now();
  const url = `http://127.0.0.1:${port}`;
  while (Date.now() - startTime < maxWaitMs) {
    try {
      const r = await axios.post(url, {
        jsonrpc: '2.0', id: 1, method: 'eth_blockNumber', params: []
      }, { timeout: 1500 });
      if (r.data?.result) return true;
    } catch (e) { /* niet klaar */ }
    await new Promise(res => setTimeout(res, 400));
  }
  return false;
}

// Start Anvil met 1 specifiek RPC, return null bij failure
async function tryStartAnvil(rpcUrl, port) {
  let anvil;
  try {
    anvil = spawn(ANVIL_PATH, [
      '--fork-url', rpcUrl,
      '--host', '127.0.0.1',
      '--port', String(port),
      '--chain-id', '56',
      '--auto-impersonate',
    ], { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true, detached: false });
  } catch (e) {
    console.error(`[ANVIL] Spawn fout: ${e.message}`);
    return null;
  }
  ACTIVE_ANVILS.add(anvil);

  let stderrBuf = '';
  anvil.stderr.on('data', d => { stderrBuf += d.toString(); });
  anvil.on('error', e => console.error(`[ANVIL] Process error: ${e.message}`));

  // Auto-kill na 90 sec MAX (failsafe tegen hangen)
  const hardKill = setTimeout(() => {
    try { anvil.kill('SIGKILL'); } catch (e) {}
    ACTIVE_ANVILS.delete(anvil);
  }, 90000);

  const ready = await isAnvilReady(port, 25000);
  if (!ready) {
    console.error(`[ANVIL] RPC ${rpcUrl} faalde — stderr: ${stderrBuf.slice(0, 200)}`);
    try { anvil.kill('SIGKILL'); } catch (e) {}
    clearTimeout(hardKill);
    ACTIVE_ANVILS.delete(anvil);
    return null;
  }
  return { proc: anvil, hardKill };
}

async function runOnAnvilFork(targetAddress, exploitCode) {
  // Find free port (voorkomt collision crashes)
  const port = await findFreePort();
  if (!port) {
    throw new Error('Geen vrije poort beschikbaar in range 18546-18600');
  }

  // Probeer elke RPC tot 1 werkt
  let started = null;
  let triedRpcs = [];
  for (const rpc of BSC_RPCS) {
    triedRpcs.push(rpc);
    started = await tryStartAnvil(rpc, port);
    if (started) {
      console.log(`[ANVIL] Fork klaar op port ${port} via ${rpc.replace(/https?:\/\//, '').split('/')[0]}`);
      break;
    }
    console.log(`[ANVIL] Retry met andere RPC...`);
  }

  if (!started) {
    throw new Error(`Anvil kon niet starten met ${triedRpcs.length} RPCs geprobeerd`);
  }

  const { proc: anvil, hardKill } = started;

  // Schrijf exploit script
  const tmpFile = path.join(__dirname, 'tmp', `anvil_exploit_${port}.js`);
  let output = '';
  try {
    fs.mkdirSync(path.join(__dirname, 'tmp'), { recursive: true });

    const wrapper = `
const { ethers } = require('ethers');
const provider = new ethers.JsonRpcProvider('http://127.0.0.1:${port}');
const TARGET = '${targetAddress}';

async function impersonate(addr) {
  await provider.send('anvil_impersonateAccount', [addr]);
  return new ethers.JsonRpcSigner(provider, addr);
}
async function setBalance(addr, eth) {
  await provider.send('anvil_setBalance', [addr, ethers.toBeHex(ethers.parseEther(String(eth)))]);
}
async function fund(addr) { await setBalance(addr, '100'); }

(async () => {
  try {
    ${exploitCode}
    console.log('[DONE] Exploit test voltooid');
  } catch(e) {
    console.error('[ERROR]', e.message);
  }
  process.exit(0);
})();
`;
    fs.writeFileSync(tmpFile, wrapper);

    try {
      output = execSync(`node "${tmpFile}"`, {
        timeout: 60000,
        encoding: 'utf-8',
        env: process.env,
        cwd: path.dirname(tmpFile),
        windowsHide: true,
      });
    } catch(e) {
      output = (e.stdout || '') + '\n' + (e.stderr || '');
    }
  } catch (e) {
    output = `[ANVIL-WRAP-ERROR] ${e.message}`;
  } finally {
    // ALTIJD opruimen, ook bij errors
    clearTimeout(hardKill);
    try { anvil.kill('SIGKILL'); } catch(e) {}
    ACTIVE_ANVILS.delete(anvil);
    try { fs.unlinkSync(tmpFile); } catch(e) {}
  }

  return output;
}

// === FOUNDRY ON-CHAIN SCAN (cast) ===
const CAST_PATH = 'C:/Users/moham/.foundry/bin/cast';
const BSC_RPC = process.env.BSC_RPC || 'https://bsc-dataseed1.binance.org';

async function runFoundryScan(address) {
  const findings = [];
  const run = (cmd) => {
    try { return execSync(cmd, { timeout: 15000, encoding: 'utf-8', windowsHide: true, env: { ...process.env, PATH: process.env.PATH + ';C:/Users/moham/.foundry/bin' } }).trim(); } catch (e) { return ''; }
  };

  try {
    // 1. Check owner storage slot 0 (veel contracten slaan owner op in slot 0)
    const slot0 = run(`"${CAST_PATH}" storage ${address} 0 --rpc-url ${BSC_RPC}`);
    if (slot0 && slot0 !== '0x0000000000000000000000000000000000000000000000000000000000000000') {
      // Check of owner() callable is
      const owner = run(`"${CAST_PATH}" call ${address} "owner()(address)" --rpc-url ${BSC_RPC}`);
      if (owner && owner !== '0x0000000000000000000000000000000000000000') {
        findings.push({ check: 'OWNER', severity: 'INFO', detail: `Owner: ${owner}` });

        // Check of owner een EOA of contract is
        const ownerCode = run(`"${CAST_PATH}" code ${owner} --rpc-url ${BSC_RPC}`);
        if (!ownerCode || ownerCode === '0x') {
          findings.push({ check: 'EOA_OWNER', severity: 'MEDIUM', detail: 'Owner is een EOA (geen multisig/timelock)' });
        }
      }
    }

    // 2. Check proxy — EIP-1967 implementation slot
    const implSlot = '0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc';
    const implRaw = run(`"${CAST_PATH}" storage ${address} ${implSlot} --rpc-url ${BSC_RPC}`);
    if (implRaw && implRaw !== '0x0000000000000000000000000000000000000000000000000000000000000000') {
      const implAddr = '0x' + implRaw.slice(26);
      findings.push({ check: 'PROXY', severity: 'MEDIUM', detail: `Upgradeable proxy → impl: ${implAddr}` });

      // Check of implementatie verified is
      try {
        const url = `https://api.etherscan.io/v2/api?chainid=56&module=contract&action=getabi&address=${implAddr}&apikey=${BSCSCAN_KEY}`;
        const res = await bscScanGet(url);
        if (res.data.status !== '1') {
          findings.push({ check: 'UNVERIFIED_IMPL', severity: 'HIGH', detail: `Implementatie ${implAddr} is NIET verified` });
        }
      } catch (e) {}
    }

    // 3. Check paused state
    const paused = run(`"${CAST_PATH}" call ${address} "paused()(bool)" --rpc-url ${BSC_RPC}`);
    if (paused === 'true') {
      findings.push({ check: 'PAUSED', severity: 'HIGH', detail: 'Contract is momenteel GEPAUZEERD' });
    }

    // 4. Check totalSupply vs balance (token drain indicator)
    const totalSupply = run(`"${CAST_PATH}" call ${address} "totalSupply()(uint256)" --rpc-url ${BSC_RPC}`);
    if (totalSupply && totalSupply !== '0') {
      findings.push({ check: 'TOKEN', severity: 'INFO', detail: `TotalSupply: ${totalSupply}` });
    }

    // 5. Check selfdestruct in bytecode
    const bytecode = run(`"${CAST_PATH}" code ${address} --rpc-url ${BSC_RPC}`);
    if (bytecode && bytecode.toLowerCase().includes('ff')) {
      // ff = SELFDESTRUCT opcode — check meer specifiek
      const opcodes = bytecode.toLowerCase();
      // SELFDESTRUCT = 0xff, maar ff kan ook in PUSH data zitten
      // Simpele heuristiek: als bytecode kort is en ff bevat, waarschijnlijk selfdestruct
      if (bytecode.length < 2000 && opcodes.includes('ff')) {
        findings.push({ check: 'SELFDESTRUCT_BYTECODE', severity: 'MEDIUM', detail: 'Mogelijke SELFDESTRUCT in bytecode (kort contract)' });
      }
    }

    return { success: true, findings };
  } catch (err) {
    return { success: false, error: err.message, findings };
  }
}

function formatFoundryReport(address, result) {
  if (!result.success && result.findings.length === 0) {
    return `⚠️ *Foundry Scan Mislukt*\n\`${address}\``;
  }
  const findings = result.findings;
  if (findings.length === 0) return null; // Niks interessants

  const high = findings.filter(f => f.severity === 'HIGH');
  const medium = findings.filter(f => f.severity === 'MEDIUM');
  const info = findings.filter(f => f.severity === 'INFO');

  let msg = `🔧 *Foundry On-Chain Scan*\n━━━━━━━━━━━━━━━━━━━━\n\`${address}\`\n\n`;

  for (const f of [...high, ...medium]) {
    const icon = f.severity === 'HIGH' ? '🔴' : '🟡';
    msg += `${icon} *${f.check}* — ${f.detail}\n`;
  }
  for (const f of info) {
    msg += `ℹ️ *${f.check}* — ${f.detail}\n`;
  }

  return msg;
}

// === ECHIDNA FUZZING ===
async function runEchidna(address) {
  try {
    const url = `https://api.etherscan.io/v2/api?chainid=56&module=contract&action=getsourcecode&address=${address}&apikey=${BSCSCAN_KEY}`;
    const res = await bscScanGet(url);
    if (res.data.status !== '1' || !res.data.result[0].SourceCode) return { success: false, error: 'Source niet beschikbaar' };

    const contract = res.data.result[0];
    const contractName = contract.ContractName || 'Contract';
    const compilerVersion = contract.CompilerVersion || '';
    let sourceCode = contract.SourceCode;

    const tmpDir = path.join(__dirname, 'tmp_echidna', address);
    fs.mkdirSync(tmpDir, { recursive: true });

    let mainFile = path.join(tmpDir, `${contractName}.sol`);

    // Flatten multi-file contracts (zelfde logica als Mythril)
    if (sourceCode.startsWith('{{')) {
      try {
        const parsed = JSON.parse(sourceCode.slice(1, -1));
        const sources = parsed.sources || parsed;
        const files = Object.keys(sources);
        const imports = {};
        for (const f of files) {
          const content = sources[f].content || sources[f];
          imports[f] = [];
          for (const line of content.split('\n')) {
            const m = line.trim().match(/^import\s+.*["'](.+?)["']/);
            if (m) {
              const imp = m[1];
              let resolved = imp;
              if (imp.startsWith('.')) {
                const dir = f.substring(0, f.lastIndexOf('/'));
                const parts = (dir + '/' + imp).split('/');
                const normalized = [];
                for (const p of parts) { if (p === '..') normalized.pop(); else if (p !== '.') normalized.push(p); }
                resolved = normalized.join('/');
              }
              const match = files.find(k => k === resolved) || files.find(k => k === imp) || files.find(k => k.endsWith(resolved));
              if (match && !imports[f].includes(match)) imports[f].push(match);
            }
          }
        }
        const ordered = []; const visited = new Set();
        function visit(f) { if (visited.has(f)) return; visited.add(f); for (const dep of (imports[f] || [])) visit(dep); ordered.push(f); }
        for (const f of files) visit(f);
        let flatCode = ''; let licenseAdded = false; let pragmaAdded = false;
        for (const filePath of ordered) {
          const content = sources[filePath].content || sources[filePath];
          for (const line of content.split('\n')) {
            const trimmed = line.trim();
            if (trimmed.startsWith('import ')) continue;
            if (trimmed.startsWith('// SPDX-License')) { if (licenseAdded) continue; licenseAdded = true; }
            if (trimmed.startsWith('pragma solidity')) { if (pragmaAdded) continue; pragmaAdded = true; }
            flatCode += line + '\n';
          }
        }
        sourceCode = flatCode;
      } catch (e) { /* gebruik originele sourceCode */ }
    }

    // Schrijf contract + echidna config
    fs.writeFileSync(mainFile, sourceCode);

    const versionMatch = compilerVersion.match(/v?(\d+\.\d+\.\d+)/);
    const solcVersion = versionMatch ? versionMatch[1] : '0.8.20';

    // Echidna config: assertion mode (detecteert assert failures + reverts automatisch)
    const config = {
      testMode: 'assertion',
      testLimit: 10000,
      timeout: 90,
      seqLen: 50,
      format: 'text',
      codeSize: '0xffffffff',
      shrinkLimit: 2500,
    };
    fs.writeFileSync(path.join(tmpDir, 'echidna.yaml'), Object.entries(config).map(([k,v]) => `${k}: ${v}`).join('\n'));

    // Native Echidna binary (geen Docker meer)
    const ECHIDNA_PATH = 'C:/bsc-scanner/echidna/echidna.exe';
    const cmd = `"${ECHIDNA_PATH}" "${mainFile}" --contract ${contractName} --config "${path.join(tmpDir, 'echidna.yaml')}" 2>&1`;

    let output = '';
    try {
      output = execSync(cmd, { timeout: 180000, encoding: 'utf-8', windowsHide: true });
    } catch (e) {
      output = (e.stdout || '') + (e.stderr || '');
    }

    // Cleanup
    setTimeout(() => { try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch(e) {} }, 5000);

    // Parse resultaten
    const issues = [];
    const lines = output.split('\n');
    for (const line of lines) {
      // Echidna meldt "assertion in <function>: FAILED!" of "echidna_<prop>: FAILED!"
      if (line.includes('FAILED')) {
        const match = line.match(/(.+?):\s*FAILED/i);
        issues.push({
          type: 'assertion_failure',
          detail: match ? match[1].trim() : line.trim(),
          severity: 'High'
        });
      }
      // Reverts detecteren
      if (line.includes('REVERT') && !line.includes('PASSED')) {
        issues.push({
          type: 'revert_detected',
          detail: line.trim().substring(0, 300),
          severity: 'Medium'
        });
      }
    }

    // Check of echidna ueberhaupt iets nuttigs vond
    const passed = lines.filter(l => l.includes('PASSED')).length;
    const failed = issues.filter(i => i.type === 'assertion_failure').length;

    return {
      success: true,
      issues,
      passed,
      failed,
      contractName,
      compilerVersion,
      rawOutput: output.substring(0, 2000)
    };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

function formatEchidnaReport(address, result) {
  if (!result.success) {
    const safeError = (result.error || '').replace(/[`*_\[\]()~>#+=|{}.!\\-]/g, ' ').substring(0, 300);
    return `❌ *Echidna Fuzzing Mislukt*\n\`${address}\`\nFout: ${safeError}`;
  }

  const failed = result.failed || 0;
  const passed = result.passed || 0;
  const assertions = result.issues.filter(i => i.type === 'assertion_failure');

  let riskLevel = '🟢 GEEN ISSUES';
  if (failed > 0) riskLevel = '🔴 ASSERTION FAILURES';

  let msg = `🦔 *Echidna Fuzzing*\n━━━━━━━━━━━━━━━━━━━━\n📋 *Contract:* ${result.contractName || 'Onbekend'}\n\`${address}\`\n${riskLevel}\n━━━━━━━━━━━━━━━━━━━━\n\n📊 *Resultaten:* ✅ ${passed} passed | ❌ ${failed} failed\n`;

  if (assertions.length > 0) {
    msg += `\n⚠️ *Failed Assertions:*\n`;
    for (const a of assertions.slice(0, 5)) {
      msg += `🔴 ${a.detail.substring(0, 200)}\n`;
    }
  }

  if (failed === 0 && passed > 0) msg += `\n✅ Alle fuzzing tests doorstaan (${passed} properties)\n`;

  msg += `\n━━━━━━━━━━━━━━━━━━━━\n🔗 [BSCScan](https://bscscan.com/address/${address})`;
  return msg;
}

// === SAVE RESULT ===
function saveResult(address, balanceUsd, breakdown, slither, mythril, security, echidna, extra) {
  echidna = echidna || { success: false };
  extra = extra || {};
  let results = [];
  try { if (fs.existsSync(RESULTS_FILE)) results = JSON.parse(fs.readFileSync(RESULTS_FILE, 'utf-8')); } catch (e) {}

  const totalHigh = (slither.success ? slither.findings.filter(f => f.impact === 'High').length : 0)
    + (mythril.success ? mythril.issues.filter(i => i.severity === 'High').length : 0)
    + (security.success ? security.findings.filter(f => f.severity === 'HIGH').length : 0)
    + (echidna.success ? (echidna.failed || 0) : 0);
  const totalMedium = (slither.success ? slither.findings.filter(f => f.impact === 'Medium').length : 0)
    + (mythril.success ? mythril.issues.filter(i => i.severity === 'Medium').length : 0)
    + (security.success ? security.findings.filter(f => f.severity === 'MEDIUM').length : 0);

  const newResult = {
    address, balanceUsd, breakdown, time: new Date().toISOString(), totalHigh, totalMedium,
    contractName: slither.contractName || mythril.contractName || security.contractName || 'Onbekend',
    slither: { success: slither.success, high: slither.success ? slither.findings.filter(f => f.impact === 'High').length : 0, medium: slither.success ? slither.findings.filter(f => f.impact === 'Medium').length : 0, findings: slither.success ? slither.findings.filter(f => f.impact === 'High' || f.impact === 'Medium').map(f => ({ check: f.check, impact: f.impact, description: (f.description || '').substring(0, 200) })) : [] },
    mythril: { success: mythril.success, high: mythril.success ? mythril.issues.filter(i => i.severity === 'High').length : 0, medium: mythril.success ? mythril.issues.filter(i => i.severity === 'Medium').length : 0, issues: mythril.success ? mythril.issues.filter(i => i.severity === 'High' || i.severity === 'Medium').map(i => ({ title: i.title, severity: i.severity, swcId: i.swcId, function: i.function })) : [] },
    security: { success: security.success, findings: security.success ? security.findings : [] },
    echidna: { success: echidna.success, failed: echidna.failed || 0, passed: echidna.passed || 0, issues: echidna.success ? (echidna.issues || []).slice(0, 10) : [] },
    // Extra resultaten: Pashov, Foundry, Exploit test, Business Logic
    pashov: extra.pashov || null,
    foundry: extra.foundry || null,
    exploitTest: extra.exploitTest || null,
    businessLogic: extra.businessLogic || null
  };

  results.unshift(newResult);
  if (results.length > 200) results.pop();

  try { fs.writeFileSync(RESULTS_FILE, JSON.stringify(results, null, 2)); } catch (e) { console.error('[WORKER] Save fout:', e.message); }

  // Push naar dashboards
  const headers = { 'x-api-key': SCANNER_API_KEY };
  if (SCANNER_API_KEY && RENDER_URL) {
    axios.post(`${RENDER_URL}/api/scanner/results`, { result: newResult }, { headers, timeout: 10000 })
      .catch(e => console.error('[WORKER] Render push fout:', e.message));
  }
  // Lokaal dashboard: alleen verdachte/gevaarlijke contracten (high of medium findings)
  const LOCAL_DASH = process.env.LOCAL_DASH || 'http://localhost:3099';
  if (SCANNER_API_KEY && LOCAL_DASH) {
    axios.post(`${LOCAL_DASH}/api/scanner/results`, { result: newResult }, { headers, timeout: 3000 })
      .catch(() => {});
  }
}

// === BUSINESS LOGIC AUDIT (Stap 8) ===
// Gebruikt Claude om business logic bugs te vinden en genereert een Hardhat exploit om ze te verifiëren

async function runBusinessLogicAudit(address, sourceCode, balanceUsd, breakdown) {
  if (!CLAUDE_API_KEY) return null;

  try {
    // Stap 1: Stuur source naar Claude voor business logic analyse + exploit generatie
    const stripped = stripBoilerplate(sourceCode);
    const trimmedSource = stripped.length > 60000 ? stripped.substring(0, 60000) + '\n// ... [TRUNCATED]' : stripped;

    const tokenList = Object.entries(breakdown || {}).map(([k, v]) => `${k}: $${Math.round(v.usd || v.amount)}`).join(', ');

    const prompt = `Er zit $${Math.round(balanceUsd)} (${tokenList}) in dit BSC contract. De Pashov audit heeft al verdachte code gevonden.

Jouw taak: bevestig of een NIET-EIGENAAR daadwerkelijk geld kan stelen, en genereer een werkend exploit.

Contract: ${address} | Chain: BSC (chainId 56)

\`\`\`solidity
${trimmedSource}
\`\`\`

JE BENT EEN AANVALLER zonder owner/admin rechten. De aanvaller hoeft GEEN withdraw functie aan te roepen — hij gebruikt LEGIT functies (deposit/claim/swap/vote) op een onbedoelde manier. Zoek een pad via:

**Type A — Directe access bugs:**
- External/public functie die geld verstuurt zonder msg.sender check

**Type B — Business logic trucs (gevaarlijker, vaker voorkomend):**
1. Flash loan → manipuleer prijs/reserves/share ratio/votes → drain via legit functie → terugbetalen
2. Cross-function reentrancy → claim() callback → re-enter via deposit() → state mismatch
3. Read-only reentrancy → externe caller leest tijdelijk inconsistente state
4. Rekenfouten → first depositor inflation, share/asset ratio manipulatie, division-before-multiply, decimal mismatch
5. Eerste depositor / donation attack → directe transfer naar contract verandert share price
6. Multi-asset accounting bugs → mismatch tussen interne bookkeeping en werkelijke balans
7. Oracle manipulatie → spot price uit DEX die je in dezelfde tx kan kantelen
8. Slippage/MEV → ontbrekende min-out check → sandwich extractie
9. Approval misbruik → contract houdt user approvals, jij triggert transferFrom in hun naam
10. Initialisatie bug → initialize() zonder access of replayable
11. Signature/permit replay → ontbrekende nonce, cross-chain replay
12. Token quirks → fee-on-transfer, rebase, hook tokens die accounting breken
13. Multi-step chains → 3 functies achter elkaar (deposit → vote → claim) breken een invariant
14. Unchecked .call() return → state divergeert van werkelijkheid

VRAAG JEZELF BIJ ELKE EXTERNAL FUNCTIE: "kan ik via deze functie — alleen of in combinatie met anderen of met een flash loan — funds uit dit contract krijgen die niet van mij zijn?"

DE ENIGE VRAAG: kan een niet-eigenaar via welke truc dan ook funds uit dit contract halen waar hij geen recht op heeft?

==== ANTI-HALLUCINATIE (verplicht) ====
- Entrypoint moet \`external\`/\`public\` zijn. Internal/private niet als entrypoint rapporteren (wel als doorvoer in een chain).
- Functienaam moet LETTERLIJK in de source staan. Verzin niks.
- Source bevat "// TRUNCATED" of functie body niet zichtbaar? Antwoord: {"findings": [], "exploitable": false, "confidence": "LOW", "exploit_description": "INSUFFICIENT_DATA", "exploit_code": null}
- \`onlyOwner\`/\`onlyAdmin\` = directe call beschermd. Maar check WEL of er een indirecte weg bestaat via een andere external functie.

Als je een CONCRETE manier vindt, genereer een Hardhat exploit script (ethers v6, BSC fork) dat:
- Impersonate een willekeurig adres (NIET de owner)
- De exploit uitvoert en winst laat zien
- Console.log toont: stappen + balans voor/na

Antwoord in EXACT dit JSON format (geen markdown, puur JSON):
{
  "findings": ["hoe een niet-eigenaar geld kan stelen"],
  "exploitable": true/false,
  "confidence": "HIGH"/"MEDIUM"/"LOW",
  "exploit_description": "exact wat de aanvaller doet in 2-3 zinnen",
  "exploit_code": "// volledig Hardhat script als exploitable=true, anders null"
}

Als een niet-eigenaar GEEN geld kan stelen: {"findings": [], "exploitable": false, "confidence": "HIGH", "exploit_description": null, "exploit_code": null}

BELANGRIJK: Alleen echte, exploiteerbare bugs. Geen theoretische risico's. Als je niet zeker bent, zet confidence op LOW.`;

    let response = null;
    for (let attempt = 1; attempt <= 3; attempt++) {
      try {
        response = await axios.post('https://api.anthropic.com/v1/messages', {
          model: 'claude-sonnet-4-6',
          max_tokens: 16000,
          thinking: { type: 'enabled', budget_tokens: 10000 },
          messages: [{ role: 'user', content: prompt }]
        }, {
          headers: { 'x-api-key': CLAUDE_API_KEY, 'anthropic-version': '2023-06-01', 'anthropic-beta': 'interleaved-thinking-2025-05-14', 'content-type': 'application/json' },
          timeout: 180000
        });
        break;
      } catch (e) {
        const status = e.response?.status;
        const isRetryable = status === 529 || status === 503 || status === 500 || e.code === 'ECONNABORTED' || e.code === 'ETIMEDOUT';
        if (isRetryable && attempt < 3) {
          const waitTime = attempt * 60000;
          console.log(`[BIZ-LOGIC] API ${status || e.code} — retry ${attempt}/3 in ${waitTime/1000}s...`);
          await new Promise(r => setTimeout(r, waitTime));
        } else { throw e; }
      }
    }

    // Extract text blocks (skip thinking blocks)
    const textBlocks = response.data.content.filter(b => b.type === 'text');
    const aiText = textBlocks.map(b => b.text).join('\n');
    let aiResult;
    try {
      // Probeer JSON te parsen (soms zit er markdown omheen)
      const jsonMatch = aiText.match(/\{[\s\S]*\}/);
      if (!jsonMatch) {
        console.log('[WORKER-BL] Geen JSON in AI response');
        return { findings: [], exploitConfirmed: false };
      }
      aiResult = JSON.parse(jsonMatch[0]);
    } catch (e) {
      console.error('[WORKER-BL] JSON parse fout:', e.message);
      return { findings: [], exploitConfirmed: false };
    }

    if (!aiResult.exploitable || !aiResult.exploit_code) {
      return { findings: aiResult.findings || [], exploitConfirmed: false, confidence: aiResult.confidence };
    }

    // Stap 2: Voer exploit uit op Anvil BSC fork
    console.log(`[WORKER-BL] Exploit gegenereerd (confidence: ${aiResult.confidence}), wordt getest op Anvil fork...`);

    let exploitOutput = '';
    let exploitSuccess = false;
    try {
      exploitOutput = await runOnAnvilFork(address, aiResult.exploit_code);
      exploitSuccess = !exploitOutput.toLowerCase().includes('error') &&
                       !exploitOutput.toLowerCase().includes('revert') &&
                       exploitOutput.length > 10;
      console.log(`[WORKER-BL] Exploit output (${exploitSuccess ? 'SUCCESS' : 'FAILED'}):\n${exploitOutput.substring(0, 500)}`);
    } catch (e) {
      exploitOutput = e.message || '';
      console.log(`[WORKER-BL] Exploit gefaald: ${exploitOutput.substring(0, 300)}`);
      exploitSuccess = false;
    }

    return {
      findings: aiResult.findings || [],
      exploitConfirmed: exploitSuccess,
      confidence: aiResult.confidence,
      description: aiResult.exploit_description,
      exploitOutput: exploitOutput.substring(0, 1000),
      exploitCode: aiResult.exploit_code,
    };

  } catch (err) {
    console.error('[WORKER-BL] Fout:', err.message);
    return { findings: [], exploitConfirmed: false, error: err.message };
  }
}

function formatBusinessLogicReport(address, result, balanceUsd) {
  const conf = result.confidence === 'HIGH' ? '🔴' : result.confidence === 'MEDIUM' ? '🟡' : '⚪';

  let msg = `🧠💀 *BUSINESS LOGIC EXPLOIT BEVESTIGD*\n\n`;
  msg += `━━━━━━━━━━━━━━━━━━━━\n`;
  msg += `📋 *Contract:* \`${address}\`\n`;
  msg += `💰 *Balans:* $${Math.round(balanceUsd).toLocaleString()}\n`;
  msg += `${conf} *Confidence:* ${result.confidence}\n`;
  msg += `━━━━━━━━━━━━━━━━━━━━\n\n`;

  msg += `📝 *Exploit:*\n${result.description || 'Geen beschrijving'}\n\n`;

  if (result.findings && result.findings.length > 0) {
    msg += `🔍 *Findings:*\n`;
    for (const f of result.findings.slice(0, 5)) {
      msg += `• ${f}\n`;
    }
    msg += '\n';
  }

  if (result.exploitOutput) {
    const cleanOutput = result.exploitOutput.substring(0, 400).replace(/[`]/g, "'");
    msg += `📟 *Test Output:*\n\`\`\`\n${cleanOutput}\n\`\`\`\n\n`;
  }

  msg += `━━━━━━━━━━━━━━━━━━━━\n`;
  msg += `⚠️ *Bug Bounty Target*\n`;
  msg += `🔗 [BSCScan](https://bscscan.com/address/${address})\n`;
  msg += `📄 [Source Code](https://bscscan.com/address/${address}#code)`;

  return msg;
}

// === PRE-ANVIL CONFIDENCE SCORE ===
// Berekent per finding een score (0-100) om te bepalen of Anvil test zinvol is.
// Alleen findings met score >= 50 gaan naar Anvil — bespaart tijd en kosten.
function calcAnvilConfidence(finding, { slitherFuncs, securityFuncs, sourceCode, totalUsd, learnedFP }) {
  let score = 0;
  const fn = (finding.function || '').replace(/\(.*/, '').toLowerCase();

  // Factor 1: Slither bevestigt dezelfde functie (+30)
  if (slitherFuncs && slitherFuncs.has(fn)) {
    score += 30;
  }

  // Factor 2: Security check bevestigt dezelfde functie (+15)
  if (securityFuncs && securityFuncs.has(fn)) {
    score += 15;
  }

  // Factor 3: Functie is external/public en GEEN onlyOwner (+20)
  if (sourceCode) {
    const fnPattern = new RegExp(`function\\s+${fn.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*\\(`, 'i');
    const match = sourceCode.match(fnPattern);
    if (match) {
      // Pak de regel rondom de match
      const idx = match.index;
      const context = sourceCode.substring(Math.max(0, idx - 50), Math.min(sourceCode.length, idx + 300));
      const isExternal = /external|public/.test(context);
      const hasOwnerGuard = /onlyOwner|onlyAdmin|onlyRole|require\s*\(\s*msg\.sender\s*==\s*owner/i.test(context);
      if (isExternal && !hasOwnerGuard) score += 20;
      else if (isExternal) score += 5; // external maar met guard: lager
    }
  }

  // Factor 4: Exploit script is aanwezig en niet leeg (+15)
  if (finding.exploit_script && finding.exploit_script.length > 50) {
    score += 15;
  }

  // Factor 5: Hoge balance = meer waard om te testen (+10)
  if (totalUsd >= 10000) score += 10;
  else if (totalUsd >= 1000) score += 5;

  // Factor 6: Eerder bewezen finding patroon (+10) of eerder rejected (-20)
  if (learnedFP) {
    // Check of dit patroon eerder ALTIJD rejected is
    const fpMatch = learnedFP.find(fp => fp.toLowerCase().includes(fn));
    if (fpMatch) score -= 20;
  }

  finding.anvilConfidence = score;
  return score;
}

const ANVIL_CONFIDENCE_THRESHOLD = 50;

// === MAIN: ontvang opdracht van parent process ===
process.on('message', async (msg) => {
  const { address, totalUsd, breakdown } = msg;
  console.log(`[WORKER] Analyse gestart: ${address} ($${totalUsd})`);
  let contractName = null;

  try {
    // 0. Naam-check: skip bekende infra VOORDAT we iets doen
    try {
      const infoUrl = `https://api.etherscan.io/v2/api?chainid=56&module=contract&action=getsourcecode&address=${address}&apikey=${BSCSCAN_KEY}`;
      const infoRes = await axios.get(infoUrl, { timeout: 10000 });
      contractName = infoRes.data.result?.[0]?.ContractName || null;
      const cName = (contractName || '').toLowerCase();
      const SKIP_NAMES = [
        // DEX pairs & pools
        'pancakepair', 'pancakev3pool', 'pancakev3', 'pancakestableswap', 'pancakefactory', 'pancakerouter',
        'pancakeswap', 'pancake', 'nomiswap', 'uniswapv2pair', 'uniswapv3pool', 'uniswap',
        'sushiswap', 'biswap', 'thena', 'apeswap', 'babyswap', 'babypair', 'babyerc20', 'mdex', 'algebrapool',
        'swapflashloan', 'stableswap', 'curverpool', 'liquiditypool',
        // Generieke LP/pair namen
        'lps', 'lp token', 'lptoken', 'v2pair', 'v3pair', 'dexpair',
        // Smart accounts & wallets
        'kernel', 'semimodularaccount', 'simpleaccount', 'lightaccount', 'biconomyaccount',
        'gnosissafe', 'gnosisproxy', 'gnosissafeproxy', 'safeproxy', 'safe',
        'ownbitmultisig', 'ownbitmultisigproxy', 'nervemultisig',
        // Proxies
        'transparentupgradeableproxy', 'transparentproxy', 'erc1967proxy', 'beaconproxy',
        'adminupgradeabilityproxy', 'immutableadminupgradeabilityproxy',
        // Infra
        'masterchef', 'timelock', 'multicall', 'proxyadmin',
        'forwarderv4', 'forwarder', 'layerzero', 'stargate', 'wormhole', 'celer',
        'venuspool', 'vtoken', 'comptroller', 'aavepool', 'lendingpool',
        'dpp', 'dodo', 'dodov2', 'treasury', 'chainlinkfeed', 'pricefeed',
        'superstrategy', 'strategy', 'vault',
      ];
      const SKIP_EXACT = ['account', 'depository', 'pool', 'root', 'asset', 'wallet', 'solver', 'pair', 'factory', 'router'];
      if (SKIP_NAMES.some(s => cName.includes(s)) || SKIP_EXACT.includes(cName)) {
        console.log(`[WORKER] SKIP ${address} - ${cName} (bekende infra)`);
        process.send({ done: true, address, skipped: true });
        return;
      }
      // Extra check: source code bevat DEX pair signatuur (skim + sync + getReserves + swap + mint + burn)
      const src = infoRes.data.result?.[0]?.SourceCode || '';
      if (/function skim\(address/.test(src) && /function sync\(\)/.test(src) && /function getReserves\(/.test(src) && /function swap\(uint/.test(src)) {
        console.log(`[WORKER] SKIP ${address} - ${cName || 'unknown'} (DEX pair detected via source)`);
        process.send({ done: true, address, skipped: true });
        return;
      }
    } catch (e) {}

    // 1. Slither
    const slitherResult = await runSlither(address);
    if (slitherResult.success) {
      await safeSend(formatSlitherReport(address, slitherResult));
    } else {
      console.log(`[WORKER] Slither overgeslagen: ${slitherResult.error?.substring(0, 100)}`);
    }

    // 2. Mythril (alleen als Docker draait — anders skip, Pashov dekt symbolic execution)
    let mythrilResult = { success: false, error: 'Docker niet beschikbaar', issues: [] };
    try {
      execSync('docker info', { timeout: 5000, stdio: 'ignore', env: DOCKER_ENV, windowsHide: true });
      mythrilResult = await runMythril(address);
      if (mythrilResult.success) {
        await safeSend(formatMythrilReport(address, mythrilResult));
      } else {
        console.log(`[WORKER] Mythril overgeslagen: ${mythrilResult.error?.substring(0, 100)}`);
      }
    } catch (e) {
      console.log('[WORKER] Mythril overgeslagen (Docker niet beschikbaar)');
    }

    // 3. Security
    const securityResult = await runSecurityCheck(address);
    if (securityResult.success && securityResult.findings.length > 0) {
      await safeSend(formatSecurityReport(address, securityResult));
    } else if (!securityResult.success) {
      console.log(`[WORKER] Security overgeslagen: ${securityResult.error?.substring(0, 100)}`);
    }

    // 3.5 Foundry on-chain scan
    const foundryResult = await runFoundryScan(address);
    const foundryReport = formatFoundryReport(address, foundryResult);
    if (foundryReport) await safeSend(foundryReport);

    // 3.7 PERMISSIONLESS DRAIN TEST — gratis & deterministisch. KERN: kan een niet-owner geld wegtrekken?
    let drainResult = { tested: false, drains: [] };
    if (securityResult.sourceCode && securityResult.sourceCode.length > 100 && totalUsd >= 500) {
      try {
        const abiRes = await bscScanGet(`https://api.etherscan.io/v2/api?chainid=56&module=contract&action=getabi&address=${address}&apikey=${BSCSCAN_KEY}`);
        if (abiRes.data.status === '1' && abiRes.data.result.startsWith('[')) {
          const abi = JSON.parse(abiRes.data.result);
          const cands = pickDrainCandidates(abi, slitherResult.success ? slitherResult.findings : []);
          const apprCands = pickApprovalCandidates(abi, slitherResult.success ? slitherResult.findings : []);
          let drains = [];
          if (cands.length > 0) {
            console.log(`[DRAIN] ${cands.length} kandidaat-functies testen op fork: ${address}`);
            const out = await runOnAnvilFork(address, buildDrainScript(cands, pickDepositCandidates(abi), DRAIN_TOKENS));
            drains = parseDrains(out);
          }
          if (apprCands.length > 0) {
            console.log(`[DRAIN] ${apprCands.length} approval-kandidaten testen: ${address}`);
            try { const aout = await runOnAnvilFork(address, buildApprovalDrainScript(apprCands)); drains.push(...parseDrains(aout)); } catch (e) { console.error('[DRAIN] approval fout: ' + (e.message || '').slice(0, 80)); }
          }
          {
            drainResult = { tested: cands.length > 0 || apprCands.length > 0, candidates: cands.length + apprCands.length, drains };
            if (drains.length > 0) {
              console.log(`[DRAIN] 🔴 ${drains.length} DRAIN(S) op ${address}: ${drains.map(d => d.fn + '/' + d.token).join(', ')}`);
              let dmsg = `🔴 *PERMISSIONLESS DRAIN BEWEZEN*\n━━━━━━━━━━━━━━━━━━━━\n📝 *${contractName || securityResult.contractName || 'Onbekend'}*\n\`${address}\`\n💰 $${Math.round(totalUsd).toLocaleString()}\n\n_Een niet-owner kan fondsen wegtrekken (bewezen op Anvil-fork):_\n`;
              for (const d of drains.slice(0, 8)) dmsg += `💀 \`${d.fn}()\` → ${d.amount} ${d.token}\n`;
              dmsg += `━━━━━━━━━━━━━━━━━━━━\n🔗 [BscScan](https://bscscan.com/address/${address})`;
              await safeSend(dmsg);
            }
          }
        }
      } catch (e) { console.error(`[DRAIN] fout: ${(e.message || '').substring(0, 120)}`); }
    }

    // 4. Pashov 8-Agent Audit — alleen als Slither/Mythril/Security iets kritisch vond
    const hasVerifiedSource = securityResult.sourceCode && securityResult.sourceCode.length > 100;
    const slitherHighs = slitherResult.success ? slitherResult.findings.filter(f => f.impact === 'High').length : 0;
    const mythrilHighs = mythrilResult.success ? mythrilResult.issues.filter(i => i.severity === 'High').length : 0;
    const securityHighs = securityResult.success ? securityResult.findings.filter(f => f.severity === 'HIGH').length : 0;
    const slitherMeds = slitherResult.success ? slitherResult.findings.filter(f => f.impact === 'Medium').length : 0;
    const mythrilMeds = mythrilResult.success ? mythrilResult.issues.filter(i => i.severity === 'Medium').length : 0;
    const securityMeds = securityResult.success ? securityResult.findings.filter(f => f.severity === 'MEDIUM').length : 0;
    const totalHighs = slitherHighs + mythrilHighs + securityHighs;
    const totalMeds = slitherMeds + mythrilMeds + securityMeds;
    // Trigger op (a) elke HIGH, of (b) high-balance contract met meerdere mediums
    const hasCriticalFindings = totalHighs > 0 || (totalUsd >= 50000 && totalMeds >= 3);
    let pashovResult = null;
    let pashovHasFindings = false;
    let pashovActionableCount = 0; // HIGH/CRITICAL findings die Anvil NIET heeft weerlegd

    // Pashov draait op ELK verified $500+ contract — onafhankelijk van regex-HIGH (meer dekking).
    // hasCriticalFindings hierboven blijft alleen bewaard voor exploit-test triage verderop.
    // DEDUP: sla over als exact dezelfde source al binnen TTL geaudit is (bespaart ~2x credits).
    const curHash = srcHash(securityResult.sourceCode);
    const cachedAudit = pashovAuditedCache[address.toLowerCase()];
    const alreadyAudited = cachedAudit && cachedAudit.hash === curHash && (Date.now() - cachedAudit.ts) < PASHOV_CACHE_TTL;
    if (alreadyAudited) console.log(`[PASHOV] Skip — identieke source al geaudit ${Math.round((Date.now() - cachedAudit.ts) / 3600000)}u geleden (${address})`);
    if (hasVerifiedSource && totalUsd >= 500 && CLAUDE_API_KEY && !alreadyAudited) {
      console.log(`[WORKER] Pashov 8-agent audit gestart: ${address} ($${totalUsd})`);
      try {
        pashovResult = await runPashovAudit(address, securityResult.sourceCode, totalUsd);
        if (pashovResult) {
          markPashovAudited(address, curHash, pashovResult); // cache: identieke source niet opnieuw auditen
          // SELF-VERIFICATION PASS — verifieer elke finding letterlijk in source
          if (pashovResult.findings && pashovResult.findings.length > 0) {
            console.log(`[WORKER] Self-verification van ${pashovResult.findings.length} Pashov findings...`);
            // Bewaar originele findings voor history (incl. false positives)
            const originalFindings = [...pashovResult.findings];
            const verified = await verifyFindings(address, securityResult.sourceCode || '', pashovResult.findings);

            // PRE-ANVIL CONFIDENCE SCORE — filter findings op verwachte Anvil succes
            const slitherFuncsForConf = new Set((slitherResult.success ? slitherResult.findings : []).map(f => {
              const m = (f.description || '').match(/(\w+)\s*\(/); return m ? m[1].toLowerCase() : '';
            }).filter(Boolean));
            const securityFuncsForConf = new Set((securityResult.success ? securityResult.findings : []).map(f => {
              const m = (f.title || '').match(/(\w+)/); return m ? m[1].toLowerCase() : '';
            }).filter(Boolean));
            // Parse learned FP patronen als array
            const learnedFPList = LEARNED_FP_PATTERNS ? LEARNED_FP_PATTERNS.split('\n').filter(l => l.includes('rejected')) : [];

            const highVerified = verified.filter(f => f.severity === 'HIGH' || f.severity === 'CRITICAL');

            // Bereken confidence per finding
            for (const f of highVerified) {
              calcAnvilConfidence(f, {
                slitherFuncs: slitherFuncsForConf,
                securityFuncs: securityFuncsForConf,
                sourceCode: securityResult.sourceCode || '',
                totalUsd,
                learnedFP: learnedFPList
              });
            }

            const worthTesting = highVerified.filter(f => (f.anvilConfidence || 0) >= ANVIL_CONFIDENCE_THRESHOLD);
            const skippedLowConf = highVerified.filter(f => (f.anvilConfidence || 0) < ANVIL_CONFIDENCE_THRESHOLD);

            if (skippedLowConf.length > 0) {
              console.log(`[CONFIDENCE] ${skippedLowConf.length} findings onder drempel (${ANVIL_CONFIDENCE_THRESHOLD}): ${skippedLowConf.map(f => `${f.function}=${f.anvilConfidence}`).join(', ')}`);
              for (const f of skippedLowConf) f.anvilResult = 'SKIPPED_LOW_CONFIDENCE';
            }

            let anvilTested = verified; // bewaar alle verified findings
            if (worthTesting.length > 0) {
              console.log(`[WORKER] Anvil test: ${worthTesting.length}/${highVerified.length} HIGH+ findings (${skippedLowConf.length} overgeslagen wegens lage confidence)`);
              const anvilResults = await testFindingsOnAnvil(address, worthTesting, securityResult.sourceCode || '');
              // Merge anvil results terug in verified lijst
              anvilTested = verified.map(f => {
                const tested = anvilResults.find(a => a.function === f.function && a.description === f.description);
                return tested || f;
              });
            }
            pashovResult.findings = anvilTested;
            pashovResult.verificationPassed = true;
            pashovResult.anvilTested = true;

            // HISTORY: log ALLE originele findings met hun verdict + anvil resultaat
            for (const orig of originalFindings) {
              const matched = anvilTested.find(v =>
                v.function === orig.function && v.description === orig.description
              );
              const findingForLog = matched
                ? { ...orig, verifyVerdict: matched.verifyVerdict || 'CONFIRMED', anvilResult: matched.anvilResult }
                : { ...orig, verifyVerdict: 'FALSE_POSITIVE', anvilResult: null };
              logFinding(address, contractName, findingForLog, findingForLog.anvilResult);
            }
          }

          const highFinds = (pashovResult.findings || []).filter(f => f.severity === 'HIGH');
          const medFinds = (pashovResult.findings || []).filter(f => f.severity === 'MEDIUM');
          pashovHasFindings = (pashovResult.findings || []).length > 0;
          // Strikt: alleen HIGH/CRITICAL findings die Anvil NIET heeft weerlegd tellen als 'echt'
          pashovActionableCount = (pashovResult.findings || []).filter(f =>
            (f.severity === 'HIGH' || f.severity === 'CRITICAL') &&
            !['REJECTED', 'GEN_FAILED', 'ERROR', 'SKIPPED_LOW_CONFIDENCE'].includes(f.anvilResult)
          ).length;

          // Telegram melding met Anvil bewijs status + confidence
          const proven = (pashovResult.findings || []).filter(f => f.anvilResult === 'PROVEN').length;
          const rejected = (pashovResult.findings || []).filter(f => f.anvilResult === 'REJECTED').length;
          const skipped = (pashovResult.findings || []).filter(f => f.anvilResult === 'SKIPPED_LOW_CONFIDENCE').length;
          let pashovMsg = `🏛️ *Pashov 8-Agent Audit*\n━━━━━━━━━━━━━━━━━━━━\n\`${address}\`\n💰 $${Math.round(totalUsd).toLocaleString()}\n`;
          pashovMsg += `⚠️ Risk: *${pashovResult.risk_level || 'UNKNOWN'}*\n`;
          pashovMsg += `🔴 ${highFinds.length} HIGH | 🟡 ${medFinds.length} MEDIUM\n`;
          if (pashovResult.anvilTested) {
            pashovMsg += `⚡ Anvil: ✅ ${proven} BEWEZEN | ❌ ${rejected} weerlegd`;
            if (skipped > 0) pashovMsg += ` | ⏭️ ${skipped} overgeslagen`;
            pashovMsg += `\n`;
          }
          pashovMsg += `━━━━━━━━━━━━━━━━━━━━\n\n`;
          for (const f of (pashovResult.findings || []).slice(0, 8)) {
            const sevIcon = f.severity === 'HIGH' ? '🔴' : f.severity === 'MEDIUM' ? '🟡' : '🟢';
            const confLabel = f.anvilConfidence != null ? ` [${f.anvilConfidence}]` : '';
            const anvilIcon = f.anvilResult === 'PROVEN' ? ' ⚡✅'
              : f.anvilResult === 'REJECTED' ? ' ⚡❌'
              : f.anvilResult === 'SKIPPED_LOW_CONFIDENCE' ? ' ⏭️'
              : f.anvilResult === 'INCONCLUSIVE' ? ' ⚡⚠️' : '';
            pashovMsg += `${sevIcon}${anvilIcon}${confLabel} *[${f.agent}]* ${f.description || ''}\n`;
            if (f.proof) pashovMsg += `   📋 _${f.proof.substring(0, 100)}_\n`;
          }
          if (pashovResult.summary) pashovMsg += `\n📝 ${pashovResult.summary}`;
          // Strikt: alleen melden bij niet-weerlegde HIGH/CRITICAL findings (clean + door Anvil weerlegd = stil)
          if (pashovActionableCount > 0) await safeSend(pashovMsg);

          // Push naar dashboard
          if (SCANNER_API_KEY && RENDER_URL) {
            const pashovPush = { address, contractName: contractName || null, balanceUsd: totalUsd, time: new Date().toISOString(), type: 'pashov', hasCritical: highFinds.length > 0, confidence: pashovResult.risk_level, pashov: pashovResult };
            axios.post(`${RENDER_URL}/api/scanner/ai-results`, { result: pashovPush }, { headers: { 'x-api-key': SCANNER_API_KEY }, timeout: 10000 })
              .catch(e => console.error('[WORKER] Pashov dashboard push fout:', e.message));
          }

          if (!pashovHasFindings) {
            console.log(`[WORKER] Pashov: schoon — skip AI Deep Analyse + Business Logic voor ${address}`);
          }
        }
      } catch (e) {
        console.error(`[WORKER] Pashov audit fout: ${e.message}`);
      }
    }

    let echidnaResult = { success: false, error: 'overgeslagen' };

    // 5. Cross-reference: Pashov + Slither overlap = hoge confidence
    const pashovFuncs = new Set((pashovResult?.findings || []).map(f => (f.function || '').replace(/\(.*/, '').toLowerCase()).filter(Boolean));
    const slitherFuncs = new Set((slitherResult.success ? slitherResult.findings : []).map(f => {
      const m = (f.description || '').match(/(\w+)\s*\(/); return m ? m[1].toLowerCase() : '';
    }).filter(Boolean));
    const crossMatches = [...pashovFuncs].filter(f => slitherFuncs.has(f));
    if (crossMatches.length > 0) {
      console.log(`[WORKER] Cross-reference: ${crossMatches.length} overlap(s) Pashov+Slither: ${crossMatches.join(', ')}`);
      // Mark overlapping findings as high confidence
      if (pashovResult?.findings) {
        for (const f of pashovResult.findings) {
          const fn = (f.function || '').replace(/\(.*/, '').toLowerCase();
          if (crossMatches.includes(fn)) f.crossConfirmed = true;
        }
      }
    }

    // 6. Exploit test — twee fasen: functie-test + Pashov exploit scripts
    const totalCritical = (pashovResult?.findings || []).filter(f => f.severity === 'HIGH' || f.severity === 'CRITICAL').length
      + (slitherResult.success ? slitherResult.findings.filter(f => f.impact === 'High').length : 0)
      + (securityResult.success ? securityResult.findings.filter(f => f.severity === 'HIGH').length : 0);

    const isUnverified = !hasVerifiedSource;

    let exploitTestResult = null;
    if (totalCritical > 0 || (pashovResult?.findings || []).length > 0) {
      // Fase A: Test welke functies aanroepbaar zijn zonder auth
      const testFunctions = new Set(['withdraw', 'emergencyWithdraw', 'claim']);
      if (pashovResult?.findings) {
        for (const f of pashovResult.findings) {
          if (f.function) testFunctions.add(f.function.replace(/\(.*/, ''));
        }
      }
      if (securityResult?.findings) {
        for (const f of securityResult.findings) {
          const m = (f.title || '').match(/(\w+)\(\)/);
          if (m) testFunctions.add(m[1]);
        }
      }
      // Fase 3: ook door Slither geflagde functies gratis op Anvil testen
      if (slitherResult?.success && slitherResult.findings) {
        for (const f of slitherResult.findings) {
          const m = (f.description || '').match(/\.(\w+)\s*\(/) || (f.description || '').match(/(\w+)\s*\(/);
          if (m && m[1].length > 2) testFunctions.add(m[1]);
        }
      }
      const fnList = [...testFunctions];
      console.log(`[WORKER] Exploit test: ${fnList.length} functies + ${(pashovResult?.findings || []).filter(f => f.exploit_script).length} exploit scripts`);
      console.log(`[WORKER] Exploit test: ${fnList.length} functies + scripts`);

      try {
        const abiFragments = fnList.map(fn => `function ${fn}() external`).join("', '");
        const fnListStr = fnList.map(f => `'${f}'`).join(',');
        const output = await runOnAnvilFork(address, `
          console.log('[EXPLOIT-TEST] Fase A: ${fnList.length} functies');
          const contract = new ethers.Contract('${address}', ['${abiFragments}'], provider);
          for (const fn of [${fnListStr}]) {
            try { await contract[fn].staticCall({ from: ethers.ZeroAddress }); console.log('[HIT]', fn, 'aanroepbaar zonder auth!'); }
            catch(e) { console.log('[SAFE]', fn, 'geblokkeerd'); }
          }
        `);
        console.log(output);
        const hits = (output || '').split('\n').filter(l => l.includes('[HIT]')).map(l => l.replace(/.*\[HIT\]\s*/, ''));
        const safes = (output || '').split('\n').filter(l => l.includes('[SAFE]')).map(l => l.replace(/.*\[SAFE\]\s*/, ''));

        // Fase B: Voer Pashov exploit scripts uit met balance tracking
        const exploitResults = [];
        const USDT = '0x55d398326f99059fF775485246999027B3197955';
        const USDC = '0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d';
        for (const finding of (pashovResult?.findings || []).filter(f => f.exploit_script && (f.severity === 'HIGH' || f.severity === 'CRITICAL'))) {
          try {
            console.log(`[EXPLOIT] Running script voor: ${finding.name}`);
            const scriptOutput = await runOnAnvilFork(address, `
              const ADDR = '${address}';
              const ATTACKER = '0x0000000000000000000000000000000000001337';
              const USDT = '${USDT}';
              const USDC = '${USDC}';
              await provider.send('anvil_impersonateAccount', [ATTACKER]);
              await provider.send('anvil_setBalance', [ATTACKER, '0x56BC75E2D63100000']);
              const usdt = new ethers.Contract(USDT, ['function balanceOf(address) view returns (uint256)'], provider);
              const usdc = new ethers.Contract(USDC, ['function balanceOf(address) view returns (uint256)'], provider);
              const contractUsdtBefore = await usdt.balanceOf(ADDR);
              const contractUsdcBefore = await usdc.balanceOf(ADDR);
              console.log('[BAL-VOOR] Contract USDT:', ethers.formatUnits(contractUsdtBefore, 18), 'USDC:', ethers.formatUnits(contractUsdcBefore, 18));
              try {
                ${finding.exploit_script}
                const contractUsdtAfter = await usdt.balanceOf(ADDR);
                const contractUsdcAfter = await usdc.balanceOf(ADDR);
                const lostUsdt = parseFloat(ethers.formatUnits(contractUsdtBefore - contractUsdtAfter, 18));
                const lostUsdc = parseFloat(ethers.formatUnits(contractUsdcBefore - contractUsdcAfter, 18));
                console.log('[BAL-NA] Contract USDT:', ethers.formatUnits(contractUsdtAfter, 18), 'USDC:', ethers.formatUnits(contractUsdcAfter, 18));
                if (lostUsdt > 1 || lostUsdc > 1) console.log('[DRAIN] $' + (lostUsdt + lostUsdc).toFixed(2) + ' verloren uit contract!');
                else console.log('[NO-DRAIN] Geen significant verlies');
              } catch(e) { console.log('[SCRIPT-FAIL]', e.message?.substring(0, 150)); }
            `);
            console.log(scriptOutput);
            const drain = (scriptOutput || '').match(/\[DRAIN\] \$([\d.]+)/);
            const fail = (scriptOutput || '').includes('[SCRIPT-FAIL]') || (scriptOutput || '').includes('[NO-DRAIN]');
            exploitResults.push({
              finding: finding.name,
              drained: drain ? parseFloat(drain[1]) : 0,
              success: !!drain,
              output: (scriptOutput || '').substring(0, 300)
            });
          } catch(e) {
            console.error(`[EXPLOIT] Script fout voor ${finding.name}: ${e.message?.substring(0, 100)}`);
            exploitResults.push({ finding: finding.name, drained: 0, success: false, error: e.message });
          }
        }

        exploitTestResult = { tested: true, hits, safes, totalFindings: totalCritical, functionsTested: fnList, exploitScripts: exploitResults };

        // Telegram melding als een exploit script succesvol was
        const successfulDrains = exploitResults.filter(r => r.success);
        if (successfulDrains.length > 0) {
          let drainMsg = `🔴 *EXPLOIT BEWEZEN OP ANVIL FORK*\n━━━━━━━━━━━━━━━━━━━━\n\`${address}\`\n💰 $${Math.round(totalUsd).toLocaleString()}\n\n`;
          for (const d of successfulDrains) {
            drainMsg += `💀 *${d.finding}* — $${d.drained.toFixed(0)} gedraineerd\n`;
          }
          drainMsg += `━━━━━━━━━━━━━━━━━━━━`;
          await safeSend(drainMsg);
        }

      } catch (e) {
        console.error(`[WORKER] Exploit test fout: ${(e.message || '').substring(0, 300)}`);
        exploitTestResult = { tested: true, error: e.message, totalFindings: totalCritical };
      }
    }

    let businessLogicResult = null;

    // 6. ALLES opslaan + pushen naar dashboard (na alle stappen)
    saveResult(address, totalUsd, breakdown, slitherResult, mythrilResult, securityResult, echidnaResult, {
      pashov: pashovResult,
      foundry: foundryResult || null,
      exploitTest: exploitTestResult,
      businessLogic: businessLogicResult
    });

    // 8. SAMENVATTING naar Telegram
    const pashovFindings = pashovResult?.findings?.length || 0;
    const pashovProven = (pashovResult?.findings || []).filter(f => f.anvilResult === 'PROVEN').length;
    const pashovCross = (pashovResult?.findings || []).filter(f => f.crossConfirmed).length;
    const exploitHits = exploitTestResult?.hits?.length || 0;

    // Fase 3: high-precision Slither-detectoren mogen GRATIS een VERDACHT geven (Pashov-onafhankelijk).
    // reentrancy/unchecked-transfer NIET (te ruizig) — die alleen via Anvil-bevestiging (exploitHits).
    const SLITHER_HIGH_PRECISION = new Set(['suicidal', 'arbitrary-send-eth', 'arbitrary-send-erc20', 'arbitrary-send-erc20-permit', 'unprotected-upgrade', 'controlled-delegatecall', 'tx-origin', 'weak-prng']);
    const slitherActionable = (slitherResult.success ? slitherResult.findings : []).filter(f =>
      (f.impact === 'High' || f.impact === 'Medium') && SLITHER_HIGH_PRECISION.has(f.check)).length;

    const drainProven = (drainResult.drains || []).length > 0;
    let verdict = '🟢 SAFE';
    if (drainProven || pashovProven > 0 || exploitHits > 0) verdict = '🔴 EXPLOITABLE'; // drain = niet-owner trekt geld weg (gratis bewezen)
    else if (pashovActionableCount > 0 || slitherActionable > 0) verdict = '🟡 VERDACHT'; // Pashov-finding OF high-precision Slither (gratis)

    // Fase 4: log elke Slither-finding + Anvil-uitkomst naar dataset (bouwt gelabelde data voor later FP-model)
    if (slitherResult.success && (slitherResult.findings || []).length > 0) {
      try {
        const hitFns = new Set((exploitTestResult?.hits || []).map(h => (String(h).match(/(\w+)/) || [])[1]));
        const lines = slitherResult.findings.map(f => {
          const fn = ((f.description || '').match(/\.(\w+)\s*\(/) || [])[1] || null;
          return JSON.stringify({ ts: Date.now(), address, contractName, check: f.check, impact: f.impact, confidence: f.confidence, fn, anvilHit: fn ? hitFns.has(fn) : false, verdict, balanceUsd: Math.round(totalUsd) });
        }).join('\n') + '\n';
        fs.appendFileSync(path.join(__dirname, 'slither_dataset.jsonl'), lines);
      } catch (e) {}
    }

    // Samenvatting alleen sturen als VERDACHT of EXPLOITABLE — SAFE contracten niet melden
    if (verdict !== '🟢 SAFE') {
      let summary = `📋 *ANALYSE SAMENVATTING*\n━━━━━━━━━━━━━━━━━━━━\n`;
      summary += `📝 *${contractName || 'Onbekend'}*${isUnverified ? ' 🔒 UNVERIFIED' : ''}\n\`${address}\`\n💰 $${Math.round(totalUsd).toLocaleString()}\n\n`;
      summary += `${verdict}\n`;
      if (!pashovResult && slitherActionable > 0) summary += `_ℹ️ Gratis statische detectie (Slither) — geen AI-audit_\n`;
      summary += `\n`;
      const slActChecks = [...new Set((slitherResult.success ? slitherResult.findings : []).filter(f => SLITHER_HIGH_PRECISION.has(f.check)).map(f => f.check))];
      summary += `🔬 Slither: ${slitherResult.success ? ((slitherResult.findings || []).filter(f => f.impact === 'High').length + ' HIGH' + (slActChecks.length ? ' ⚠️ ' + slActChecks.join(', ') : '')) : 'n/a'}\n`;
      summary += `🛡️ Security: ${securityResult.success ? securityResult.findings.filter(f => f.severity === 'HIGH').length + ' HIGH' : 'n/a'}\n`;
      summary += `🏛️ Pashov: ${pashovResult ? (pashovFindings + ' findings, ' + pashovProven + ' bewezen') : 'geen source'}\n`;
      if (pashovCross > 0) summary += `🔗 Cross-ref: ${pashovCross} bevestigd door Slither\n`;
      summary += `⚡ Exploit test: ${exploitTestResult ? (exploitHits + ' hits / ' + (exploitTestResult.safes?.length || 0) + ' safe') : 'geen findings'}\n`;
      summary += `💧 Drain-test: ${drainResult.tested ? (drainProven ? '🔴 ' + drainResult.drains.length + ' DRAIN (' + drainResult.drains.map(d => d.fn).join(', ') + ')' : drainResult.candidates + ' functies, geen drain') : 'n.v.t.'}\n`;
      summary += `━━━━━━━━━━━━━━━━━━━━`;
      await safeSend(summary);
    } else {
      console.log(`[WORKER] ${address} — SAFE, geen Telegram melding`);
    }

    console.log(`[WORKER] Analyse klaar: ${address}`);
    process.send({ done: true, address });
  } catch (err) {
    console.error(`[WORKER] Fout: ${err.message}`);
    process.send({ done: true, address, error: err.message });
  }
});

// === PASHOV 8-AGENT AUDIT ===
// === PER-FINDING ANVIL EXPLOIT TEST ===
// Voor elke Pashov finding: AI genereert een gericht exploit script
// dat exact die ene bug probeert uit te buiten op een Anvil fork
async function generateAnvilTestForFinding(address, finding, sourceCode) {
  if (!CLAUDE_API_KEY) return null;

  try {
    // Korte source: alleen de functie waar de finding op slaat
    const stripped = stripBoilerplate(sourceCode);
    const trimmed = stripped.length > 30000 ? stripped.substring(0, 30000) : stripped;

    const prompt = `Je bent een exploit developer. Schrijf een JavaScript exploit script dat één specifieke bug in een BSC contract probeert uit te buiten op een Anvil fork.

CONTRACT: ${address}
FINDING:
- Functie: ${finding.function || '?'}
- Severity: ${finding.severity || '?'}
- Beschrijving: ${finding.description || ''}
- Code citaat: ${finding.proof || finding.verifyQuote || ''}

SOURCE (relevante delen):
\`\`\`solidity
${trimmed}
\`\`\`

==== BESCHIKBARE HELPERS (al gedefinieerd in scope) ====
- \`provider\` — ethers.JsonRpcProvider naar Anvil
- \`TARGET\` — het contract adres als string
- \`ethers\` — ethers v6
- \`impersonate(addr)\` → returns ethers.JsonRpcSigner
- \`setBalance(addr, ethAmount)\` → geeft adres ETH (bv. setBalance('0xabc', '100'))
- \`fund(addr)\` → geeft adres 100 ETH

==== JOUW TAAK ====
Schrijf alleen de body code (geen async wrapper, dat zit er al om heen). Het script moet:
1. Een fake aanvaller adres maken (bv. '0x1111111111111111111111111111111111111111')
2. Hem funden met fund()
3. De vulnerable functie aanroepen via die signer
4. Vergelijken: contract balance VOOR vs NA
5. Console.log met 'EXPLOIT_PROVEN' als balans naar omlaag is gegaan, anders 'EXPLOIT_FAILED'

==== OUTPUT REGELS ====
- Output ALLEEN het JavaScript code blok, geen markdown, geen uitleg
- Gebruik staticCall waar mogelijk om gas te besparen
- Wrap alles in try/catch
- Max 30 regels code
- Als het contract balance niet kan worden gemeten via standaard ERC20 (bv. internal accounting), check dan of de functie zonder revert kan worden aangeroepen — dat is ook bewijs

Begin DIRECT met je code (geen \`\`\`):`;

    const response = await axios.post('https://api.anthropic.com/v1/messages', {
      model: 'claude-sonnet-4-6',
      max_tokens: 1500,
      messages: [{ role: 'user', content: prompt }]
    }, {
      headers: { 'x-api-key': CLAUDE_API_KEY, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' },
      timeout: 60000
    });

    const text = response.data.content.filter(b => b.type === 'text').map(b => b.text).join('\n');
    // Strip markdown code blocks
    let code = text.replace(/^```(?:javascript|js)?\n?/m, '').replace(/```$/m, '').trim();
    return code;
  } catch (e) {
    console.error('[ANVIL-GEN] Fout:', e.message);
    return null;
  }
}

// Test alle findings één voor één op Anvil
async function testFindingsOnAnvil(address, findings, sourceCode) {
  if (!findings || findings.length === 0) return findings;

  const tested = [];
  let proven = 0, failed = 0, errored = 0;

  for (let i = 0; i < findings.length; i++) {
    const f = findings[i];
    if (f.verifyVerdict === 'FALSE_POSITIVE') {
      tested.push(f);
      continue;
    }

    console.log(`[ANVIL-TEST] Finding ${i + 1}/${findings.length}: ${f.function || '?'}`);
    try {
      const exploitCode = await generateAnvilTestForFinding(address, f, sourceCode);
      if (!exploitCode) {
        f.anvilResult = 'GEN_FAILED';
        tested.push(f);
        errored++;
        continue;
      }

      const output = await runOnAnvilFork(address, exploitCode);

      if (output.includes('EXPLOIT_PROVEN')) {
        f.anvilResult = 'PROVEN';
        f.anvilOutput = output.substring(0, 500);
        proven++;
        console.log(`[ANVIL-TEST] ✅ PROVEN: ${f.function}`);
      } else if (output.includes('EXPLOIT_FAILED')) {
        f.anvilResult = 'REJECTED';
        f.anvilOutput = output.substring(0, 500);
        failed++;
        console.log(`[ANVIL-TEST] ❌ REJECTED: ${f.function}`);
      } else {
        f.anvilResult = 'INCONCLUSIVE';
        f.anvilOutput = output.substring(0, 500);
        errored++;
        console.log(`[ANVIL-TEST] ⚠️ INCONCLUSIVE: ${f.function}`);
      }
      tested.push(f);
    } catch (e) {
      f.anvilResult = 'ERROR';
      f.anvilError = e.message;
      tested.push(f);
      errored++;
      console.error(`[ANVIL-TEST] Fout: ${e.message}`);
    }
  }

  console.log(`[ANVIL-TEST] Klaar: ${proven} PROVEN, ${failed} REJECTED, ${errored} INCONCLUSIVE`);
  return tested;
}

// === HISTORICAL ACCURACY TRACKING ===
// Logt elke finding met verify verdict en Anvil resultaat
// Bestand: findings_history.jsonl (append-only, één finding per regel)
const HISTORY_FILE = path.join(__dirname, 'findings_history.jsonl');

function logFinding(address, contractName, finding, anvilResult = null) {
  try {
    const entry = {
      ts: Date.now(),
      date: new Date().toISOString(),
      address,
      contractName: contractName || 'unknown',
      agent: finding.agent || finding.category || 'unknown',
      category: finding.category || 'unknown',
      severity: finding.severity || 'unknown',
      function: finding.function || '?',
      visibility: finding.visibility || '?',
      description: (finding.description || '').substring(0, 200),
      verifyVerdict: finding.verifyVerdict || 'NOT_VERIFIED', // CONFIRMED/FALSE_POSITIVE/UNCERTAIN
      anvilResult, // null/CONFIRMED/REJECTED/UNTESTED
      anvilConfidence: finding.anvilConfidence || null, // pre-anvil confidence score
      crossConfirmed: finding.crossConfirmed || false,
    };
    fs.appendFileSync(HISTORY_FILE, JSON.stringify(entry) + '\n');
  } catch (e) {
    console.error('[HISTORY] Log fout:', e.message);
  }
}

// Aggregeer historische stats over X dagen
function getHistoryStats(daysBack = 7) {
  try {
    if (!fs.existsSync(HISTORY_FILE)) return null;
    const cutoff = Date.now() - (daysBack * 24 * 60 * 60 * 1000);
    const lines = fs.readFileSync(HISTORY_FILE, 'utf-8').split('\n').filter(Boolean);
    const entries = [];
    for (const line of lines) {
      try {
        const e = JSON.parse(line);
        if (e.ts >= cutoff) entries.push(e);
      } catch (err) {}
    }

    const byAgent = {};
    const bySeverity = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 };
    const byVerdict = { CONFIRMED: 0, FALSE_POSITIVE: 0, UNCERTAIN: 0, NOT_VERIFIED: 0 };
    const byAnvil = { CONFIRMED: 0, REJECTED: 0, UNTESTED: 0, null: 0 };

    for (const e of entries) {
      const agent = e.agent || 'unknown';
      if (!byAgent[agent]) byAgent[agent] = { total: 0, confirmed: 0, false: 0 };
      byAgent[agent].total++;
      if (e.verifyVerdict === 'CONFIRMED') byAgent[agent].confirmed++;
      if (e.verifyVerdict === 'FALSE_POSITIVE') byAgent[agent].false++;

      bySeverity[e.severity || 'UNKNOWN'] = (bySeverity[e.severity || 'UNKNOWN'] || 0) + 1;
      byVerdict[e.verifyVerdict || 'NOT_VERIFIED'] = (byVerdict[e.verifyVerdict || 'NOT_VERIFIED'] || 0) + 1;
      byAnvil[e.anvilResult || 'null'] = (byAnvil[e.anvilResult || 'null'] || 0) + 1;
    }

    return {
      daysBack,
      total: entries.length,
      byAgent,
      bySeverity,
      byVerdict,
      byAnvil,
      accuracyRate: entries.length > 0
        ? Math.round((byVerdict.CONFIRMED / entries.length) * 100)
        : 0,
    };
  } catch (e) {
    console.error('[HISTORY] Stats fout:', e.message);
    return null;
  }
}

// === SELF-VERIFICATION PASS ===
// Stuur findings TERUG naar AI met letterlijke source — vraag verificatie van elke finding
// Verwijdert findings die niet bewezen kunnen worden met code citaat
async function verifyFindings(address, sourceCode, findings) {
  if (!CLAUDE_API_KEY || !findings || findings.length === 0) return findings;

  try {
    const stripped = stripBoilerplate(sourceCode);
    const trimmedSource = stripped.length > 60000 ? stripped.substring(0, 60000) + '\n// ... [TRUNCATED]' : stripped;

    const findingsList = findings.map((f, i) => {
      return `[${i}] AGENT=${f.agent || '?'} | SEV=${f.severity || '?'} | FUNC=${f.function || '?'} | VIS=${f.visibility || '?'}\n     DESC: ${f.description || ''}\n     PROOF: ${f.proof || '(geen)'}`;
    }).join('\n\n');

    const prompt = `Je bent een ULTRA-SCEPTISCHE security auditor. Je job is false positives ELIMINEREN. Historisch wordt 71% van "CONFIRMED" findings toch weerlegd op Anvil — je moet strenger zijn.

\`\`\`solidity
${trimmedSource}
\`\`\`

== FINDINGS ==
${findingsList}

== PER FINDING: beantwoord AL DEZE 5 vragen. Als één antwoord NEE is → FALSE_POSITIVE ==
1. Bestaat functie LETTERLIJK in source met EXACT die naam?
2. Is het external/public? (internal/private → FALSE_POSITIVE)
3. Heeft het GEEN access control? (onlyOwner, onlyAdmin, onlyRole, require(msg.sender==...), initializer → FALSE_POSITIVE)
4. Gaan funds naar een AANVALLER-CONTROLLED adres (msg.sender of aanvaller parameter)?
   - Funds naar een VAST/hardcoded adres → FALSE_POSITIVE (dat is by design)
   - Funds naar address(0) of burn → FALSE_POSITIVE
   - Funds naar owner/admin → FALSE_POSITIVE (dat is rugpull, niet exploit)
5. Levert het NETTO WINST op? (als aanvaller eerst moet storten om te claimen → FALSE_POSITIVE tenzij hij meer terugkrijgt)

== EXTRA FALSE POSITIVE REGELS ==
- skim() op DEX pairs: stuurt verschil naar TO parameter, maar reserves worden NIET verminderd → geen echte drain
- claim/harvest met msg.sender: stuurt alleen OWN rewards, geen andermans geld
- initialize() die al gecalled is → FALSE_POSITIVE (kan maar 1x)
- Functies die bestaan maar REVERT bij aanroep door niet-eigenaar → FALSE_POSITIVE
- Flash loan aanvallen die alleen werken met externe liquiditeit → FALSE_POSITIVE

== VERDICTS ==
- CONFIRMED = aanvaller stuurt geld naar EIGEN wallet, je hebt de EXACTE code flow getracet van input→transfer→msg.sender
- FALSE_POSITIVE = alles wat niet 100% zeker CONFIRMED is
- STANDAARD = FALSE_POSITIVE. Alleen bij onweerlegbaar bewijs → CONFIRMED.

Antwoord ALLEEN met JSON, geen markdown backticks:
{"verified":[{"index":0,"verdict":"CONFIRMED","reason":"exacte code flow: functie X op lijn Y stuurt via Z naar msg.sender"}]}`;

    const response = await axios.post('https://api.anthropic.com/v1/messages', {
      model: 'claude-sonnet-4-6',
      max_tokens: 4000,
      messages: [{ role: 'user', content: prompt }]
    }, {
      headers: { 'x-api-key': CLAUDE_API_KEY, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' },
      timeout: 180000
    });

    const text = response.data.content.filter(b => b.type === 'text').map(b => b.text).join('\n');
    // Robuuste JSON extractie
    let parsed = null;
    // Poging 1: markdown code block (meest voorkomend)
    const codeMatch = text.match(/```(?:json)?\s*(\{[\s\S]*?"verified"[\s\S]*?\})\s*```/);
    if (codeMatch) try { parsed = JSON.parse(codeMatch[1]); } catch(e) {}
    // Poging 2: strip alle backticks en probeer opnieuw
    if (!parsed) {
      const clean = text.replace(/```json\s*/g, '').replace(/```/g, '').trim();
      const jsonStart = clean.indexOf('{"verified"');
      if (jsonStart >= 0) {
        let depth = 0;
        for (let i = jsonStart; i < clean.length; i++) {
          if (clean[i] === '{') depth++;
          else if (clean[i] === '}') { depth--; if (depth === 0) { try { parsed = JSON.parse(clean.substring(jsonStart, i + 1)); } catch(e) {} break; } }
        }
      }
    }
    if (!parsed) {
      console.log('[VERIFY] Kon geen verificatie JSON parsen, behoud alle findings');
      console.log('[VERIFY] Response start:', text.substring(0, 300));
      return findings;
    }
    const verifications = parsed.verified || [];

    // Map terug naar originele findings, voeg verdict toe
    const result = [];
    let confirmedCount = 0, falseCount = 0, uncertainCount = 0;
    for (let i = 0; i < findings.length; i++) {
      const v = verifications.find(x => x.index === i);
      if (!v || v.verdict === 'FALSE_POSITIVE') {
        falseCount++;
        continue; // weg ermee
      }
      if (v.verdict === 'CONFIRMED') confirmedCount++;
      else uncertainCount++;
      result.push({
        ...findings[i],
        verifyVerdict: v.verdict,
        verifyReason: v.reason,
        verifyQuote: v.code_quote,
      });
    }

    console.log(`[VERIFY] ${findings.length} → ${result.length} | CONFIRMED=${confirmedCount}, UNCERTAIN=${uncertainCount}, FALSE=${falseCount}`);
    return result;
  } catch (e) {
    console.error(`[VERIFY] Fout: ${e.message} — behoud alle findings`);
    return findings;
  }
}

async function runPashovAudit(address, sourceCode, balanceUsd) {
  if (!CLAUDE_API_KEY) return null;
  if (process.env.PASHOV_DISABLED === '1') { console.log('[PASHOV] Disabled via env — overslaan'); return null; }

  try {
    const stripped = stripBoilerplate(sourceCode);
    const trimmedSource = stripped.length > 70000 ? stripped.substring(0, 70000) + '\n// ... [TRUNCATED]' : stripped;
    const vectorSection = ATTACK_VECTORS ? ATTACK_VECTORS.substring(0, 3000) : '';
    // Fetch cross-contract dependencies zodat AI cross-contract bugs kan vinden
    const depsSection = await fetchDependencyContracts(sourceCode, address);

    const prompt = `Je bent een elite smart contract security auditor. Er zit $${Math.round(balanceUsd)} in dit BSC contract.

Contract: ${address}

\`\`\`solidity
${trimmedSource}
\`\`\`
${vectorSection ? '\n## BEKENDE ATTACK VECTORS:\n' + vectorSection : ''}
${depsSection}

## STAP 1: IDENTIFICEER CONTRACT TYPE
Bepaal eerst: is dit een staking, lending, vault, token, game, bridge, DEX, of ander type contract?

## STAP 2: GERICHTE AANVAL PER TYPE
**Staking/Rewards:** claim→unstake→restake→claim loop, reward inflatie zonder deposit, state update na transfer (CEI), dubbele claim via memory copy
**Vault/Pool:** first-depositor attack (1 wei + donatie), share ratio manipulatie, emergency withdraw > normaal
**Token:** onbeschermde mint/burn, fee bypass, approval misbruik, permit replay
**Lending:** oracle manipulatie, liquidatie bonus > schuld, collateral inflate
**Bridge/Proxy:** initialize front-run, storage collision, delegatecall naar user adres
**Generiek:** reentrancy (CEI), missing access control op external functies, tx.origin, ongevalideerde parameters (to/beneficiary)

## STAP 3: VOOR ELKE EXTERNAL/PUBLIC FUNCTIE
Vraag: "Als ik een random wallet ben (NIET owner), en ik roep deze functie aan — kan ik er geld mee verdienen?"

## STAP 4: FUNCTIE-PAREN
Vraag: "Als ik functie A aanroep en daarna B — kan ik dan meer terugkrijgen dan ik erin stopte?"

## OUTPUT — Begin DIRECT met { (geen markdown, geen backticks)
{
  "contract_type": "staking|lending|vault|token|game|bridge|dex|other",
  "findings": [
    {
      "name": "korte naam",
      "severity": "CRITICAL|HIGH",
      "function": "exacte functie naam uit source",
      "description": "wat is het probleem + hoe misbruiken",
      "exploit_script": "// Ethers.js script dat de exploit uitvoert op een Anvil fork\\nconst attacker = await provider.getSigner(ATTACKER);\\nconst contract = new ethers.Contract(ADDR, ABI, attacker);\\n// stap 1: ...\\n// stap 2: ...",
      "expected_profit": "$XXX — uitleg hoe berekend",
      "proof": "LETTERLIJK code citaat uit source"
    }
  ],
  "summary": "JA/NEE — kan een niet-eigenaar funds stelen? 1-2 zinnen",
  "risk_level": "CRITICAL|HIGH|MEDIUM|LOW|SAFE"
}

== REGELS ==
- ALLEEN external/public functies als entrypoint
- Functienaam MOET letterlijk in source staan — verzin niks
- proof = LETTERLIJK citaat uit source code hierboven
- exploit_script = WERKBAAR ethers.js script (geen pseudocode)
- Bij "TRUNCATED": risk_level = "INSUFFICIENT_DATA", findings = []
- Het gaat ALLEEN om: kan een BUITENSTAANDER funds **NAAR ZICHZELF** stelen?

== VERPLICHTE WINST-UITLEG (overtreding = finding wordt weggegooid) ==
Voor ELKE finding moet je beantwoorden:
1. **Naar welk adres** gaan de funds? msg.sender? Een hardcoded adres? Een parameter?
2. **Hoeveel USD** verdient de aanvaller? Bereken exact op basis van contract balance.
3. **Via welke wallet** komt het geld binnen bij de aanvaller?
Als je vraag 1-3 NIET kunt beantwoorden → NIET rapporteren. "Functie is aanroepbaar" is GEEN finding. "Aanvaller roept X aan en ontvangt $Y op zijn wallet" IS een finding.
Alleen rapporteren als severity HIGH of CRITICAL — MEDIUM en LOW findings worden genegeerd.

== NIET RAPPORTEREN (FALSE POSITIVE PATRONEN) ==
- Owner-only functies (rugpull = ander type, niet 'aanvaller drain')
- Gas issues, MEV/slippage, flash loans, theoretische bugs
- **Deposit/proxy/sweep contracten**: als een functie ETH/tokens stuurt naar een VAST adres (cold wallet, treasury, hardcoded address) en NIET naar msg.sender of een user-controlled parameter → dit is BY DESIGN permissionless. dump(), sweep(), flush() etc. zijn typische sweep functies bij exchanges. NIET rapporteren tenzij de bestemming manipuleerbaar is.
- **Permissionless functies die alleen de eigenaar helpen**: als iedereen een functie mag callen maar de output altijd naar een vast adres gaat → geen exploit. De aanvaller betaalt gas om iemand anders te helpen.
- **Reentrancy die naar een vast adres stuurt**: als een reentrancy-keten funds naar het cold address stuurt ipv naar de aanvaller → geen exploit.
- Functies die afhangen van external contracts waarvan de code NIET beschikbaar is → INSUFFICIENT_DATA, geen CRITICAL
${LEARNED_FP_PATTERNS}
Begin DIRECT met {`;

    console.log(`[PASHOV] Audit gestart voor ${address} | source: ${trimmedSource.length} chars`);

    // === STAP 1: Sonnet (goedkoop) als eerste filter ===
    async function callClaude(model, thinkingBudget) {
      let response = null;
      for (let attempt = 1; attempt <= 3; attempt++) {
        try {
          response = await axios.post('https://api.anthropic.com/v1/messages', {
            model,
            max_tokens: 8000,
            thinking: { type: 'enabled', budget_tokens: thinkingBudget },
            messages: [{ role: 'user', content: prompt }]
          }, {
            headers: { 'x-api-key': CLAUDE_API_KEY, 'anthropic-version': '2023-06-01', 'anthropic-beta': 'interleaved-thinking-2025-05-14', 'content-type': 'application/json' },
            timeout: 600000
          });
          break;
        } catch (e) {
          const status = e.response?.status;
          const isRetryable = status === 529 || status === 503 || status === 500 || e.code === 'ECONNABORTED' || e.code === 'ETIMEDOUT';
          if (isRetryable && attempt < 3) {
            const waitTime = attempt * 60000;
            console.log(`[PASHOV] API ${status || e.code} — retry ${attempt}/3 in ${waitTime/1000}s...`);
            await new Promise(r => setTimeout(r, waitTime));
          } else {
            throw e;
          }
        }
      }
      const textBlocks = response.data.content.filter(b => b.type === 'text');
      const aiText = textBlocks.map(b => b.text).join('\n');
      let result = null;
      const jsonStart = aiText.indexOf('{"findings"');
      if (jsonStart >= 0) {
        let depth = 0;
        for (let i = jsonStart; i < aiText.length; i++) {
          if (aiText[i] === '{') depth++;
          if (aiText[i] === '}') depth--;
          if (depth === 0) {
            try { result = JSON.parse(aiText.substring(jsonStart, i + 1)); } catch(e) {}
            break;
          }
        }
      }
      if (!result) {
        const m = aiText.match(/\{[\s\S]*"findings"[\s\S]*\}/);
        if (m) try { result = JSON.parse(m[0]); } catch(e) {}
      }
      return result;
    }

    // Sonnet eerst
    console.log(`[PASHOV] Sonnet scan...`);
    const sonnetResult = await callClaude('claude-sonnet-4-6', 5000);
    if (!sonnetResult) {
      console.log('[PASHOV] Sonnet: geen JSON gevonden');
      return null;
    }

    const sonnetFindings = (sonnetResult.findings || []).filter(f => f.severity === 'HIGH' || f.severity === 'CRITICAL');
    console.log(`[PASHOV] Sonnet: ${sonnetResult.findings?.length || 0} findings (${sonnetFindings.length} HIGH/CRITICAL) | Risk: ${sonnetResult.risk_level}`);

    // === STAP 2: Opus alleen als Sonnet HIGH/CRITICAL heeft gevonden ===
    if (sonnetFindings.length > 0) {
      console.log(`[PASHOV] 🔴 Sonnet vond ${sonnetFindings.length} HIGH/CRITICAL — Opus bevestiging starten...`);
      const opusResult = await callClaude('claude-opus-4-6', 10000);
      if (opusResult) {
        opusResult._model = 'opus';
        opusResult._sonnetFindings = sonnetFindings.length;
        console.log(`[PASHOV] Opus: ${opusResult.findings?.length || 0} findings | Risk: ${opusResult.risk_level}`);
        return opusResult;
      }
      console.log('[PASHOV] Opus faalde, val terug op Sonnet resultaat');
    }

    sonnetResult._model = 'sonnet';
    return sonnetResult;
  } catch (err) {
    console.error('[PASHOV] Fout:', err.response?.status, JSON.stringify(err.response?.data?.error || err.message));
    return null;
  }
}

// Exporteer kernfuncties voor de backtest-harness (alleen actief bij require, niet als worker)
if (require.main !== module) {
  module.exports = { runPashovAudit, verifyFindings, runSecurityCheck, testFindingsOnAnvil, runOnAnvilFork, runSlither };
}

console.log('[WORKER] Analyse worker gestart, wacht op opdrachten...');
