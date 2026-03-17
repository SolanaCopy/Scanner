require('dotenv').config();
const { ethers } = require('ethers');
const TelegramBot = require('node-telegram-bot-api');
const axios = require('axios');
const { execSync, fork } = require('child_process');
const fs = require('fs');
const path = require('path');

const SLITHER_PATH = 'C:/Users/moham/AppData/Local/Python/pythoncore-3.14-64/Scripts/slither.exe';
const SOLC_PATH = 'C:/Users/moham/AppData/Local/Python/pythoncore-3.14-64/Scripts/solc.exe';
const MYTHRIL_PATH = 'C:/Users/moham/AppData/Local/Programs/Python/Python311/Scripts/myth.exe';

// === CONFIG ===
const TELEGRAM_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const CHAT_ID = process.env.TELEGRAM_CHAT_ID;
const BSCSCAN_KEY = process.env.BSCSCAN_API_KEY;
const CLAUDE_API_KEY = process.env.CLAUDE_API_KEY || '';
const MIN_BALANCE_USD = parseFloat(process.env.MIN_BALANCE_USD) || 10000;
const BSC_RPC = process.env.BSC_RPC || 'https://bsc-dataseed1.binance.org';
const STATUS_INTERVAL = 5 * 60 * 1000; // 5 minuten
const RENDER_URL = process.env.RENDER_URL || '';
const SCANNER_API_KEY = process.env.SCANNER_API_KEY || '';

// === HEARTBEAT ===
async function sendHeartbeat() {
  if (!RENDER_URL) return;
  try {
    await axios.post(`${RENDER_URL}/api/scanner/heartbeat`, {
      blocks: blocksScanned,
      contracts: contractsFound,
      balance10k: contractsWithBalance,
      alerts: alertsSent,
      liveBlocks: liveBlocksScanned,
      workers: activeWorkers.size
    }, { headers: { 'X-API-Key': SCANNER_API_KEY }, timeout: 5000 });
  } catch (e) {
    // stil falen
  }
}

// === STABLECOIN ADRESSEN (BSC) ===
const STABLECOINS = [
  { name: 'USDT', address: '0x55d398326f99059fF775485246999027B3197955', decimals: 18 },
  { name: 'USDC', address: '0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d', decimals: 18 },
  { name: 'BUSD', address: '0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56', decimals: 18 },
];

const ERC20_ABI = ['function balanceOf(address) view returns (uint256)'];

// Bekende contracten uitsluiten (stablecoins, DEX routers, bridges, infra etc.)
const SKIP_ADDRESSES = new Set([
  // === STABLECOINS ===
  '0x55d398326f99059fF775485246999027B3197955'.toLowerCase(), // USDT
  '0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d'.toLowerCase(), // USDC
  '0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56'.toLowerCase(), // BUSD
  '0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c'.toLowerCase(), // WBNB
  '0x2170Ed0880ac9A755fd29B2688956BD959F933F8'.toLowerCase(), // ETH (BSC)
  '0x7130d2A12B9BCbFAe4f2634d864A1Ee1Ce3Ead9c'.toLowerCase(), // BTCB
  '0x1AF3F329e8BE154074D8769D1FFa4eE058B1DBc3'.toLowerCase(), // DAI
  '0x1D2F0da169ceB9fC7B3144628dB156f3F6c60dBE'.toLowerCase(), // BEP20 XRP
  // === DEX ROUTERS ===
  '0x10ED43C718714eb63d5aA57B78B54704E256024E'.toLowerCase(), // PancakeSwap Router v2
  '0x13f4EA83D0bd40E75C8222255bc855a974568Dd4'.toLowerCase(), // PancakeSwap Router v3
  '0x1111111254EEB25477B68fb85Ed929f73A960582'.toLowerCase(), // 1inch Router
  '0xEfF92A263d31888d860bD50809A8D171709b7b1c'.toLowerCase(), // PancakeSwap SmartRouter
  '0x556B9306565093C855AEA9AE92A594704c2Cd59e'.toLowerCase(), // PancakeSwap MasterChef v3
  // === PANCAKESWAP INFRA ===
  '0x0BFbCF9fa4f9C56B0F40a671Ad40E0805A091865'.toLowerCase(), // PancakeSwap Factory v2
  '0xcA143Ce32Fe78f1f7019d7d551a6402fC5350c73'.toLowerCase(), // PancakeSwap Factory
  '0xD62Af4601E91eC2E64632D64793C888Fb1c83879'.toLowerCase(), // PancakePair (uit scan)
  // === BRIDGES ===
  '0xB685760EBD368a891F27ae547391F4E2A289895b'.toLowerCase(), // Bridgers (uit scan)
  '0xC38e4e6A15593f908255214653d3D947CA1c2338'.toLowerCase(), // MayanSwift (uit scan)
  '0x35b85A4938C6b139803763325fCc379D495647E1'.toLowerCase(), // Bridge (uit scan)
  // === LENDING / DEFI INFRA ===
  '0xc55B409014480C4580A7Df71f4BB08CE20fb8935'.toLowerCase(), // AToken Aave (uit scan)
  '0xfD36E2c2a6789Db23113685031d7F16329158384'.toLowerCase(), // Venus vUSDT
  '0x95c78222B3D6e262dCeD25E0746d30f3f2E2B0E0'.toLowerCase(), // Venus Comptroller
  '0xecA88125a5ADbe82614ffC12D0DB554E2e2867C8'.toLowerCase(), // Venus vUSDC
  // === ACCOUNT ABSTRACTION ===
  '0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789'.toLowerCase(), // EntryPoint v0.6 (uit scan)
  // === PROXIES (standaard, geen echte bugs) ===
  '0x8599068597fd27D87514CB90c42300c03a474084'.toLowerCase(), // ERC1967Proxy (uit scan)
  '0x99F008922815f3C32ee33E894478931e2B43F655'.toLowerCase(), // ERC1967Proxy (uit scan)
  '0x8599068597fd27D87514CB90c42300c03a474084'.toLowerCase(), // ERC1967Proxy
  '0x39E66eE6b2ddaf4DEfDEd3038E0162180dbeF340'.toLowerCase(), // ERC1967Proxy (uit scan)
  '0xC05617bc2490CB57a8db163b5551bb7E532695e3'.toLowerCase(), // TransparentProxy (uit scan)
  '0x408bE6cF2284452AFE506C1b95E846A56065cc43'.toLowerCase(), // TransparentProxy (uit scan)
  // === BSC SYSTEM ===
  '0x0000000000000000000000000000000000001000'.toLowerCase(), // BSCValidatorSet
  '0x0000000000000000000000000000000000001001'.toLowerCase(), // SystemReward
  '0x0000000000000000000000000000000000001002'.toLowerCase(), // SlashIndicator
  '0x0000000000000000000000000000000000001003'.toLowerCase(), // TokenHub
  '0x0000000000000000000000000000000000001004'.toLowerCase(), // RelayerIncentivize
  '0x0000000000000000000000000000000000001005'.toLowerCase(), // RelayerHub
  '0x0000000000000000000000000000000000001006'.toLowerCase(), // GovHub
  '0x0000000000000000000000000000000000001007'.toLowerCase(), // TokenManager
  '0x0000000000000000000000000000000000001008'.toLowerCase(), // CrossChain
  '0x0000000000000000000000000000000000002000'.toLowerCase(), // Staking
  '0x0000000000000000000000000000000000002001'.toLowerCase(), // StakeHub
  // === EXCHANGE TREASURIES ===
  '0xcEF2dD45Da08b37fB1c2f441d33c2eBb424866A4'.toLowerCase(), // ApolloxExchangeTreasury (uit scan)
  '0xad2EAE16157002a97E11b4201D111e6cd4C977ca'.toLowerCase(), // Groot contract (uit scan)
  '0x0B54637d1F9Ed1F86Dd349dF47395dB0A2a2Ed3F'.toLowerCase(), // Groot contract (uit scan)
  '0xcFe66D6c615500Fb0E567D9BaBdC6E3cDcd23634'.toLowerCase(), // Groot contract (uit scan)
  '0x53d3564E06F20f89119ed6B654AB2D4f010A2b2B'.toLowerCase(), // $2M contract (uit scan)
]);

// === INIT ===
const provider = new ethers.JsonRpcProvider(BSC_RPC);
const bot = new TelegramBot(TELEGRAM_TOKEN, { polling: true });

// Stablecoin contract instances
const stablecoinContracts = STABLECOINS.map(s => ({
  ...s,
  contract: new ethers.Contract(s.address, ERC20_ABI, provider)
}));

let bnbPriceUsd = 0;
let blocksScanned = 0;
let contractsFound = 0;
let contractsWithBalance = 0;
let verifiedContracts = 0;
let alertsSent = 0;
let scanning = true;
let startTime = Date.now();
let startBlock = 0;
let currentBlockNum = 0;
let historyScanActive = false;
let historyScanProgress = '';
let liveBlocksScanned = 0;

// Worker tracking (max 2 gelijktijdig)
const MAX_WORKERS = 2;
const activeWorkers = new Set();
const analyzingAddresses = new Set();
let currentScanBlock = 0; // global zodat saveState altijd werkt

// Lijst van gevonden contracten (max 50 bijhouden)
const recentContracts = [];
const MAX_RECENT = 50;

// Cache van al gecheckte adressen (voorkomt dubbel werk)
const checkedAddresses = new Set();

// Lijst van alerts (matches)
const recentAlerts = [];
const MAX_ALERTS = 20;

// === STATE SAVE/RESUME ===
const STATE_FILE = path.join(__dirname, 'scanner_state.json');
const CHECKED_FILE = path.join(__dirname, 'checked_addresses.json');
const RESULTS_FILE = path.join(__dirname, 'scan_results.json');

// Analyse resultaten opslaan
function saveResult(address, balanceUsd, breakdown, slither, mythril, security) {
  let results = [];
  try {
    if (fs.existsSync(RESULTS_FILE)) {
      results = JSON.parse(fs.readFileSync(RESULTS_FILE, 'utf-8'));
    }
  } catch (e) {}

  const slitherHighMed = slither.success ? slither.findings.filter(f => f.impact === 'High' || f.impact === 'Medium') : [];
  const mythrilHighMed = mythril.success ? mythril.issues.filter(i => i.severity === 'High' || i.severity === 'Medium') : [];
  const securityHigh = security.success ? security.findings.filter(f => f.severity === 'HIGH') : [];

  const totalHigh = (slither.success ? slither.findings.filter(f => f.impact === 'High').length : 0)
    + (mythril.success ? mythril.issues.filter(i => i.severity === 'High').length : 0)
    + securityHigh.length;
  const totalMedium = (slither.success ? slither.findings.filter(f => f.impact === 'Medium').length : 0)
    + (mythril.success ? mythril.issues.filter(i => i.severity === 'Medium').length : 0)
    + (security.success ? security.findings.filter(f => f.severity === 'MEDIUM').length : 0);

  results.push({
    address,
    contractName: slither.contractName || mythril.contractName || security.contractName || 'Onbekend',
    balanceUsd,
    breakdown,
    time: new Date().toISOString(),
    totalHigh,
    totalMedium,
    slither: {
      success: slither.success,
      high: slither.success ? slither.findings.filter(f => f.impact === 'High').length : 0,
      medium: slither.success ? slither.findings.filter(f => f.impact === 'Medium').length : 0,
      findings: slitherHighMed.map(f => ({ check: f.check, impact: f.impact, description: (f.description || '').substring(0, 200) }))
    },
    mythril: {
      success: mythril.success,
      high: mythril.success ? mythril.issues.filter(i => i.severity === 'High').length : 0,
      medium: mythril.success ? mythril.issues.filter(i => i.severity === 'Medium').length : 0,
      issues: mythrilHighMed.map(i => ({ title: i.title, severity: i.severity, swcId: i.swcId, function: i.function }))
    },
    security: {
      success: security.success,
      findings: security.success ? security.findings.map(f => ({ category: f.category, severity: f.severity, title: f.title, detail: f.detail })) : []
    }
  });

  try {
    fs.writeFileSync(RESULTS_FILE, JSON.stringify(results, null, 2));
  } catch (e) {
    console.error('[RESULTS] Save fout:', e.message);
  }
}

function saveState() {
  const state = {
    scanBlock: currentScanBlock,
    blocksScanned,
    contractsFound,
    contractsWithBalance,
    verifiedContracts,
    alertsSent,
    recentAlerts: recentAlerts.slice(0, MAX_ALERTS),
    savedAt: new Date().toISOString()
  };
  try {
    fs.writeFileSync(STATE_FILE, JSON.stringify(state, null, 2));
    // Sla ook gecheckte adressen op
    fs.writeFileSync(CHECKED_FILE, JSON.stringify([...checkedAddresses]));
  } catch (e) {
    console.error('[STATE] Save fout:', e.message);
  }
}

function loadState() {
  try {
    if (fs.existsSync(STATE_FILE)) {
      const state = JSON.parse(fs.readFileSync(STATE_FILE, 'utf-8'));
      console.log(`[STATE] Hervat vanaf block ${state.scanBlock} (opgeslagen ${state.savedAt})`);
      // Laad gecheckte adressen (altijd lowercase voor consistente dedup)
      if (fs.existsSync(CHECKED_FILE)) {
        const addrs = JSON.parse(fs.readFileSync(CHECKED_FILE, 'utf-8'));
        addrs.forEach(a => checkedAddresses.add(a.toLowerCase()));
        console.log(`[STATE] ${checkedAddresses.size} gecheckte adressen geladen`);
      }
      return state;
    }
  } catch (e) {
    console.error('[STATE] Load fout:', e.message);
  }
  return null;
}

// === HELPERS ===
async function safeSend(text, opts = {}) {
  try {
    await bot.sendMessage(CHAT_ID, text, { parse_mode: 'Markdown', disable_web_page_preview: true, ...opts });
  } catch (err) {
    // Markdown parsing mislukt → stuur zonder formatting
    console.error('[TELEGRAM] Markdown fout, retry als plain text:', err.message);
    try {
      await bot.sendMessage(CHAT_ID, text.replace(/[*_`\[\]]/g, ''), { disable_web_page_preview: true });
    } catch (err2) {
      console.error('[TELEGRAM] Plain text ook mislukt:', err2.message);
    }
  }
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function uptime() {
  const ms = Date.now() - startTime;
  const sec = Math.floor(ms / 1000) % 60;
  const min = Math.floor(ms / 60000) % 60;
  const hrs = Math.floor(ms / 3600000);
  return `${hrs}u ${min}m ${sec}s`;
}

function shortAddr(addr) {
  return addr.slice(0, 6) + '...' + addr.slice(-4);
}

function formatDuration(ms) {
  const sec = Math.floor(ms / 1000) % 60;
  const min = Math.floor(ms / 60000) % 60;
  const hrs = Math.floor(ms / 3600000) % 24;
  const days = Math.floor(ms / 86400000);
  if (days > 0) return `${days}d ${hrs}u ${min}m`;
  if (hrs > 0) return `${hrs}u ${min}m ${sec}s`;
  return `${min}m ${sec}s`;
}

function blocksToTime(blocks) {
  return formatDuration(blocks * 3000); // ~3 sec per block
}

function parseTimeArg(arg) {
  const match = arg.match(/^(\d+)(m|h|d|w|y)$/i);
  if (!match) return null;
  const num = parseInt(match[1]);
  const unit = match[2].toLowerCase();
  const blocksPerSec = 1 / 3; // BSC ~1 block per 3 sec
  switch (unit) {
    case 'm': return Math.floor(num * 60 * blocksPerSec);
    case 'h': return Math.floor(num * 3600 * blocksPerSec);
    case 'd': return Math.floor(num * 86400 * blocksPerSec);
    case 'w': return Math.floor(num * 7 * 86400 * blocksPerSec);
    case 'y': return Math.floor(num * 365 * 86400 * blocksPerSec);
    default: return null;
  }
}

// === BNB PRIJS OPHALEN ===
async function updateBnbPrice() {
  try {
    const res = await axios.get('https://api.coingecko.com/api/v3/simple/price?ids=binancecoin&vs_currencies=usd');
    bnbPriceUsd = res.data.binancecoin.usd;
    console.log(`[PRIJS] BNB = $${bnbPriceUsd}`);
  } catch (err) {
    console.error('[PRIJS] Fout bij ophalen BNB prijs:', err.message);
    if (bnbPriceUsd === 0) bnbPriceUsd = 600;
  }
}

// === CHECK TOTALE BALANCE (BNB + STABLECOINS) ===
async function getTotalBalance(address) {
  let totalUsd = 0;
  let breakdown = {};

  // BNB balance
  try {
    const bnbBal = await provider.getBalance(address);
    const bnb = parseFloat(ethers.formatEther(bnbBal));
    const bnbUsd = bnb * bnbPriceUsd;
    if (bnbUsd > 0) {
      totalUsd += bnbUsd;
      breakdown.BNB = { amount: bnb, usd: bnbUsd };
    }
  } catch (err) {}

  // Stablecoin balances
  for (const sc of stablecoinContracts) {
    try {
      const bal = await sc.contract.balanceOf(address);
      const amount = parseFloat(ethers.formatUnits(bal, sc.decimals));
      if (amount > 0) {
        totalUsd += amount; // Stablecoins = ~$1
        breakdown[sc.name] = { amount, usd: amount };
      }
    } catch (err) {}
  }

  return { totalUsd, breakdown };
}

// === CHECK OF CONTRACT EEN PROXY IS ===
async function isProxy(address) {
  try {
    const code = await provider.getCode(address);
    // Proxy contracten hebben korte bytecode (< 200 bytes)
    // EIP-1167 minimal proxy: begint met 0x363d3d373d3d3d363d73
    // EIP-1967 proxy: korte delegatecall bytecode
    if (code.length < 200) return true;
    if (code.includes('363d3d373d3d3d363d73')) return true; // EIP-1167 clone
    if (code.includes('5460206000396000f3')) return true; // another proxy pattern
    return false;
  } catch (err) {
    return false;
  }
}

// === SLITHER ANALYSE ===
async function runSlither(address) {
  try {
    // Source code ophalen van BSCScan
    const url = `https://api.etherscan.io/v2/api?chainid=56&module=contract&action=getsourcecode&address=${address}&apikey=${BSCSCAN_KEY}`;
    const res = await axios.get(url);

    if (res.data.status !== '1' || !res.data.result[0].SourceCode) {
      return { success: false, error: 'Source code niet beschikbaar' };
    }

    const contract = res.data.result[0];
    const contractName = contract.ContractName || 'Contract';
    const compilerVersion = contract.CompilerVersion || '';
    let sourceCode = contract.SourceCode;

    // Temp directory aanmaken
    const tmpDir = path.join(__dirname, 'tmp_slither', address);
    fs.mkdirSync(tmpDir, { recursive: true });

    // Check of het multi-file source is (begint met {{ )
    if (sourceCode.startsWith('{{')) {
      // Multi-file format
      try {
        const parsed = JSON.parse(sourceCode.slice(1, -1));
        const sources = parsed.sources || parsed;
        for (const [filePath, fileData] of Object.entries(sources)) {
          const fullPath = path.join(tmpDir, filePath);
          fs.mkdirSync(path.dirname(fullPath), { recursive: true });
          fs.writeFileSync(fullPath, fileData.content || fileData);
        }
      } catch (e) {
        // Fallback: schrijf als enkel bestand
        fs.writeFileSync(path.join(tmpDir, `${contractName}.sol`), sourceCode);
      }
    } else {
      fs.writeFileSync(path.join(tmpDir, `${contractName}.sol`), sourceCode);
    }

    // Solc versie bepalen
    const versionMatch = compilerVersion.match(/v?(\d+\.\d+\.\d+)/);
    let solcVersion = '0.8.20';
    if (versionMatch) {
      solcVersion = versionMatch[1];
      // Installeer benodigde versie
      try {
        execSync(`C:/Users/moham/AppData/Local/Python/pythoncore-3.14-64/Scripts/solc-select install ${solcVersion}`, { timeout: 30000 });
        execSync(`C:/Users/moham/AppData/Local/Python/pythoncore-3.14-64/Scripts/solc-select use ${solcVersion}`, { timeout: 10000 });
      } catch (e) {
        // Gebruik fallback versie
      }
    }

    // Slither draaien
    let output = '';
    try {
      output = execSync(`"${SLITHER_PATH}" "${tmpDir}" --json -`, {
        timeout: 120000,
        encoding: 'utf-8',
        env: { ...process.env, PATH: process.env.PATH + ';C:/Users/moham/AppData/Local/Python/pythoncore-3.14-64/Scripts' }
      });
    } catch (e) {
      // Slither geeft exit code 1 als er findings zijn, dat is normaal
      output = e.stdout || e.stderr || '';
    }

    // Cleanup
    fs.rmSync(tmpDir, { recursive: true, force: true });

    // Parse resultaten
    let findings = [];
    try {
      const json = JSON.parse(output);
      if (json.results && json.results.detectors) {
        findings = json.results.detectors.map(d => ({
          check: d.check,
          impact: d.impact,
          confidence: d.confidence,
          description: d.description
        }));
      }
    } catch (e) {
      // Als JSON parsing faalt, probeer tekst output
      if (output.includes('detector')) {
        return { success: true, findings: [], raw: output.substring(0, 2000), contractName, compilerVersion };
      }
      return { success: false, error: 'Slither output kon niet geparsed worden', raw: output.substring(0, 500) };
    }

    return { success: true, findings, contractName, compilerVersion };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

// Format Slither resultaten voor Telegram
function formatSlitherReport(address, result) {
  if (!result.success) {
    const safeError = result.error.replace(/[`*_\[\]()~>#+=|{}.!\\-]/g, ' ').substring(0, 300);
    return `❌ *Slither Analyse Mislukt*\n\nContract:\n\`${address}\`\n\nFout: ${safeError}`;
  }

  const findings = result.findings;
  const contractName = result.contractName || 'Onbekend';

  // Tel per impact level
  const high = findings.filter(f => f.impact === 'High').length;
  const medium = findings.filter(f => f.impact === 'Medium').length;
  const low = findings.filter(f => f.impact === 'Low').length;
  const info = findings.filter(f => f.impact === 'Informational' || f.impact === 'Optimization').length;

  let riskLevel = '🟢 LAAG RISICO';
  if (high > 0) riskLevel = '🔴 HOOG RISICO';
  else if (medium > 0) riskLevel = '🟡 MEDIUM RISICO';

  let msg = `🔬 *Slither Analyse*

━━━━━━━━━━━━━━━━━━━━
📋 *Contract:* ${contractName}
\`${address}\`
${riskLevel}
━━━━━━━━━━━━━━━━━━━━

📊 *Gevonden Issues:*
🔴 High: *${high}*
🟡 Medium: *${medium}*
🟢 Low: *${low}*
ℹ️ Info: *${info}*
`;

  // Top findings tonen (max 5)
  const important = findings.filter(f => f.impact === 'High' || f.impact === 'Medium').slice(0, 5);
  if (important.length > 0) {
    msg += `\n⚠️ *Belangrijkste Issues:*\n`;
    for (const f of important) {
      const icon = f.impact === 'High' ? '🔴' : '🟡';
      const desc = f.description.substring(0, 150).replace(/[`*_]/g, '');
      msg += `${icon} *${f.check}*\n   ${desc}\n\n`;
    }
  }

  msg += `━━━━━━━━━━━━━━━━━━━━
🔗 [BSCScan](https://bscscan.com/address/${address})
⏰ ${new Date().toLocaleString('nl-NL')}`;

  return msg;
}

// === MYTHRIL ANALYSE ===
async function runMythril(address) {
  try {
    // Source code ophalen van BSCScan
    const url = `https://api.etherscan.io/v2/api?chainid=56&module=contract&action=getsourcecode&address=${address}&apikey=${BSCSCAN_KEY}`;
    const res = await axios.get(url);

    if (res.data.status !== '1' || !res.data.result[0].SourceCode) {
      return { success: false, error: 'Source code niet beschikbaar' };
    }

    const contract = res.data.result[0];
    const contractName = contract.ContractName || 'Contract';
    const compilerVersion = contract.CompilerVersion || '';
    let sourceCode = contract.SourceCode;

    // Temp directory aanmaken
    const tmpDir = path.join(__dirname, 'tmp_mythril', address);
    fs.mkdirSync(tmpDir, { recursive: true });

    // Flatten alle bestanden tot 1 bestand (voorkomt import issues)
    let mainFile = path.join(tmpDir, `${contractName}.sol`);
    if (sourceCode.startsWith('{{')) {
      try {
        const parsed = JSON.parse(sourceCode.slice(1, -1));
        const sources = parsed.sources || parsed;
        const files = Object.keys(sources);

        // Bouw dependency graph op basis van imports
        const imports = {};
        for (const f of files) {
          const content = sources[f].content || sources[f];
          imports[f] = [];
          for (const line of content.split('\n')) {
            const m = line.trim().match(/^import\s+.*["'](.+?)["']/);
            if (m) {
              const imp = m[1];
              // Resolve relatief pad naar absoluut
              let resolved = imp;
              if (imp.startsWith('.')) {
                const dir = f.substring(0, f.lastIndexOf('/'));
                const parts = (dir + '/' + imp).split('/');
                const normalized = [];
                for (const p of parts) {
                  if (p === '..') normalized.pop();
                  else if (p !== '.') normalized.push(p);
                }
                resolved = normalized.join('/');
              }
              const match = files.find(k => k === resolved) || files.find(k => k === imp) || files.find(k => k.endsWith(resolved));
              if (match && !imports[f].includes(match)) imports[f].push(match);
            }
          }
        }

        // Topologische sort (dependencies eerst)
        const ordered = [];
        const visited = new Set();
        function visit(f) {
          if (visited.has(f)) return;
          visited.add(f);
          for (const dep of (imports[f] || [])) visit(dep);
          ordered.push(f);
        }
        for (const f of files) visit(f);

        // Flatten: combineer in juiste volgorde
        let flatCode = '';
        let licenseAdded = false;
        let pragmaAdded = false;

        for (const filePath of ordered) {
          const content = sources[filePath].content || sources[filePath];
          const lines = content.split('\n');
          for (const line of lines) {
            const trimmed = line.trim();
            if (trimmed.startsWith('import ')) continue;
            if (trimmed.startsWith('// SPDX-License')) {
              if (licenseAdded) continue;
              licenseAdded = true;
            }
            if (trimmed.startsWith('pragma solidity')) {
              if (pragmaAdded) continue;
              pragmaAdded = true;
            }
            flatCode += line + '\n';
          }
        }

        fs.writeFileSync(mainFile, flatCode);
      } catch (e) {
        fs.writeFileSync(mainFile, sourceCode);
      }
    } else {
      fs.writeFileSync(mainFile, sourceCode);
    }

    // Solc versie bepalen
    const versionMatch = compilerVersion.match(/v?(\d+\.\d+\.\d+)/);
    let solcVersion = '0.8.20';
    if (versionMatch) {
      solcVersion = versionMatch[1];
      try {
        execSync(`C:/Users/moham/AppData/Local/Python/pythoncore-3.14-64/Scripts/solc-select install ${solcVersion}`, { timeout: 30000 });
        execSync(`C:/Users/moham/AppData/Local/Python/pythoncore-3.14-64/Scripts/solc-select use ${solcVersion}`, { timeout: 10000 });
      } catch (e) {}
    }

    // Mythril draaien - gebruik Windows pad format
    const winPath = mainFile.replace(/\//g, '\\');
    let output = '';
    const solcBinary = SOLC_PATH.replace(/\//g, '\\');
    const mythrilEnv = { ...process.env, PYTHONIOENCODING: 'utf-8', PYTHONUTF8: '1', SOLC_BINARY: solcBinary, PATH: process.env.PATH + ';C:/Users/moham/AppData/Local/Python/pythoncore-3.14-64/Scripts' };

    // Eerst zonder --via-ir proberen, als dat faalt met "stack too deep" dan met --via-ir
    for (const solcArgs of ['', ' --solc-args "--via-ir --optimize"']) {
      const cmd = `"${MYTHRIL_PATH}" analyze "${winPath}" --solv ${solcVersion} -o json --execution-timeout 120${solcArgs}`;
      console.log(`[MYTHRIL] CMD: ${cmd}`);
      try {
        output = execSync(cmd, {
          timeout: 300000,
          encoding: 'utf-8',
          cwd: tmpDir,
          env: mythrilEnv
        });
        break; // Gelukt, stop retry
      } catch (e) {
        output = e.stdout || e.stderr || '';
        output = output.replace(/[^\x20-\x7E\n\r\t{}[\]:,"]/g, '');
        console.log(`[MYTHRIL] Error output: ${output.substring(0, 500)}`);
        // Alleen retry met --via-ir als "stack too deep" error
        if (!solcArgs && output.toLowerCase().includes('stack too deep')) {
          console.log('[MYTHRIL] Stack too deep - retry met --via-ir...');
          continue;
        }
        break;
      }
    }

    // Cleanup (met delay want Mythril kan bestanden nog vasthouden)
    setTimeout(() => {
      try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch(e) {}
    }, 5000);

    // Parse resultaten
    let issues = [];
    try {
      if (!output || !output.trim()) {
        return { success: false, error: 'Mythril gaf geen output (compilatie mislukt?)', contractName, compilerVersion };
      }
      // Output kan "INFO: Could not find files..." bevatten voor de JSON
      const jsonStart = output.indexOf('{');
      if (jsonStart < 0) {
        return { success: false, error: output.substring(0, 200), contractName, compilerVersion };
      }
      if (jsonStart > 0) output = output.substring(jsonStart);
      const json = JSON.parse(output);
      if (json.success && json.issues) {
        issues = json.issues.map(i => ({
          title: i.title,
          severity: i.severity,
          swcId: i['swc-id'],
          description: i.description,
          function: i.function,
          lineno: i.lineno,
          code: i.code
        }));
      } else if (json.error) {
        // Zoek de echte error regel (niet ^^ of lege regels)
        const errLines = json.error.trim().split('\n');
        const meaningful = errLines.find(l => {
          const t = l.trim();
          return t.length > 5 && !t.match(/^[\s\^|~]+$/) && !t.startsWith('File') && !t.startsWith('-->');
        }) || errLines[0];
        // Bekende errors vertalen
        let shortErr = meaningful.trim().substring(0, 200);
        if (json.error.includes('Stack too deep')) shortErr = 'Contract te complex (stack too deep)';
        else if (json.error.includes('not contain a compilable')) shortErr = 'Contract niet compileerbaar (te oude Solidity versie?)';
        else if (json.error.includes('CompilerError')) shortErr = 'Compilatie fout: ' + shortErr;
        return { success: false, error: shortErr, contractName, compilerVersion };
      }
    } catch (e) {
      // Probeer error uit output te halen
      const errLines = output.trim().split('\n');
      const meaningful = errLines.find(l => l.trim().length > 5 && !l.trim().match(/^[\s\^|~]+$/)) || errLines[0];
      return { success: false, error: meaningful.trim().substring(0, 200) || 'Mythril output kon niet geparsed worden' };
    }

    return { success: true, issues, contractName, compilerVersion };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

// Format Mythril resultaten voor Telegram
function formatMythrilReport(address, result) {
  if (!result.success) {
    // Escape Markdown speciale tekens in error message
    const safeError = result.error.replace(/[`*_\[\]()~>#+=|{}.!\\-]/g, ' ').substring(0, 300);
    return `❌ *Mythril Analyse Mislukt*\n\nContract:\n\`${address}\`\n\nFout: ${safeError}`;
  }

  const issues = result.issues;
  const contractName = result.contractName || 'Onbekend';

  const high = issues.filter(i => i.severity === 'High').length;
  const medium = issues.filter(i => i.severity === 'Medium').length;
  const low = issues.filter(i => i.severity === 'Low').length;

  let riskLevel = '🟢 LAAG RISICO';
  if (high > 0) riskLevel = '🔴 HOOG RISICO';
  else if (medium > 0) riskLevel = '🟡 MEDIUM RISICO';

  let msg = `🔮 *Mythril Deep Analyse*

━━━━━━━━━━━━━━━━━━━━
📋 *Contract:* ${contractName}
\`${address}\`
${riskLevel}
━━━━━━━━━━━━━━━━━━━━

📊 *Gevonden Vulnerabilities:*
🔴 High: *${high}*
🟡 Medium: *${medium}*
🟢 Low: *${low}*
`;

  if (issues.length === 0) {
    msg += `\n✅ Geen kwetsbaarheden gevonden!\n`;
  }

  // Top issues tonen (max 5)
  const important = issues.filter(i => i.severity === 'High' || i.severity === 'Medium').slice(0, 5);
  if (important.length > 0) {
    msg += `\n⚠️ *Belangrijkste Vulnerabilities:*\n`;
    for (const i of important) {
      const icon = i.severity === 'High' ? '🔴' : '🟡';
      const swc = i.swcId ? ` (SWC-${i.swcId})` : '';
      const desc = i.description.substring(0, 200).replace(/[`*_]/g, '');
      const func = i.function ? `\n   📍 Functie: ${i.function}` : '';
      const code = i.code ? `\n   📝 \`${i.code.substring(0, 80)}\`` : '';
      msg += `${icon} *${i.title}*${swc}${func}${code}\n   ${desc}\n\n`;
    }
  }

  msg += `━━━━━━━━━━━━━━━━━━━━
🔗 [BSCScan](https://bscscan.com/address/${address})
⏰ ${new Date().toLocaleString('nl-NL')}`;

  return msg;
}

// === CHECK OF CONTRACT VERIFIED IS ===
async function isVerified(address) {
  try {
    const url = `https://api.etherscan.io/v2/api?chainid=56&module=contract&action=getabi&address=${address}&apikey=${BSCSCAN_KEY}`;
    const res = await axios.get(url);
    return res.data.status === '1';
  } catch (err) {
    return false;
  }
}

// === TELEGRAM COMMANDO'S ===
bot.onText(/\/start$/, async (msg) => {
  if (msg.chat.id.toString() !== CHAT_ID) return;
  scanning = true;
  await bot.sendMessage(CHAT_ID, `🟢 *BSC Scanner is ACTIEF*

━━━━━━━━━━━━━━━━━━━━
⚙️ *Instellingen:*
• Min balance: *$${MIN_BALANCE_USD.toLocaleString()}*
• Filter: Verified ✅ + Balance 💰
• BNB prijs: *$${bnbPriceUsd.toFixed(0)}*
━━━━━━━━━━━━━━━━━━━━

📡 Ik scan nu elke nieuwe block op BSC...
Gebruik /help voor alle commando's`, { parse_mode: 'Markdown' });
});

bot.onText(/\/stop/, async (msg) => {
  if (msg.chat.id.toString() !== CHAT_ID) return;
  scanning = false;
  historyScanActive = false;
  await bot.sendMessage(CHAT_ID, `🔴 *Scanner GEPAUZEERD*

Gebruik /start om weer te beginnen.`, { parse_mode: 'Markdown' });
});

bot.onText(/\/status/, async (msg) => {
  if (msg.chat.id.toString() !== CHAT_ID) return;
  await sendStatusReport();
});

bot.onText(/\/lijst/, async (msg) => {
  if (msg.chat.id.toString() !== CHAT_ID) return;
  await sendContractList();
});

bot.onText(/\/alerts/, async (msg) => {
  if (msg.chat.id.toString() !== CHAT_ID) return;
  await sendAlertList();
});

bot.onText(/\/scan (.+)/, async (msg, match) => {
  if (msg.chat.id.toString() !== CHAT_ID) return;
  const arg = match[1].trim();
  const blocksBack = parseTimeArg(arg);

  if (!blocksBack) {
    await bot.sendMessage(CHAT_ID, `❌ Ongeldig formaat. Gebruik bijv:
/scan 30m - laatste 30 minuten
/scan 1h - laatste uur
/scan 6h - laatste 6 uur
/scan 1d - laatste dag
/scan 2w - laatste 2 weken
/scan 1y - laatste jaar`, { parse_mode: 'Markdown' });
    return;
  }

  if (historyScanActive) {
    await bot.sendMessage(CHAT_ID, `⏳ Er loopt al een history scan. Wacht tot die klaar is of gebruik /stop om te annuleren.`, { parse_mode: 'Markdown' });
    return;
  }

  // Start history scan
  startHistoryScan(blocksBack, arg);
});

bot.onText(/\/check/, async (msg) => {
  if (msg.chat.id.toString() !== CHAT_ID) return;
  const addrMatch = msg.text.match(/0x[a-fA-F0-9]{40}/);
  if (!addrMatch) {
    await bot.sendMessage(CHAT_ID, '❌ Geen geldig adres gevonden.\n\nGebruik: `/check 0x1234...`\nOf plak het adres op een nieuwe regel.', { parse_mode: 'Markdown' });
    return;
  }
  const address = addrMatch[0];

  await bot.sendMessage(CHAT_ID, `🔬 *Slither analyse gestart...*\n\n\`${address}\`\n\n⏳ Dit kan 1-2 minuten duren.`, { parse_mode: 'Markdown' });

  const result = await runSlither(address);
  const report = formatSlitherReport(address, result);

  await bot.sendMessage(CHAT_ID, report, { parse_mode: 'Markdown', disable_web_page_preview: true });
});

bot.onText(/\/mythril/, async (msg) => {
  if (msg.chat.id.toString() !== CHAT_ID) return;
  // Zoek 0x adres overal in het bericht (ook op nieuwe regel)
  const addrMatch = msg.text.match(/0x[a-fA-F0-9]{40}/);
  if (!addrMatch) {
    await bot.sendMessage(CHAT_ID, '❌ Geen geldig adres gevonden.\n\nGebruik: `/mythril 0x1234...`\nOf plak het adres op een nieuwe regel.', { parse_mode: 'Markdown' });
    return;
  }
  const address = addrMatch[0];

  await bot.sendMessage(CHAT_ID, `🔮 *Mythril deep analyse gestart...*\n\n\`${address}\`\n\n⏳ Dit kan 2-5 minuten duren (symbolische executie).`, { parse_mode: 'Markdown' });

  const result = await runMythril(address);
  const report = formatMythrilReport(address, result);

  await bot.sendMessage(CHAT_ID, report, { parse_mode: 'Markdown', disable_web_page_preview: true });
});

bot.onText(/\/security/, async (msg) => {
  if (msg.chat.id.toString() !== CHAT_ID) return;
  const addrMatch = msg.text.match(/0x[a-fA-F0-9]{40}/);
  if (!addrMatch) {
    await bot.sendMessage(CHAT_ID, '❌ Geen geldig adres.\n\nGebruik: `/security 0x1234...`', { parse_mode: 'Markdown' });
    return;
  }
  const address = addrMatch[0];

  await bot.sendMessage(CHAT_ID, `🛡️ *Security check gestart...*\n\`${address}\`\n⏳ Even geduld...`, { parse_mode: 'Markdown' });

  const result = await runSecurityCheck(address);
  const report = formatSecurityReport(address, result);
  await bot.sendMessage(CHAT_ID, report, { parse_mode: 'Markdown', disable_web_page_preview: true });

  // AI analyse als API key beschikbaar
  if (CLAUDE_API_KEY && result.success) {
    await bot.sendMessage(CHAT_ID, `🤖 *AI analyse gestart...*\n⏳ Even geduld...`, { parse_mode: 'Markdown' });
    const aiText = await runAIAnalysis(address, result.sourceCode || '', [], [], result.findings);
    if (aiText) {
      const aiReport = formatAIReport(address, aiText);
      await bot.sendMessage(CHAT_ID, aiReport, { parse_mode: 'Markdown', disable_web_page_preview: true });
    }
  }
});

bot.onText(/\/fullscan/, async (msg) => {
  if (msg.chat.id.toString() !== CHAT_ID) return;
  const addrMatch = msg.text.match(/0x[a-fA-F0-9]{40}/);
  if (!addrMatch) {
    await bot.sendMessage(CHAT_ID, '❌ Geen geldig adres.\n\nGebruik: `/fullscan 0x1234...`\nDraait alle 4 analyses: Slither + Mythril + Security + AI', { parse_mode: 'Markdown' });
    return;
  }
  const address = addrMatch[0];

  // 1. Slither
  await bot.sendMessage(CHAT_ID, `🔬 *Full Scan gestart (4 stappen)...*\n\`${address}\`\n\n⏳ Stap 1/4: Slither...`, { parse_mode: 'Markdown' });
  const slitherResult = await runSlither(address);
  await bot.sendMessage(CHAT_ID, formatSlitherReport(address, slitherResult), { parse_mode: 'Markdown', disable_web_page_preview: true });

  // 2. Mythril
  await bot.sendMessage(CHAT_ID, `⏳ Stap 2/4: Mythril deep analyse...`, { parse_mode: 'Markdown' });
  const mythrilResult = await runMythril(address);
  await bot.sendMessage(CHAT_ID, formatMythrilReport(address, mythrilResult), { parse_mode: 'Markdown', disable_web_page_preview: true });

  // 3. Security/Rugpull check
  await bot.sendMessage(CHAT_ID, `⏳ Stap 3/4: Security & Rugpull check...`, { parse_mode: 'Markdown' });
  const securityResult = await runSecurityCheck(address);
  await bot.sendMessage(CHAT_ID, formatSecurityReport(address, securityResult), { parse_mode: 'Markdown', disable_web_page_preview: true });

  // 4. AI Analyse
  if (CLAUDE_API_KEY && securityResult.success) {
    await bot.sendMessage(CHAT_ID, `⏳ Stap 4/4: AI deep analyse...`, { parse_mode: 'Markdown' });
    const aiText = await runAIAnalysis(
      address,
      securityResult.sourceCode || '',
      slitherResult.success ? slitherResult.findings : [],
      mythrilResult.success ? mythrilResult.issues : [],
      securityResult.success ? securityResult.findings : []
    );
    if (aiText) {
      await bot.sendMessage(CHAT_ID, formatAIReport(address, aiText), { parse_mode: 'Markdown', disable_web_page_preview: true });
    }
  } else if (!CLAUDE_API_KEY) {
    await bot.sendMessage(CHAT_ID, `ℹ️ Stap 4 overgeslagen: geen CLAUDE\\_API\\_KEY in .env`, { parse_mode: 'Markdown' });
  }

  await bot.sendMessage(CHAT_ID, `✅ *Full Scan Voltooid!*\n\`${address}\``, { parse_mode: 'Markdown' });
});

bot.onText(/\/help/, async (msg) => {
  if (msg.chat.id.toString() !== CHAT_ID) return;
  await bot.sendMessage(CHAT_ID, `📖 *BSC Scanner - Commando's*

━━━━━━━━━━━━━━━━━━━━
*Scanner:*
/start - Scanner starten
/stop - Scanner pauzeren
/status - Live status bekijken
/lijst - Laatste gevonden contracten
/alerts - Lijst van matches (alerts)
/scan 1h - Scan verleden (1h/1d/1w/1y)

*Analyse:*
/check 0x... - Slither analyse
/mythril 0x... - Mythril deep analyse
/security 0x... - Rugpull & exploit check
/fullscan 0x... - Alles in 1 (4 stappen)

*Overig:*
/help - Dit menu
━━━━━━━━━━━━━━━━━━━━`, { parse_mode: 'Markdown' });
});

// === HISTORY SCAN ===
async function startHistoryScan(blocksBack, label) {
  historyScanActive = true;
  const currentBlock = await provider.getBlockNumber();
  const fromBlock = currentBlock - blocksBack;
  const totalBlocks = blocksBack;
  let scannedInScan = 0;
  let foundInScan = 0;
  let balanceInScan = 0;
  let alertsInScan = 0;

  await bot.sendMessage(CHAT_ID, `🔄 *History Scan Gestart*

━━━━━━━━━━━━━━━━━━━━
📅 Periode: *Laatste ${label}*
📦 Blocks te scannen: *${totalBlocks.toLocaleString()}*
📍 Van block: *${fromBlock.toLocaleString()}*
📍 Tot block: *${currentBlock.toLocaleString()}*
━━━━━━━━━━━━━━━━━━━━

⏳ Dit kan even duren...`, { parse_mode: 'Markdown' });

  const scanStart = Date.now();
  let lastProgressUpdate = Date.now();

  for (let b = fromBlock; b <= currentBlock; b++) {
    if (!historyScanActive) {
      await bot.sendMessage(CHAT_ID, `🛑 *History scan gestopt*\n\n${scannedInScan} blocks gescand, ${foundInScan} contracten, ${alertsInScan} matches`, { parse_mode: 'Markdown' });
      return;
    }

    try {
      const block = await provider.getBlock(b, true);
      if (block && block.prefetchedTransactions) {
        const contractTxs = block.prefetchedTransactions.filter(tx => tx.to === null);

        for (const tx of contractTxs) {
          try {
            const receipt = await provider.getTransactionReceipt(tx.hash);
            if (!receipt || !receipt.contractAddress) continue;

            const contractAddress = receipt.contractAddress;

            // Skip proxy contracten
            const proxy = await isProxy(contractAddress);
            if (proxy) continue;

            foundInScan++;
            contractsFound++;

            const { totalUsd, breakdown } = await getTotalBalance(contractAddress);
            const hasBalance = totalUsd >= MIN_BALANCE_USD;

            if (hasBalance) {
              balanceInScan++;
              contractsWithBalance++;
            }

            const contractInfo = {
              address: contractAddress,
              balanceUsd: totalUsd,
              breakdown,
              hasBalance,
              verified: false,
              time: new Date(),
              fromHistory: true
            };

            if (hasBalance) {
              console.log(`[HISTORY] ${contractAddress} - $${totalUsd.toFixed(0)} - checking verified...`);
              const verified = await isVerified(contractAddress);
              contractInfo.verified = verified;
              if (verified) {
                verifiedContracts++;
                alertsInScan++;
                await sendAlert(contractAddress, totalUsd, breakdown, verified);
              }
            }

            recentContracts.unshift(contractInfo);
            if (recentContracts.length > MAX_RECENT) recentContracts.pop();
          } catch (err) {
            // Skip
          }
        }
      }
    } catch (err) {
      console.error(`[HISTORY] Fout bij block ${b}:`, err.message);
    }

    scannedInScan++;
    blocksScanned++;

    // Progress update elke 60 seconden
    if (Date.now() - lastProgressUpdate > 60000) {
      const pct = ((scannedInScan / totalBlocks) * 100).toFixed(1);
      const elapsed = ((Date.now() - scanStart) / 60000).toFixed(1);
      const speed = (scannedInScan / ((Date.now() - scanStart) / 60000)).toFixed(0);
      const remaining = ((totalBlocks - scannedInScan) / (scannedInScan / ((Date.now() - scanStart) / 60000))).toFixed(1);

      historyScanProgress = `${pct}%`;

      await bot.sendMessage(CHAT_ID, `⏳ *History Scan Voortgang*

━━━━━━━━━━━━━━━━━━━━
📊 *${pct}%* voltooid
📦 ${scannedInScan.toLocaleString()} / ${totalBlocks.toLocaleString()} blocks
📋 ${foundInScan} contracten gevonden
💰 ${balanceInScan} met $10k+ balance
🚨 ${alertsInScan} matches

⚡ Snelheid: ${speed} blocks/min
⏱️ Verstreken: ${elapsed} min
⏱️ Geschat resterend: ~${remaining} min
━━━━━━━━━━━━━━━━━━━━`, { parse_mode: 'Markdown' });

      lastProgressUpdate = Date.now();
    }

    await sleep(200);
  }

  // Scan klaar
  const totalTime = ((Date.now() - scanStart) / 60000).toFixed(1);
  historyScanActive = false;
  historyScanProgress = '';

  await bot.sendMessage(CHAT_ID, `✅ *History Scan Voltooid!*

━━━━━━━━━━━━━━━━━━━━
📅 Periode: *Laatste ${label}*
⏱️ Duur: *${totalTime} minuten*
━━━━━━━━━━━━━━━━━━━━

📊 *Resultaten:*
📦 Blocks gescand: *${scannedInScan.toLocaleString()}*
📋 Contracten gevonden: *${foundInScan}*
💰 Met $10k+ balance: *${balanceInScan}*
🚨 Matches (verified + $10k+): *${alertsInScan}*

${alertsInScan > 0 ? '👆 Bekijk /alerts voor alle matches' : '😔 Geen matches gevonden in deze periode'}
━━━━━━━━━━━━━━━━━━━━

📡 Real-time scanner draait weer verder...`, { parse_mode: 'Markdown' });
}

// === RUGPULL & EXPLOIT PATTERN CHECKER ===
async function runSecurityCheck(address) {
  try {
    const url = `https://api.etherscan.io/v2/api?chainid=56&module=contract&action=getsourcecode&address=${address}&apikey=${BSCSCAN_KEY}`;
    const res = await axios.get(url);
    if (res.data.status !== '1' || !res.data.result[0].SourceCode) {
      return { success: false, error: 'Source niet beschikbaar' };
    }

    let sourceCode = res.data.result[0].SourceCode;
    const contractName = res.data.result[0].ContractName || 'Contract';

    // Multi-file flatten
    if (sourceCode.startsWith('{{')) {
      try {
        const parsed = JSON.parse(sourceCode.slice(1, -1));
        const sources = parsed.sources || parsed;
        sourceCode = Object.values(sources).map(s => s.content || s).join('\n');
      } catch (e) {}
    }

    const code = sourceCode.toLowerCase();
    const findings = [];

    // ====== RUGPULL PATRONEN ======

    // 1. Hidden mint — owner kan onbeperkt tokens maken
    if (/function\s+mint\s*\(/.test(sourceCode) && /onlyowner|_owner|owner\(\)/.test(code)) {
      const hasMaxSupply = /maxsupply|max_supply|totalsupply\s*<|totalsupply\s*<=|cap/.test(code);
      findings.push({
        category: 'RUGPULL',
        severity: hasMaxSupply ? 'MEDIUM' : 'HIGH',
        title: 'Owner Mint Functie',
        detail: hasMaxSupply
          ? 'Owner kan tokens minten, maar er is een supply cap'
          : 'Owner kan ONBEPERKT tokens minten — kan dumpen en prijs crashen'
      });
    }

    // 2. Fee/tax manipulatie zonder limiet
    const feeSetters = sourceCode.match(/function\s+set(Fee|Tax|Rate|Commission|Slippage)\w*\s*\([^)]*\)/gi) || [];
    for (const fn of feeSetters) {
      const fnBody = sourceCode.substring(sourceCode.indexOf(fn), sourceCode.indexOf(fn) + 500);
      const hasLimit = /require\s*\(.*[<>]=?\s*\d+|max(fee|tax|rate)|<= ?\d+/.test(fnBody.toLowerCase());
      if (!hasLimit) {
        findings.push({
          category: 'RUGPULL',
          severity: 'HIGH',
          title: `Fee Manipulatie: ${fn.match(/set\w+/)[0]}`,
          detail: 'Owner kan fees naar 100% zetten — alle trades gaan naar owner'
        });
      }
    }

    // 3. Blacklist/whitelist/pause — kan transfers blokkeren
    if (/function\s+(blacklist|addblacklist|blocklist|ban)\s*\(/i.test(sourceCode)) {
      findings.push({
        category: 'RUGPULL',
        severity: 'HIGH',
        title: 'Blacklist Functie',
        detail: 'Owner kan adressen blokkeren — holders kunnen niet meer verkopen'
      });
    }
    if (/function\s+pause\s*\(/i.test(sourceCode) && /whennotpaused|_paused|paused\(\)/i.test(code)) {
      findings.push({
        category: 'RUGPULL',
        severity: 'MEDIUM',
        title: 'Pause Functie',
        detail: 'Owner kan alle transfers pauzeren'
      });
    }

    // 4. Honeypot — sell blokkade
    if (/mapping.*isbot|mapping.*isblocked|mapping.*_isexcluded/i.test(code)) {
      const hasSellBlock = /require\s*\(\s*!.*bot|require\s*\(\s*!.*blocked/i.test(sourceCode);
      if (hasSellBlock) {
        findings.push({
          category: 'RUGPULL',
          severity: 'HIGH',
          title: 'Mogelijke Honeypot',
          detail: 'Bot/blocked mapping kan verkoop blokkeren voor specifieke adressen'
        });
      }
    }

    // 5. Proxy / upgradeable — contract kan vervangen worden
    if (/delegatecall|upgradeto|_implementation|transparentproxy|uupsproxy/i.test(code)) {
      findings.push({
        category: 'RUGPULL',
        severity: 'MEDIUM',
        title: 'Upgradeable Contract',
        detail: 'Owner kan de volledige logica vervangen — alles kan later veranderd worden'
      });
    }

    // 6. Selfdestruct
    if (/selfdestruct|suicide/i.test(code)) {
      findings.push({
        category: 'RUGPULL',
        severity: 'HIGH',
        title: 'Selfdestruct Aanwezig',
        detail: 'Contract kan zichzelf vernietigen — alle funds verdwijnen naar owner'
      });
    }

    // ====== EXPLOIT / DIEFSTAL PATRONEN ======

    // 7. Unprotected withdraw/transfer
    const withdrawFns = sourceCode.match(/function\s+(withdraw|emergencyWithdraw|sweep|drain|claim|rescue)\w*\s*\([^)]*\)[^{]*/gi) || [];
    for (const fn of withdrawFns) {
      const fnName = fn.match(/function\s+(\w+)/)[1];
      const fnStart = sourceCode.indexOf(fn);
      const fnBody = sourceCode.substring(fnStart, fnStart + 800);
      const hasAuth = /onlyowner|require\s*\(\s*msg\.sender\s*==\s*(owner|_owner|admin)|modifier|onlyrole|hasrole/i.test(fnBody);
      if (!hasAuth) {
        findings.push({
          category: 'EXPLOIT',
          severity: 'HIGH',
          title: `Onbeschermde ${fnName}()`,
          detail: `Iedereen kan ${fnName}() aanroepen — funds kunnen gestolen worden`
        });
      }
    }

    // 8. Reentrancy patronen (extra check bovenop Slither)
    if (/\.call\{value:|\.call\.value\(/.test(sourceCode)) {
      const hasGuard = /reentrancyguard|nonreentrant|_status|_locked/i.test(code);
      if (!hasGuard) {
        findings.push({
          category: 'EXPLOIT',
          severity: 'HIGH',
          title: 'Reentrancy Risico',
          detail: 'External call met ETH/BNB zonder reentrancy guard — funds kunnen herhaaldelijk opgenomen worden'
        });
      }
    }

    // 9. Unprotected external calls naar willekeurig adres
    if (/\(bool\s+\w*,?\s*\)\s*=\s*\w+\.call/i.test(sourceCode)) {
      const parameterizedTarget = /address\s+\w+.*\.call\{/i.test(sourceCode);
      if (parameterizedTarget) {
        findings.push({
          category: 'EXPLOIT',
          severity: 'MEDIUM',
          title: 'Externe Call naar Variabel Adres',
          detail: 'Call naar door gebruiker opgegeven adres — kan misbruikt worden voor phishing of fund drainage'
        });
      }
    }

    // 10. tx.origin authenticatie
    if (/require\s*\(\s*tx\.origin\s*==/.test(sourceCode)) {
      findings.push({
        category: 'EXPLOIT',
        severity: 'HIGH',
        title: 'tx.origin Authenticatie',
        detail: 'Gebruikt tx.origin voor auth — kwetsbaar voor phishing aanvallen'
      });
    }

    // 11. Unchecked return values
    const uncheckedTransfers = (sourceCode.match(/\.transfer\(|\.send\(/g) || []).length;
    const checkedTransfers = (sourceCode.match(/require\s*\(.*\.(transfer|send)\(/g) || []).length;
    if (uncheckedTransfers > checkedTransfers + 1) {
      findings.push({
        category: 'EXPLOIT',
        severity: 'MEDIUM',
        title: 'Unchecked Transfer/Send',
        detail: 'Token transfers zonder return value check — funds kunnen stil falen'
      });
    }

    // 12. Hardcoded adressen die funds ontvangen
    const hardcodedAddrs = sourceCode.match(/address\s*\(\s*0x[a-fA-F0-9]{40}\s*\)/g) || [];
    const uniqueAddrs = [...new Set(hardcodedAddrs)];
    if (uniqueAddrs.length > 0) {
      const receivesValue = uniqueAddrs.some(addr => {
        const idx = sourceCode.indexOf(addr);
        const context = sourceCode.substring(idx, idx + 200);
        return /\.transfer|\.send|\.call\{value/.test(context);
      });
      if (receivesValue) {
        findings.push({
          category: 'EXPLOIT',
          severity: 'MEDIUM',
          title: 'Hardcoded Wallet Ontvangt Funds',
          detail: 'Vaste wallet adressen ontvangen funds — kan backdoor zijn'
        });
      }
    }

    // ====== BUSINESS LOGIC ======

    // 13. Flash loan kwetsbaarheid
    if (/balanceof\s*\(\s*address\s*\(\s*this\s*\)\s*\)/i.test(sourceCode) && !/twap|timeweighted|cumulativeprice/i.test(code)) {
      const usedForPrice = /price|rate|ratio|getreserves|reserve/i.test(code);
      if (usedForPrice) {
        findings.push({
          category: 'LOGIC',
          severity: 'HIGH',
          title: 'Flash Loan Kwetsbaar',
          detail: 'Gebruikt spot balance voor prijs berekening zonder TWAP — manipuleerbaar via flash loan'
        });
      }
    }

    // 14. Integer overflow in fee/reward berekeningen (pre-0.8)
    const compilerVersion = res.data.result[0].CompilerVersion || '';
    const vMatch = compilerVersion.match(/(\d+)\.(\d+)\.(\d+)/);
    if (vMatch && (parseInt(vMatch[1]) < 1 && parseInt(vMatch[2]) < 8)) {
      if (!/safemath|using safemath/i.test(code)) {
        findings.push({
          category: 'LOGIC',
          severity: 'HIGH',
          title: 'Geen SafeMath (Solidity <0.8)',
          detail: 'Contract gebruikt Solidity <0.8 zonder SafeMath — integer overflow kan balances manipuleren'
        });
      }
    }

    // 15. Oneerlijke reward/staking verdeling
    if (/rewardpertoken|rewardrate|earned\s*\(/i.test(code)) {
      const hasRoundingProtection = /1e18|1e12|precision|decimal/i.test(code);
      if (!hasRoundingProtection) {
        findings.push({
          category: 'LOGIC',
          severity: 'MEDIUM',
          title: 'Reward Afrondingsfout',
          detail: 'Staking/reward berekening zonder precision scaling — kan leiden tot reward diefstal of verlies'
        });
      }
    }

    // 16. Access control gaps
    if (/function\s+set(Owner|Admin|Operator)\s*\(/i.test(sourceCode)) {
      const fnMatch = sourceCode.match(/function\s+set(Owner|Admin|Operator)\s*\([^)]*\)[^{]*/i);
      if (fnMatch) {
        const fnBody = sourceCode.substring(sourceCode.indexOf(fnMatch[0]), sourceCode.indexOf(fnMatch[0]) + 500);
        if (!/onlyowner|require|modifier/i.test(fnBody)) {
          findings.push({
            category: 'EXPLOIT',
            severity: 'HIGH',
            title: 'Onbeschermde Owner Transfer',
            detail: 'Iedereen kan zichzelf owner maken — volledige controle over contract'
          });
        }
      }
    }

    return { success: true, findings, contractName, sourceCode };
  } catch (err) {
    return { success: false, error: err.message, findings: [] };
  }
}

function formatSecurityReport(address, result) {
  if (!result.success) {
    return `❌ *Security Check Mislukt*\n\`${address}\`\nFout: ${result.error.substring(0, 200)}`;
  }

  const findings = result.findings;
  if (findings.length === 0) {
    return `✅ *Security Check Schoon*\n\`${address}\`\n\nGeen rugpull patronen of exploits gevonden.`;
  }

  const rugpulls = findings.filter(f => f.category === 'RUGPULL');
  const exploits = findings.filter(f => f.category === 'EXPLOIT');
  const logic = findings.filter(f => f.category === 'LOGIC');
  const highCount = findings.filter(f => f.severity === 'HIGH').length;

  let verdict = '🟢 RELATIEF VEILIG';
  if (highCount >= 3) verdict = '🔴 ZEER GEVAARLIJK';
  else if (highCount >= 1) verdict = '🟡 VERDACHT';

  let msg = `🛡️ *Security & Rugpull Check*

━━━━━━━━━━━━━━━━━━━━
📋 *Contract:* ${result.contractName || 'Onbekend'}
\`${address}\`
${verdict}
━━━━━━━━━━━━━━━━━━━━

`;

  if (rugpulls.length > 0) {
    msg += `🚩 *Rugpull Risico's (${rugpulls.length}):*\n`;
    for (const f of rugpulls) {
      const icon = f.severity === 'HIGH' ? '🔴' : '🟡';
      msg += `${icon} *${f.title}*\n   ${f.detail}\n\n`;
    }
  }

  if (exploits.length > 0) {
    msg += `💀 *Exploit Risico's (${exploits.length}):*\n`;
    for (const f of exploits) {
      const icon = f.severity === 'HIGH' ? '🔴' : '🟡';
      msg += `${icon} *${f.title}*\n   ${f.detail}\n\n`;
    }
  }

  if (logic.length > 0) {
    msg += `🧠 *Business Logic Issues (${logic.length}):*\n`;
    for (const f of logic) {
      const icon = f.severity === 'HIGH' ? '🔴' : '🟡';
      msg += `${icon} *${f.title}*\n   ${f.detail}\n\n`;
    }
  }

  msg += `━━━━━━━━━━━━━━━━━━━━
🔗 [BSCScan](https://bscscan.com/address/${address})
⏰ ${new Date().toLocaleString('nl-NL')}`;

  return msg;
}

// === AI DEEP ANALYSE (Claude API) ===
async function runAIAnalysis(address, sourceCode, slitherFindings, mythrilIssues, securityFindings) {
  if (!CLAUDE_API_KEY) return null;

  try {
    // Beperk source code tot ~15k chars voor API
    const trimmedSource = sourceCode.length > 15000
      ? sourceCode.substring(0, 15000) + '\n// ... [TRUNCATED]'
      : sourceCode;

    const previousFindings = [];
    if (slitherFindings && slitherFindings.length > 0) {
      previousFindings.push('Slither: ' + slitherFindings.slice(0, 5).map(f => `${f.impact} - ${f.check}`).join(', '));
    }
    if (mythrilIssues && mythrilIssues.length > 0) {
      previousFindings.push('Mythril: ' + mythrilIssues.slice(0, 5).map(i => `${i.severity} - ${i.title}`).join(', '));
    }
    if (securityFindings && securityFindings.length > 0) {
      previousFindings.push('Security: ' + securityFindings.slice(0, 5).map(f => `${f.severity} ${f.title}`).join(', '));
    }

    const prompt = `Je bent een blockchain security expert. Analyseer dit BSC smart contract op:

1. BUSINESS LOGIC BUGS - Fouten in de logica waardoor funds verloren gaan of gestolen kunnen worden
2. DIEFSTAL RISICO - Kan iemand ZONDER owner te zijn geld uit dit contract halen?
3. RUGPULL MECHANISMES - Verborgen manieren waarop de owner users kan benadelen
4. EXPLOITS - Manieren om het contract te misbruiken (flash loans, reentrancy, etc.)

Eerder gevonden issues (ga hier NIET op in, zoek NIEUWE dingen):
${previousFindings.join('\n')}

Contract address: ${address}
Source code:
\`\`\`solidity
${trimmedSource}
\`\`\`

Geef je antwoord in dit exacte format (max 5 findings, alleen echte risico's):
🔴 of 🟡 gevolgd door titel
Uitleg in 1-2 zinnen

Als je NIETS vindt bovenop de eerdere findings, zeg dan: "Geen aanvullende risico's gevonden."
Antwoord in het Nederlands. Wees kort en direct.`;

    const response = await axios.post('https://api.anthropic.com/v1/messages', {
      model: 'claude-sonnet-4-6-20250514',
      max_tokens: 1000,
      messages: [{ role: 'user', content: prompt }]
    }, {
      headers: {
        'x-api-key': CLAUDE_API_KEY,
        'anthropic-version': '2023-06-01',
        'content-type': 'application/json'
      },
      timeout: 30000
    });

    const aiText = response.data.content[0].text;
    return aiText;
  } catch (err) {
    console.error('[AI] Analyse fout:', err.message);
    return null;
  }
}

function formatAIReport(address, aiText) {
  if (!aiText) return null;

  return `🤖 *AI Deep Analyse*

━━━━━━━━━━━━━━━━━━━━
\`${address}\`
━━━━━━━━━━━━━━━━━━━━

${aiText}

━━━━━━━━━━━━━━━━━━━━
_Powered by Claude AI_
⏰ ${new Date().toLocaleString('nl-NL')}`;
}

// === TELEGRAM ALERT STUREN + WORKER FORKEN ===
async function sendAlert(contractAddress, totalUsd, breakdown, verified) {
  // Balance breakdown opbouwen
  let balanceLines = '';
  for (const [token, info] of Object.entries(breakdown)) {
    if (token === 'BNB') {
      balanceLines += `  • ${info.amount.toFixed(4)} BNB (~$${info.usd.toLocaleString('nl-NL', { maximumFractionDigits: 0 })})\n`;
    } else {
      balanceLines += `  • ${info.amount.toLocaleString('nl-NL', { maximumFractionDigits: 0 })} ${token} (~$${info.usd.toLocaleString('nl-NL', { maximumFractionDigits: 0 })})\n`;
    }
  }

  const verifiedIcon = verified ? '✅ Ja' : '❌ Nee';
  const alertIcon = verified ? '🚨' : '💰';

  const message = `${alertIcon} *CONTRACT GEVONDEN MET $10K+*

━━━━━━━━━━━━━━━━━━━━
📋 *Contract:*
\`${contractAddress}\`

💰 *Totale Balance: ~$${totalUsd.toLocaleString('nl-NL', { maximumFractionDigits: 0 })}*
${balanceLines}📝 *Verified:* ${verifiedIcon}
━━━━━━━━━━━━━━━━━━━━

🔗 [Bekijk op BSCScan](https://bscscan.com/address/${contractAddress})
🔗 [TokenSniffer Check](https://tokensniffer.com/token/bsc/${contractAddress})
🔗 [DexTools](https://www.dextools.io/app/bsc/pair-explorer/${contractAddress})

⏰ ${new Date().toLocaleString('nl-NL')}`;

  try {
    await safeSend(message);
    alertsSent++;

    recentAlerts.unshift({
      address: contractAddress,
      balanceUsd: totalUsd,
      breakdown,
      time: new Date()
    });
    if (recentAlerts.length > MAX_ALERTS) recentAlerts.pop();

    console.log(`[ALERT] Verzonden voor ${contractAddress} ($${totalUsd.toFixed(0)})`);

    // Skip als al in analyse of te veel workers
    if (analyzingAddresses.has(contractAddress.toLowerCase())) return;
    if (activeWorkers.size >= MAX_WORKERS) {
      console.log(`[WORKER] Max workers bereikt (${MAX_WORKERS}), analyse uitgesteld voor ${contractAddress}`);
      return;
    }

    // Fork analyse worker — scanner draait gewoon door!
    analyzingAddresses.add(contractAddress.toLowerCase());
    const worker = fork(path.join(__dirname, 'analyze-worker.js'));
    activeWorkers.add(worker);
    console.log(`[WORKER] Analyse worker gestart voor ${contractAddress} (${activeWorkers.size}/${MAX_WORKERS} actief)`);

    worker.send({ address: contractAddress, totalUsd, breakdown });

    worker.on('message', (msg) => {
      if (msg.done) {
        console.log(`[WORKER] Analyse klaar: ${msg.address}${msg.error ? ' (fout: ' + msg.error + ')' : ''}`);
        activeWorkers.delete(worker);
        analyzingAddresses.delete(msg.address.toLowerCase());
      }
    });

    worker.on('error', (err) => {
      console.error(`[WORKER] Worker error:`, err.message);
      activeWorkers.delete(worker);
      analyzingAddresses.delete(contractAddress.toLowerCase());
    });

    worker.on('exit', (code) => {
      if (code !== 0) console.error(`[WORKER] Worker crashed met code ${code}`);
      activeWorkers.delete(worker);
      analyzingAddresses.delete(contractAddress.toLowerCase());
    });

  } catch (err) {
    console.error('[ALERT] Fout bij verzenden:', err.message);
  }
}

// === STATUS RAPPORT ===
async function sendStatusReport() {
  const blocksPerMin = blocksScanned > 0 ? (blocksScanned / ((Date.now() - startTime) / 60000)).toFixed(1) : '0';
  const statusIcon = scanning ? '🟢 ACTIEF' : '🔴 GEPAUZEERD';
  const historyLine = historyScanActive ? `\n🔄 *History scan: ${historyScanProgress}*` : '';
  const timeScanned = blocksToTime(blocksScanned);
  const startDate = new Date(startTime).toLocaleString('nl-NL');
  const daysBack = startBlock > 0 ? ((startBlock - currentBlockNum + blocksScanned * 2) * 3 / 86400) : 0;
  const currentScanDaysBack = startBlock > 0 ? (((startBlock - (startBlock - 28800 - blocksScanned)) * 3) / 86400).toFixed(1) : '?';

  const msg = `📊 *BSC Scanner Status*

━━━━━━━━━━━━━━━━━━━━
${statusIcon}${historyLine}
⏱️ Uptime: *${uptime()}*
📅 Gestart: *${startDate}*
━━━━━━━━━━━━━━━━━━━━

⏪ *Backward Scan:*
• Blocks gescand: *${blocksScanned.toLocaleString()}*
• Nu ~*${((blocksScanned + 28800) * 3 / 86400).toFixed(1)} dagen* terug
• Snelheid: *${blocksPerMin} blocks/min*

⏩ *Live Monitoring:*
• Live blocks gescand: *${liveBlocksScanned.toLocaleString()}*
• Analyse workers actief: *${activeWorkers.size}/${MAX_WORKERS}*

📋 *Contracten:*
• Totaal gevonden: *${contractsFound.toLocaleString()}*
• Met $10k+ balance: *${contractsWithBalance.toLocaleString()}*
• Verified: *${verifiedContracts.toLocaleString()}*

🔔 *Alerts verzonden: ${alertsSent}*

💲 *BNB Prijs: $${bnbPriceUsd.toFixed(2)}*
🎯 *Min balance: $${MIN_BALANCE_USD.toLocaleString()}*
🔍 *Checkt: BNB + USDT + USDC + BUSD*
━━━━━━━━━━━━━━━━━━━━
⏰ ${new Date().toLocaleString('nl-NL')}`;

  try {
    await bot.sendMessage(CHAT_ID, msg, { parse_mode: 'Markdown' });
  } catch (err) {
    console.error('[STATUS] Fout:', err.message);
  }
}

// === CONTRACT LIJST ===
async function sendContractList() {
  if (recentContracts.length === 0) {
    await bot.sendMessage(CHAT_ID, '📋 *Nog geen contracten gevonden.*\n\nDe scanner is bezig...', { parse_mode: 'Markdown' });
    return;
  }

  let list = `📋 *Laatste ${Math.min(recentContracts.length, 15)} Contracten*\n\n`;

  const show = recentContracts.slice(0, 15);
  for (const c of show) {
    const statusIcon = c.verified ? '✅' : (c.hasBalance ? '💰' : '⚪');
    const balanceStr = c.balanceUsd > 0 ? `$${c.balanceUsd.toLocaleString('nl-NL', { maximumFractionDigits: 0 })}` : '$0';
    list += `${statusIcon} \`${shortAddr(c.address)}\` ${balanceStr}`;
    if (c.verified && c.hasBalance) list += ' 🚨';
    list += '\n';
  }

  list += `\n━━━━━━━━━━━━━━━━━━━━`;
  list += `\n✅ = Verified | 💰 = $10k+ | 🚨 = Match`;
  list += `\nTotaal bekeken: ${contractsFound}`;

  try {
    await bot.sendMessage(CHAT_ID, list, { parse_mode: 'Markdown' });
  } catch (err) {
    console.error('[LIJST] Fout:', err.message);
  }
}

// === ALERT LIJST ===
async function sendAlertList() {
  if (recentAlerts.length === 0) {
    await bot.sendMessage(CHAT_ID, '🔔 *Nog geen matches gevonden.*\n\nGeduld, de scanner zoekt...', { parse_mode: 'Markdown' });
    return;
  }

  let list = `🔔 *Laatste ${recentAlerts.length} Matches*\n\n`;

  for (const a of recentAlerts) {
    const time = a.time.toLocaleTimeString('nl-NL', { hour: '2-digit', minute: '2-digit' });
    list += `🚨 \`${shortAddr(a.address)}\` - $${a.balanceUsd.toLocaleString('nl-NL', { maximumFractionDigits: 0 })} - ${time}\n`;
    list += `   [BSCScan](https://bscscan.com/address/${a.address})\n\n`;
  }

  try {
    await bot.sendMessage(CHAT_ID, list, { parse_mode: 'Markdown', disable_web_page_preview: true });
  } catch (err) {
    console.error('[ALERTS] Fout:', err.message);
  }
}

// === CHECK EEN CONTRACT ADRES ===
async function checkContract(contractAddress, source) {
  try {
    if (checkedAddresses.has(contractAddress.toLowerCase())) return;
    if (SKIP_ADDRESSES.has(contractAddress.toLowerCase())) return;
    checkedAddresses.add(contractAddress.toLowerCase());

    // Geheugen limiet: max 500k adressen bijhouden
    if (checkedAddresses.size > 500000) {
      const iter = checkedAddresses.values();
      for (let i = 0; i < 50000; i++) {
        checkedAddresses.delete(iter.next().value);
      }
    }

    // Skip proxy contracten
    const proxy = await isProxy(contractAddress);
    if (proxy) return;

    contractsFound++;

    const { totalUsd, breakdown } = await getTotalBalance(contractAddress);
    const hasBalance = totalUsd >= MIN_BALANCE_USD;

    if (hasBalance) contractsWithBalance++;

    const contractInfo = {
      address: contractAddress,
      balanceUsd: totalUsd,
      breakdown,
      hasBalance,
      verified: false,
      time: new Date(),
      source
    };

    if (hasBalance) {
      console.log(`[CHECK] ${contractAddress} - $${totalUsd.toFixed(0)} - checking verified... (${source})`);
      const verified = await isVerified(contractAddress);
      contractInfo.verified = verified;
      if (verified) {
        verifiedContracts++;
        await sendAlert(contractAddress, totalUsd, breakdown, verified);
      }
    }

    recentContracts.unshift(contractInfo);
    if (recentContracts.length > MAX_RECENT) recentContracts.pop();
  } catch (err) {
    // Skip
  }
}

// === BLOCK SCANNEN ===
async function scanBlock(blockNumber) {
  try {
    const block = await provider.getBlock(blockNumber, true);
    if (!block || !block.prefetchedTransactions) return;

    // 1) Nieuwe contracten (tx.to === null)
    const contractTxs = block.prefetchedTransactions.filter(tx => tx.to === null);
    for (const tx of contractTxs) {
      try {
        const receipt = await provider.getTransactionReceipt(tx.hash);
        if (!receipt || !receipt.contractAddress) continue;
        await checkContract(receipt.contractAddress, 'new');
      } catch (err) {}
    }

    // 2) Bestaande contracten die transacties ontvangen
    // Pak unieke to-adressen (skip null, al gecheckte, en bekende skip-adressen)
    const toAddresses = new Set();
    for (const tx of block.prefetchedTransactions) {
      if (tx.to) {
        const addr = tx.to.toLowerCase();
        if (!checkedAddresses.has(addr) && !SKIP_ADDRESSES.has(addr)) {
          toAddresses.add(tx.to);
        }
      }
    }

    // Check max 5 adressen per block (snelheid + minder dubbel werk)
    let checked = 0;
    for (const addr of toAddresses) {
      if (checked >= 5) break;
      // Voeg meteen toe aan checked om dubbels in volgende blocks te voorkomen
      checkedAddresses.add(addr.toLowerCase());
      try {
        // Check of het een contract is (heeft code)
        const code = await provider.getCode(addr);
        if (code && code !== '0x') {
          await checkContract(addr, 'existing');
        }
      } catch (err) {}
      checked++;
    }
  } catch (err) {
    console.error(`[SCAN] Fout bij block ${blockNumber}:`, err.message);
  }
}

// === LIVE UPDATE (elke 5 min) ===
async function sendLiveUpdate() {
  if (!scanning) return;

  const blocksPerMin = blocksScanned > 0 ? (blocksScanned / ((Date.now() - startTime) / 60000)).toFixed(1) : '0';
  const historyLine = historyScanActive ? `\n🔄 History scan: ${historyScanProgress}` : '';

  const daysBack = ((blocksScanned + 28800) * 3 / 86400).toFixed(1);

  const msg = `📡 *Live Update*

⏪ ~${daysBack} dagen terug | ⏩ ${liveBlocksScanned} live blocks
🔢 ${blocksScanned.toLocaleString()} blocks | 📋 ${contractsFound.toLocaleString()} contracten
💰 ${contractsWithBalance} met $10k+ | 🔔 ${alertsSent} alerts
⚡ ${blocksPerMin} blocks/min | 🔧 ${activeWorkers.size}/${MAX_WORKERS} workers${historyLine}`;

  try {
    await bot.sendMessage(CHAT_ID, msg, { parse_mode: 'Markdown' });
  } catch (err) {
    console.error('[LIVE] Fout:', err.message);
  }
}

// === MAIN LOOP ===
async function main() {
  console.log('=== BSC Contract Scanner v3 ===');
  console.log(`Min balance: $${MIN_BALANCE_USD}`);
  console.log(`Chat ID: ${CHAT_ID}`);
  console.log('');

  await updateBnbPrice();

  setInterval(updateBnbPrice, 5 * 60 * 1000);
  setInterval(sendLiveUpdate, STATUS_INTERVAL);
  setInterval(sendHeartbeat, 60000); // heartbeat elke minuut
  sendHeartbeat(); // direct eerste heartbeat

  const currentBlock = await provider.getBlockNumber();
  currentBlockNum = currentBlock;
  startBlock = currentBlock;

  await bot.sendMessage(CHAT_ID, `🚀 *BSC Scanner v3 Gestart!*

━━━━━━━━━━━━━━━━━━━━
⚙️ *Instellingen:*
• Min balance: *$${MIN_BALANCE_USD.toLocaleString()}*
• Filter: Verified ✅ + Balance 💰 (BNB+USDT+USDC+BUSD)
• BNB prijs: *$${bnbPriceUsd.toFixed(2)}*
• Live updates: elke 5 min
━━━━━━━━━━━━━━━━━━━━

📖 *Commando's:*
/status - Live status
/lijst - Gevonden contracten
/alerts - Matches lijst
/scan 1h - Extra scan periode
/stop - Pauzeren
/help - Alle commando's

⏪ Start met scannen van laatste 24u, daarna steeds verder terug...`, { parse_mode: 'Markdown' });

  console.log(`[START] Huidig block: ${currentBlock}`);

  // Probeer vorige state te laden
  const blocksPerDay = 28800;
  let scanBlock_num;
  const savedState = loadState();

  if (savedState && savedState.scanBlock) {
    scanBlock_num = savedState.scanBlock - 1; // -1 want hij scant backwards
    blocksScanned = savedState.blocksScanned || 0;
    contractsFound = savedState.contractsFound || 0;
    contractsWithBalance = savedState.contractsWithBalance || 0;
    verifiedContracts = savedState.verifiedContracts || 0;
    alertsSent = savedState.alertsSent || 0;
    if (savedState.recentAlerts) {
      recentAlerts.push(...savedState.recentAlerts.map(a => ({ ...a, time: new Date(a.time) })));
    }
    const daysBack = ((currentBlock - scanBlock_num) * 3 / 86400).toFixed(1);
    console.log(`[START] Hervat vanaf ~${daysBack} dagen terug (block ${scanBlock_num})`);

    await bot.sendMessage(CHAT_ID, `🔄 *Scanner Hervat!*\n\n⏪ Verder vanaf ~*${daysBack} dagen* terug\n📦 Al gescand: *${blocksScanned.toLocaleString()}* blocks\n📋 Contracten: *${contractsFound}* | Alerts: *${alertsSent}*`, { parse_mode: 'Markdown' });
  } else {
    scanBlock_num = currentBlock - blocksPerDay;
    console.log(`[START] Begin met terugkijken vanaf 24u geleden...`);
  }

  // === LIVE BLOCK MONITORING (vooruit) ===
  provider.on('block', async (blockNumber) => {
    if (!scanning) return;
    try {
      await scanBlock(blockNumber);
      liveBlocksScanned++;
      if (liveBlocksScanned % 20 === 0) {
        console.log(`[LIVE] ${liveBlocksScanned} live blocks gescand (laatste: ${blockNumber})`);
      }
    } catch (err) {
      // Stil falen, niet loggen voor elk block
    }
  });
  console.log('[LIVE] Live block monitoring actief');

  // === BACKWARD SCAN LOOP ===
  while (true) {
    if (!scanning) {
      await sleep(3000);
      continue;
    }

    // Skip als history scan actief is (analyse blokkeert NIET meer)
    if (historyScanActive) {
      await sleep(3000);
      continue;
    }

    try {
      // Scan 1 block verder terug
      if (scanBlock_num > 0) {
        await scanBlock(scanBlock_num);
        blocksScanned++;
        scanBlock_num--;
        currentScanBlock = scanBlock_num;

        if (blocksScanned % 10 === 0) {
          saveState();
        }
        if (blocksScanned % 100 === 0) {
          const daysBack = ((currentBlock - scanBlock_num) * 3 / 86400).toFixed(1);
          console.log(`[INFO] ${blocksScanned} blocks | ${contractsFound} contracten | ${contractsWithBalance} $10k+ | ${alertsSent} alerts | ~${daysBack} dagen terug | ⏩ ${liveBlocksScanned} live | 🔧 ${activeWorkers.size} workers`);
        }

        await sleep(200);
      } else {
        // Alles gescand tot block 0
        await bot.sendMessage(CHAT_ID, `✅ *Volledige BSC blockchain gescand!*`, { parse_mode: 'Markdown' });
        break;
      }
    } catch (err) {
      console.error('[MAIN] Fout:', err.message);
      await sleep(5000);
    }
  }
}

main().catch(err => {
  console.error('[FATAL]', err);
  process.exit(1);
});
