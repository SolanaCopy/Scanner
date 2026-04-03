// Analyze Worker — draait Slither + Mythril + Security in apart process
// Wordt geforkt vanuit index.js zodat de scanner niet blokkeert
require('dotenv').config();
const TelegramBot = require('node-telegram-bot-api');
const axios = require('axios');
const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

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

// Telegram bot (alleen voor berichten sturen, geen polling)
const bot = new TelegramBot(TELEGRAM_TOKEN);

async function safeSend(text) {
  try {
    await bot.sendMessage(CHAT_ID, text, { parse_mode: 'Markdown', disable_web_page_preview: true });
  } catch (err) {
    try {
      await bot.sendMessage(CHAT_ID, text.replace(/[*_`\[\]]/g, ''), { disable_web_page_preview: true });
    } catch (err2) {
      console.error('[WORKER-TG] Fout:', err2.message);
    }
  }
}

// === SLITHER ===
async function runSlither(address) {
  try {
    const url = `https://api.etherscan.io/v2/api?chainid=56&module=contract&action=getsourcecode&address=${address}&apikey=${BSCSCAN_KEY}`;
    const res = await axios.get(url);
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
    let solcVersion = '0.8.20';
    if (versionMatch) {
      solcVersion = versionMatch[1];
      try {
        execSync(`C:/Users/moham/AppData/Local/Python/pythoncore-3.14-64/Scripts/solc-select install ${solcVersion}`, { timeout: 30000 });
        execSync(`C:/Users/moham/AppData/Local/Python/pythoncore-3.14-64/Scripts/solc-select use ${solcVersion}`, { timeout: 10000 });
      } catch (e) {}
    }

    let output = '';
    try {
      output = execSync(`"${SLITHER_PATH}" "${tmpDir}" --json -`, {
        timeout: 120000, encoding: 'utf-8',
        env: { ...process.env, PATH: process.env.PATH + ';C:/Users/moham/AppData/Local/Python/pythoncore-3.14-64/Scripts' }
      });
    } catch (e) { output = e.stdout || e.stderr || ''; }

    fs.rmSync(tmpDir, { recursive: true, force: true });

    let findings = [];
    try {
      const json = JSON.parse(output);
      if (json.results && json.results.detectors) {
        findings = json.results.detectors.map(d => ({ check: d.check, impact: d.impact, confidence: d.confidence, description: (d.description || '').substring(0, 300) }));
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
    const res = await axios.get(url);
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
        output = execSync(cmd, { timeout: 300000, encoding: 'utf-8', env: DOCKER_ENV });
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
    const res = await axios.get(url);
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
      if (!/onlyowner|require\s*\(\s*msg\.sender\s*==\s*(owner|_owner|admin)|onlyrole|hasrole/i.test(fnBody)) {
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

    // Logic
    if (/balanceof\s*\(\s*address\s*\(\s*this\s*\)\s*\)/i.test(sourceCode) && !/twap|timeweighted/i.test(code) && /price|rate|ratio/i.test(code)) {
      findings.push({ category: 'LOGIC', severity: 'HIGH', title: 'Flash Loan Kwetsbaar', detail: 'Spot balance als prijs zonder TWAP' });
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

// === AI ANALYSE ===
async function runAIAnalysis(address, sourceCode, slitherFindings, mythrilIssues, securityFindings) {
  if (!CLAUDE_API_KEY) return null;
  try {
    const trimmedSource = sourceCode.length > 15000 ? sourceCode.substring(0, 15000) + '\n// ... [TRUNCATED]' : sourceCode;
    const previousFindings = [];
    if (slitherFindings.length > 0) previousFindings.push('Slither: ' + slitherFindings.slice(0, 5).map(f => `${f.impact} - ${f.check}`).join(', '));
    if (mythrilIssues.length > 0) previousFindings.push('Mythril: ' + mythrilIssues.slice(0, 5).map(i => `${i.severity} - ${i.title}`).join(', '));
    if (securityFindings.length > 0) previousFindings.push('Security: ' + securityFindings.slice(0, 5).map(f => `${f.severity} ${f.title}`).join(', '));

    const prompt = `Je bent een blockchain security expert. Analyseer dit BSC smart contract op:\n1. BUSINESS LOGIC BUGS\n2. DIEFSTAL RISICO - Kan iemand ZONDER owner te zijn geld stelen?\n3. RUGPULL MECHANISMES\n4. EXPLOITS\n\nEerder gevonden (ga hier NIET op in):\n${previousFindings.join('\n')}\n\nContract: ${address}\n\`\`\`solidity\n${trimmedSource}\n\`\`\`\n\nMax 5 findings, alleen echte risico's. Format: 🔴/🟡 titel + uitleg 1-2 zinnen. Nederlands. Kort.`;

    const response = await axios.post('https://api.anthropic.com/v1/messages', {
      model: 'claude-sonnet-4-20250514', max_tokens: 1000,
      messages: [{ role: 'user', content: prompt }]
    }, {
      headers: { 'x-api-key': CLAUDE_API_KEY, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' },
      timeout: 30000
    });
    return response.data.content[0].text;
  } catch (err) { console.error('[WORKER-AI] Fout:', err.message); return null; }
}

// === FOUNDRY ON-CHAIN SCAN (cast) ===
const CAST_PATH = 'C:/Users/moham/.foundry/bin/cast';
const BSC_RPC = process.env.BSC_RPC || 'https://bsc-dataseed1.binance.org';

async function runFoundryScan(address) {
  const findings = [];
  const run = (cmd) => {
    try { return execSync(cmd, { timeout: 15000, encoding: 'utf-8', env: { ...process.env, PATH: process.env.PATH + ';C:/Users/moham/.foundry/bin' } }).trim(); } catch (e) { return ''; }
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
        const res = await axios.get(url);
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

    // 6. Check contract age
    const creationTx = run(`"${CAST_PATH}" age ${address} --rpc-url ${BSC_RPC}`);
    if (creationTx) {
      findings.push({ check: 'AGE', severity: 'INFO', detail: `Contract age: ${creationTx}` });
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
    const res = await axios.get(url);
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

    // Docker run
    const dockerTmpDir = tmpDir.replace(/\\/g, '/');
    const cmd = `docker run --rm -v "${dockerTmpDir}:/src" ${ECHIDNA_DOCKER} echidna /src/${contractName}.sol --contract ${contractName} --config /src/echidna.yaml --solc-version ${solcVersion} 2>&1`;

    let output = '';
    try {
      output = execSync(cmd, { timeout: 180000, encoding: 'utf-8', env: DOCKER_ENV });
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
function saveResult(address, balanceUsd, breakdown, slither, mythril, security, echidna) {
  echidna = echidna || { success: false };
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
    echidna: { success: echidna.success, failed: echidna.failed || 0, passed: echidna.passed || 0, issues: echidna.success ? (echidna.issues || []).slice(0, 10) : [] }
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
    const trimmedSource = sourceCode.length > 30000 ? sourceCode.substring(0, 30000) + '\n// ... [TRUNCATED]' : sourceCode;

    const tokenList = Object.entries(breakdown || {}).map(([k, v]) => `${k}: $${Math.round(v.usd || v.amount)}`).join(', ');

    const prompt = `Je bent een elite smart contract security auditor die bug bounties doet. Analyseer dit BSC contract op BUSINESS LOGIC BUGS — fouten die niet door standaard tools (Slither/Mythril) gevonden worden.

Contract: ${address}
Balans: $${Math.round(balanceUsd)} (${tokenList})
Chain: BSC (chainId 56)

\`\`\`solidity
${trimmedSource}
\`\`\`

Focus ALLEEN op:
1. Rekenfouten (afrondingsbugs, verkeerde fee/reward berekening, overflow bij vermenigvuldiging)
2. Flash loan aanvallen (spot price als oracle, manipuleerbare reserves)
3. Logica fouten in claim/withdraw/stake (dubbel claimen, timing exploits, verkeerde bookkeeping)
4. Access control gaps die NIET simpelweg "missing onlyOwner" zijn maar subtielere logica fouten
5. Cross-function reentrancy of state inconsistencies
6. Eerste depositor / donation attacks

Als je een CONCRETE exploiteerbare bug vindt, genereer een Hardhat exploit script dat:
- Draait op een BSC fork (ethers v6, Hardhat)
- Impersonate het juiste adres als nodig (hre.network.provider.request({ method: "hardhat_impersonateAccount" }))
- De exploit uitvoert en laat zien dat er winst gemaakt wordt
- Console.log gebruikt om de stappen + balans veranderingen te tonen

Antwoord in EXACT dit JSON format (geen markdown, puur JSON):
{
  "findings": ["korte beschrijving van elke finding"],
  "exploitable": true/false,
  "confidence": "HIGH"/"MEDIUM"/"LOW",
  "exploit_description": "wat de exploit doet in 2-3 zinnen",
  "exploit_code": "// volledig Hardhat script hier als exploitable=true, anders null"
}

Als er GEEN business logic bugs zijn, antwoord: {"findings": [], "exploitable": false, "confidence": "HIGH", "exploit_description": null, "exploit_code": null}

BELANGRIJK: Alleen echte, exploiteerbare bugs. Geen theoretische risico's. Als je niet zeker bent, zet confidence op LOW.`;

    const response = await axios.post('https://api.anthropic.com/v1/messages', {
      model: 'claude-sonnet-4-20250514',
      max_tokens: 4000,
      messages: [{ role: 'user', content: prompt }]
    }, {
      headers: { 'x-api-key': CLAUDE_API_KEY, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' },
      timeout: 60000
    });

    const aiText = response.data.content[0].text;
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

    // Stap 2: Voer exploit uit op Hardhat fork
    console.log(`[WORKER-BL] Exploit gegenereerd (confidence: ${aiResult.confidence}), wordt getest...`);

    const exploitDir = path.join(__dirname, 'tmp', `bl_exploit_${address}`);
    fs.mkdirSync(exploitDir, { recursive: true });

    const exploitFile = path.join(exploitDir, 'exploit.js');
    fs.writeFileSync(exploitFile, aiResult.exploit_code);

    let exploitOutput = '';
    let exploitSuccess = false;
    try {
      exploitOutput = execSync(`npx hardhat run "${exploitFile}" --network hardhat`, {
        cwd: __dirname,
        timeout: 120000,
        encoding: 'utf-8',
        env: { ...process.env, TARGET_ADDRESS: address },
      });
      // Als het script succesvol draait zonder errors = exploit werkt
      exploitSuccess = !exploitOutput.toLowerCase().includes('error') &&
                       !exploitOutput.toLowerCase().includes('revert') &&
                       exploitOutput.length > 10;
      console.log(`[WORKER-BL] Exploit output (${exploitSuccess ? 'SUCCESS' : 'FAILED'}):\n${exploitOutput.substring(0, 500)}`);
    } catch (e) {
      exploitOutput = (e.stdout || '') + '\n' + (e.stderr || '');
      console.log(`[WORKER-BL] Exploit gefaald: ${exploitOutput.substring(0, 300)}`);
      exploitSuccess = false;
    }

    // Cleanup
    setTimeout(() => { try { fs.rmSync(exploitDir, { recursive: true, force: true }); } catch(e) {} }, 10000);

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

// === MAIN: ontvang opdracht van parent process ===
process.on('message', async (msg) => {
  const { address, totalUsd, breakdown } = msg;
  console.log(`[WORKER] Analyse gestart: ${address} ($${totalUsd})`);

  try {
    // 0. Naam-check: skip bekende infra VOORDAT we iets doen
    try {
      const infoUrl = `https://api.etherscan.io/v2/api?chainid=56&module=contract&action=getsourcecode&address=${address}&apikey=${BSCSCAN_KEY}`;
      const infoRes = await axios.get(infoUrl, { timeout: 10000 });
      const cName = (infoRes.data.result?.[0]?.ContractName || '').toLowerCase();
      const SKIP_NAMES = [
        'pancakepair', 'pancakev3pool', 'pancakev3', 'pancakestableswap', 'pancakefactory', 'pancakerouter',
        'pancakeswap', 'pancake', 'nomiswap', 'uniswapv2pair', 'uniswapv3pool', 'uniswap',
        'sushiswap', 'biswap', 'thena', 'apeswap', 'babyswap', 'mdex', 'algebrapool',
        'swapflashloan', 'stableswap', 'curverpool', 'liquiditypool',
        'kernel', 'semimodularaccount', 'simpleaccount', 'lightaccount', 'biconomyaccount',
        'gnosissafe', 'gnosisproxy', 'gnosissafeproxy', 'safeproxy', 'safe',
        'ownbitmultisig', 'ownbitmultisigproxy', 'nervemultisig',
        'transparentupgradeableproxy', 'transparentproxy', 'erc1967proxy', 'beaconproxy',
        'adminupgradeabilityproxy', 'immutableadminupgradeabilityproxy',
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
    } catch (e) {}

    // 1. Slither
    await safeSend(`🔬 *Slither analyse...*\n\`${address}\``);
    const slitherResult = await runSlither(address);
    await safeSend(formatSlitherReport(address, slitherResult));

    // 2. Mythril
    await safeSend(`🔮 *Mythril deep analyse...*\n\`${address}\`\n⏳ 2-5 min...`);
    const mythrilResult = await runMythril(address);
    await safeSend(formatMythrilReport(address, mythrilResult));

    // 3. Security
    const securityResult = await runSecurityCheck(address);
    await safeSend(formatSecurityReport(address, securityResult));

    // 3.5 Foundry on-chain scan
    const foundryResult = await runFoundryScan(address);
    const foundryReport = formatFoundryReport(address, foundryResult);
    if (foundryReport) await safeSend(foundryReport);

    // 4. AI (optioneel)
    if (CLAUDE_API_KEY) {
      await safeSend(`🤖 *AI analyse...*\n\`${address}\``);
      const aiText = await runAIAnalysis(address, securityResult.sourceCode || '',
        slitherResult.success ? slitherResult.findings : [],
        mythrilResult.success ? mythrilResult.issues : [],
        securityResult.success ? securityResult.findings : []);
      if (aiText) await safeSend(`🤖 *AI Deep Analyse*\n━━━━━━━━━━━━━━━━━━━━\n\`${address}\`\n━━━━━━━━━━━━━━━━━━━━\n\n${aiText}`);
    }

    // 5. Echidna fuzzing (als Docker beschikbaar is)
    let echidnaResult = { success: false, error: 'overgeslagen' };
    try {
      execSync('docker info', { timeout: 10000, stdio: 'ignore', env: DOCKER_ENV });
      await safeSend(`🦔 *Echidna fuzzing...*\n\`${address}\`\n⏳ 1-3 min...`);
      echidnaResult = await runEchidna(address);
      await safeSend(formatEchidnaReport(address, echidnaResult));
      // Push echidna resultaten naar dashboard
      if (echidnaResult.success && SCANNER_API_KEY && RENDER_URL) {
        const echidnaPush = { address, contractName: echidnaResult.contractName, time: new Date().toISOString(), passed: echidnaResult.passed, failed: echidnaResult.failed, issues: (echidnaResult.issues || []).slice(0, 10) };
        axios.post(`${RENDER_URL}/api/scanner/echidna`, { result: echidnaPush }, { headers: { 'x-api-key': SCANNER_API_KEY }, timeout: 10000 })
          .catch(e => console.error('[WORKER] Echidna dashboard push fout:', e.message));
      }
    } catch (e) {
      console.log('[WORKER] Docker niet beschikbaar, Echidna overgeslagen');
    }

    // 6. Opslaan
    saveResult(address, totalUsd, breakdown, slitherResult, mythrilResult, securityResult, echidnaResult);

    // 7. Exploit test als er kritieke findings zijn
    const highFindings = {
      slither: slitherResult.success ? slitherResult.findings.filter(f => f.impact === 'High' || f.impact === 'Medium') : [],
      mythril: mythrilResult.success ? mythrilResult.issues.filter(i => i.severity === 'High' || i.severity === 'Medium') : [],
      security: securityResult.success ? securityResult.findings.filter(f => f.severity === 'HIGH' || f.severity === 'MEDIUM') : [],
    };
    const totalCritical = highFindings.slither.filter(f => f.impact === 'High').length
      + highFindings.mythril.filter(i => i.severity === 'High').length
      + highFindings.security.filter(f => f.severity === 'HIGH').length;

    if (totalCritical > 0) {
      console.log(`[WORKER] ${totalCritical} kritieke findings — start exploit test...`);
      await safeSend(`⚡ *Exploit test gestart...*\n\`${address}\`\n🔴 ${totalCritical} kritieke findings gevonden\n⏳ Wordt getest op lokale Hardhat fork...`);
      try {
        // Schrijf findings naar temp bestand zodat exploit-tester ze kan lezen
        const findingsFile = path.join(__dirname, 'tmp', `findings_${address}.json`);
        fs.mkdirSync(path.join(__dirname, 'tmp'), { recursive: true });
        fs.writeFileSync(findingsFile, JSON.stringify(highFindings));

        const { execSync } = require('child_process');
        const output = execSync(`npx hardhat run exploit-tester.js --network hardhat`, {
          cwd: path.join(__dirname),
          timeout: 180000,
          encoding: 'utf-8',
          env: { ...process.env, EXPLOIT_ADDRESS: address, EXPLOIT_FINDINGS: findingsFile },
        });
        console.log(output);

        // Cleanup
        try { fs.unlinkSync(findingsFile); } catch (e) {}
      } catch (e) {
        console.error(`[WORKER] Exploit test fout: ${(e.stdout || e.message || '').substring(0, 300)}`);
      }
    }

    // 8. Business Logic Audit (AI + Anvil exploit verificatie)
    // Alleen voor contracten >$10K met verified source, zonder high-severity findings (die al door stap 7 getest worden)
    const hasVerifiedSource = securityResult.sourceCode && securityResult.sourceCode.length > 100;
    const qualifiesForLogicAudit = hasVerifiedSource && totalUsd >= 10000 && totalCritical === 0;

    if (qualifiesForLogicAudit && CLAUDE_API_KEY) {
      console.log(`[WORKER] Business logic audit gestart: ${address} ($${totalUsd})`);
      await safeSend(`🧠 *Business Logic Audit...*\n\`${address}\`\n💰 $${Math.round(totalUsd).toLocaleString()}\n⏳ AI analyseert business logic + genereert exploit...`);
      try {
        const logicResult = await runBusinessLogicAudit(address, securityResult.sourceCode, totalUsd, breakdown);
        if (logicResult && logicResult.exploitConfirmed) {
          await safeSend(formatBusinessLogicReport(address, logicResult, totalUsd));
          // Push naar dashboard
          if (SCANNER_API_KEY && RENDER_URL) {
            axios.post(`${RENDER_URL}/api/scanner/results`, {
              result: { address, businessLogic: logicResult, balanceUsd: totalUsd, time: new Date().toISOString() }
            }, { headers: { 'x-api-key': SCANNER_API_KEY }, timeout: 10000 }).catch(() => {});
          }
        } else if (logicResult && logicResult.findings && logicResult.findings.length > 0) {
          await safeSend(`🧠 *Business Logic Audit*\n━━━━━━━━━━━━━━━━━━━━\n\`${address}\`\n🟡 Mogelijke bugs gevonden maar exploit niet bevestigd\n━━━━━━━━━━━━━━━━━━━━\n\n${logicResult.findings.map(f => `• ${f}`).join('\n')}`);
        } else {
          console.log(`[WORKER] Business logic audit: geen exploits gevonden voor ${address}`);
        }
      } catch (e) {
        console.error(`[WORKER] Business logic audit fout: ${e.message}`);
      }
    }

    console.log(`[WORKER] Analyse klaar: ${address}`);
    process.send({ done: true, address });
  } catch (err) {
    console.error(`[WORKER] Fout: ${err.message}`);
    process.send({ done: true, address, error: err.message });
  }
});

console.log('[WORKER] Analyse worker gestart, wacht op opdrachten...');
