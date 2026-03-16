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
const MYTHRIL_PATH = 'C:/Users/moham/AppData/Local/Programs/Python/Python311/Scripts/myth.exe';
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
    if (versionMatch) {
      solcVersion = versionMatch[1];
      try {
        execSync(`C:/Users/moham/AppData/Local/Python/pythoncore-3.14-64/Scripts/solc-select install ${solcVersion}`, { timeout: 30000 });
        execSync(`C:/Users/moham/AppData/Local/Python/pythoncore-3.14-64/Scripts/solc-select use ${solcVersion}`, { timeout: 10000 });
      } catch (e) {}
    }

    const winPath = mainFile.replace(/\//g, '\\');
    const solcBinary = SOLC_PATH.replace(/\//g, '\\');
    let output = '';
    const env = { ...process.env, PYTHONIOENCODING: 'utf-8', PYTHONUTF8: '1', SOLC_BINARY: solcBinary, PATH: process.env.PATH + ';C:/Users/moham/AppData/Local/Python/pythoncore-3.14-64/Scripts' };

    for (const solcArgs of ['', ' --solc-args "--via-ir --optimize"']) {
      const cmd = `"${MYTHRIL_PATH}" analyze "${winPath}" --solv ${solcVersion} -o json --execution-timeout 120${solcArgs}`;
      try {
        output = execSync(cmd, { timeout: 300000, encoding: 'utf-8', cwd: tmpDir, env });
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
      model: 'claude-sonnet-4-6-20250514', max_tokens: 1000,
      messages: [{ role: 'user', content: prompt }]
    }, {
      headers: { 'x-api-key': CLAUDE_API_KEY, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' },
      timeout: 30000
    });
    return response.data.content[0].text;
  } catch (err) { console.error('[WORKER-AI] Fout:', err.message); return null; }
}

// === SAVE RESULT ===
function saveResult(address, balanceUsd, breakdown, slither, mythril, security) {
  let results = [];
  try { if (fs.existsSync(RESULTS_FILE)) results = JSON.parse(fs.readFileSync(RESULTS_FILE, 'utf-8')); } catch (e) {}

  const totalHigh = (slither.success ? slither.findings.filter(f => f.impact === 'High').length : 0)
    + (mythril.success ? mythril.issues.filter(i => i.severity === 'High').length : 0)
    + (security.success ? security.findings.filter(f => f.severity === 'HIGH').length : 0);
  const totalMedium = (slither.success ? slither.findings.filter(f => f.impact === 'Medium').length : 0)
    + (mythril.success ? mythril.issues.filter(i => i.severity === 'Medium').length : 0)
    + (security.success ? security.findings.filter(f => f.severity === 'MEDIUM').length : 0);

  const newResult = {
    address, balanceUsd, breakdown, time: new Date().toISOString(), totalHigh, totalMedium,
    contractName: slither.contractName || mythril.contractName || security.contractName || 'Onbekend',
    slither: { success: slither.success, high: slither.success ? slither.findings.filter(f => f.impact === 'High').length : 0, medium: slither.success ? slither.findings.filter(f => f.impact === 'Medium').length : 0, findings: slither.success ? slither.findings.filter(f => f.impact === 'High' || f.impact === 'Medium').map(f => ({ check: f.check, impact: f.impact, description: (f.description || '').substring(0, 200) })) : [] },
    mythril: { success: mythril.success, high: mythril.success ? mythril.issues.filter(i => i.severity === 'High').length : 0, medium: mythril.success ? mythril.issues.filter(i => i.severity === 'Medium').length : 0, issues: mythril.success ? mythril.issues.filter(i => i.severity === 'High' || i.severity === 'Medium').map(i => ({ title: i.title, severity: i.severity, swcId: i.swcId, function: i.function })) : [] },
    security: { success: security.success, findings: security.success ? security.findings : [] }
  };

  results.unshift(newResult);
  if (results.length > 200) results.pop();

  try { fs.writeFileSync(RESULTS_FILE, JSON.stringify(results, null, 2)); } catch (e) { console.error('[WORKER] Save fout:', e.message); }

  // Push naar Render dashboard
  if (SCANNER_API_KEY) {
    axios.post(`${RENDER_URL}/api/scanner/results`, { result: newResult }, {
      headers: { 'x-api-key': SCANNER_API_KEY }, timeout: 10000
    }).catch(e => console.error('[WORKER] Render push fout:', e.message));
  }
}

// === MAIN: ontvang opdracht van parent process ===
process.on('message', async (msg) => {
  const { address, totalUsd, breakdown } = msg;
  console.log(`[WORKER] Analyse gestart: ${address} ($${totalUsd})`);

  try {
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

    // 4. AI (optioneel)
    if (CLAUDE_API_KEY) {
      await safeSend(`🤖 *AI analyse...*\n\`${address}\``);
      const aiText = await runAIAnalysis(address, securityResult.sourceCode || '',
        slitherResult.success ? slitherResult.findings : [],
        mythrilResult.success ? mythrilResult.issues : [],
        securityResult.success ? securityResult.findings : []);
      if (aiText) await safeSend(`🤖 *AI Deep Analyse*\n━━━━━━━━━━━━━━━━━━━━\n\`${address}\`\n━━━━━━━━━━━━━━━━━━━━\n\n${aiText}`);
    }

    // 5. Opslaan
    saveResult(address, totalUsd, breakdown, slitherResult, mythrilResult, securityResult);

    console.log(`[WORKER] Analyse klaar: ${address}`);
    process.send({ done: true, address });
  } catch (err) {
    console.error(`[WORKER] Fout: ${err.message}`);
    process.send({ done: true, address, error: err.message });
  }
});

console.log('[WORKER] Analyse worker gestart, wacht op opdrachten...');
