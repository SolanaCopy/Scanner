// Rescan contracten met hoge fouten uit eerdere sessie
require('dotenv').config();
const { execSync } = require('child_process');
const axios = require('axios');
const fs = require('fs');
const path = require('path');

const BSCSCAN_KEY = process.env.BSCSCAN_API_KEY;
const SLITHER_PATH = 'C:/Users/moham/AppData/Local/Python/pythoncore-3.14-64/Scripts/slither.exe';
const MYTHRIL_PATH = 'C:/Users/moham/AppData/Local/Programs/Python/Python311/Scripts/myth.exe';
const SOLC_PATH = 'C:/Users/moham/AppData/Local/Python/pythoncore-3.14-64/Scripts/solc.exe';
const RESULTS_FILE = path.join(__dirname, 'scan_results.json');

// Contracten met HIGH severity uit eerdere log
const targets = [
  { address: '0xB685760EBD368a891F27ae547391F4E2A289895b', name: 'Bridgers', balance: 122387, issue: 'Reentrancy - call{value} naar user-supplied adres' },
  { address: '0xc55B409014480C4580A7Df71f4BB08CE20fb8935', name: 'AToken', balance: 4701, issue: 'Integer Underflow' },
  { address: '0x8599068597fd27D87514CB90c42300c03a474084', name: 'ERC1967Proxy', balance: 246022, issue: 'Delegatecall naar user-supplied adres' },
  { address: '0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789', name: 'EntryPoint', balance: 61929, issue: 'Reentrancy via factory call' },
  { address: '0x99F008922815f3C32ee33E894478931e2B43F655', name: 'ERC1967Proxy', balance: 13410, issue: 'Assertion violation' },
];

async function getSource(address) {
  const url = `https://api.etherscan.io/v2/api?chainid=56&module=contract&action=getsourcecode&address=${address}&apikey=${BSCSCAN_KEY}`;
  const res = await axios.get(url);
  if (res.data.status !== '1' || !res.data.result[0].SourceCode) return null;
  return res.data.result[0];
}

async function runSlither(address) {
  try {
    const contract = await getSource(address);
    if (!contract) return { success: false, error: 'Geen source' };

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
      } catch (e) {
        fs.writeFileSync(path.join(tmpDir, `${contractName}.sol`), sourceCode);
      }
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
    } catch (e) {}

    return { success: true, findings, contractName, compilerVersion };
  } catch (err) { return { success: false, error: err.message }; }
}

async function runMythril(address) {
  try {
    const contract = await getSource(address);
    if (!contract) return { success: false, error: 'Geen source' };

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
        issues = json.issues.map(i => ({ title: i.title, severity: i.severity, swcId: i['swc-id'], description: (i.description || '').substring(0, 300), function: i.function }));
      }
    } catch (e) {}

    return { success: true, issues, contractName, compilerVersion };
  } catch (err) { return { success: false, error: err.message }; }
}

async function runSecurityCheck(address) {
  try {
    const contract = await getSource(address);
    if (!contract) return { success: false, error: 'Geen source', findings: [] };

    let sourceCode = contract.SourceCode;
    const contractName = contract.ContractName || 'Contract';
    if (sourceCode.startsWith('{{')) {
      try {
        const parsed = JSON.parse(sourceCode.slice(1, -1));
        const sources = parsed.sources || parsed;
        sourceCode = Object.values(sources).map(s => s.content || s).join('\n');
      } catch (e) {}
    }

    const code = sourceCode.toLowerCase();
    const findings = [];

    if (/function\s+mint\s*\(/.test(sourceCode) && /onlyowner|_owner|owner\(\)/.test(code)) {
      const hasMax = /maxsupply|max_supply|cap/.test(code);
      findings.push({ category: 'RUGPULL', severity: hasMax ? 'MEDIUM' : 'HIGH', title: 'Owner Mint', detail: hasMax ? 'Mint met cap' : 'Onbeperkte mint door owner' });
    }
    if (/function\s+(blacklist|addblacklist|blocklist|ban)\s*\(/i.test(sourceCode)) findings.push({ category: 'RUGPULL', severity: 'HIGH', title: 'Blacklist', detail: 'Owner kan adressen blokkeren' });
    if (/function\s+pause\s*\(/i.test(sourceCode) && /whennotpaused|_paused/i.test(code)) findings.push({ category: 'RUGPULL', severity: 'MEDIUM', title: 'Pause', detail: 'Owner kan transfers pauzeren' });
    if (/selfdestruct|suicide/i.test(code)) findings.push({ category: 'RUGPULL', severity: 'HIGH', title: 'Selfdestruct', detail: 'Contract kan vernietigd worden' });
    if (/delegatecall|upgradeto|_implementation/i.test(code)) findings.push({ category: 'RUGPULL', severity: 'MEDIUM', title: 'Upgradeable', detail: 'Logica kan vervangen worden' });

    if (/\.call\{value:|\.call\.value\(/.test(sourceCode) && !/reentrancyguard|nonreentrant/i.test(code)) findings.push({ category: 'EXPLOIT', severity: 'HIGH', title: 'Reentrancy', detail: 'External call zonder guard' });
    if (/require\s*\(\s*tx\.origin\s*==/.test(sourceCode)) findings.push({ category: 'EXPLOIT', severity: 'HIGH', title: 'tx.origin', detail: 'Kwetsbaar voor phishing' });
    if (/balanceof\s*\(\s*address\s*\(\s*this\s*\)\s*\)/i.test(sourceCode) && !/twap|timeweighted/i.test(code) && /price|rate|ratio/i.test(code)) findings.push({ category: 'LOGIC', severity: 'HIGH', title: 'Flash Loan', detail: 'Spot balance als prijs oracle' });

    return { success: true, findings, contractName };
  } catch (err) { return { success: false, error: err.message, findings: [] }; }
}

async function main() {
  let results = [];
  try { if (fs.existsSync(RESULTS_FILE)) results = JSON.parse(fs.readFileSync(RESULTS_FILE, 'utf-8')); } catch(e) {}

  for (const target of targets) {
    console.log(`\n${'='.repeat(60)}`);
    console.log(`Scanning: ${target.name} (${target.address})`);
    console.log(`Balance: $${target.balance.toLocaleString()}`);
    console.log(`Eerder gevonden: ${target.issue}`);
    console.log('='.repeat(60));

    console.log('[1/3] Slither...');
    const slither = await runSlither(target.address);
    const sH = slither.success ? slither.findings.filter(f => f.impact === 'High').length : 0;
    const sM = slither.success ? slither.findings.filter(f => f.impact === 'Medium').length : 0;
    console.log(`  Slither: ${sH} High, ${sM} Medium`);

    console.log('[2/3] Mythril...');
    const mythril = await runMythril(target.address);
    const mH = mythril.success ? mythril.issues.filter(i => i.severity === 'High').length : 0;
    const mM = mythril.success ? mythril.issues.filter(i => i.severity === 'Medium').length : 0;
    console.log(`  Mythril: ${mH} High, ${mM} Medium`);

    console.log('[3/3] Security check...');
    const security = await runSecurityCheck(target.address);
    const secH = security.success ? security.findings.filter(f => f.severity === 'HIGH').length : 0;
    console.log(`  Security: ${secH} High findings`);

    const totalHigh = sH + mH + secH;
    const totalMedium = sM + mM + (security.success ? security.findings.filter(f => f.severity === 'MEDIUM').length : 0);

    console.log(`\n  TOTAAL: ${totalHigh} HIGH, ${totalMedium} MEDIUM`);

    results.push({
      address: target.address,
      contractName: target.name,
      balanceUsd: target.balance,
      time: new Date().toISOString(),
      totalHigh,
      totalMedium,
      slither: {
        success: slither.success,
        high: sH, medium: sM,
        findings: slither.success ? slither.findings.filter(f => f.impact === 'High' || f.impact === 'Medium').map(f => ({ check: f.check, impact: f.impact, description: (f.description || '').substring(0, 300) })) : []
      },
      mythril: {
        success: mythril.success,
        high: mH, medium: mM,
        issues: mythril.success ? mythril.issues.filter(i => i.severity === 'High' || i.severity === 'Medium').map(i => ({ title: i.title, severity: i.severity, swcId: i.swcId, function: i.function })) : []
      },
      security: {
        success: security.success,
        findings: security.success ? security.findings : []
      }
    });

    // Even wachten voor API rate limits
    await new Promise(r => setTimeout(r, 2000));
  }

  // Sorteer op totalHigh (meeste fouten eerst)
  results.sort((a, b) => b.totalHigh - a.totalHigh || b.totalMedium - a.totalMedium);

  fs.writeFileSync(RESULTS_FILE, JSON.stringify(results, null, 2));
  console.log(`\n${'='.repeat(60)}`);
  console.log(`Klaar! ${results.length} resultaten opgeslagen in scan_results.json`);
  console.log('='.repeat(60));
}

main().catch(err => { console.error('FOUT:', err); process.exit(1); });
