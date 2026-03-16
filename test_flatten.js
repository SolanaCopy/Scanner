require('dotenv').config();
const axios = require('axios');
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const BSCSCAN_KEY = process.env.BSCSCAN_API_KEY;
const address = '0x8A8a43d6A9b844300E6a82D9C8568576f5640dcA';

(async () => {
  const url = `https://api.etherscan.io/v2/api?chainid=56&module=contract&action=getsourcecode&address=${address}&apikey=${BSCSCAN_KEY}`;
  const res = await axios.get(url);
  const contract = res.data.result[0];
  const sourceCode = contract.SourceCode;
  const contractName = contract.ContractName;

  const parsed = JSON.parse(sourceCode.slice(1, -1));
  const sources = parsed.sources || parsed;
  const files = Object.keys(sources);

  // Dependency graph with relative path resolution
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
          for (const p of parts) {
            if (p === '..') normalized.pop();
            else if (p !== '.') normalized.push(p);
          }
          resolved = normalized.join('/');
        }
        const match = files.find(k => k === resolved) || files.find(k => k === imp) || files.find(k => k.endsWith(resolved));
        if (match) {
          imports[f].push(match);
        } else {
          console.log(`  MISS: ${f} imports ${imp} (resolved: ${resolved})`);
        }
      }
    }
  }

  console.log('Deps:');
  for (const [f, deps] of Object.entries(imports)) {
    if (deps.length) console.log(`  ${f.split('/').pop()} -> ${deps.map(d=>d.split('/').pop()).join(', ')}`);
  }

  // Topological sort
  const ordered = [];
  const visited = new Set();
  function visit(f) {
    if (visited.has(f)) return;
    visited.add(f);
    for (const dep of (imports[f] || [])) visit(dep);
    ordered.push(f);
  }
  for (const f of files) visit(f);

  console.log('\nOrder:');
  ordered.forEach((f, i) => console.log(`  ${i+1}. ${f.split('/').pop()}`));

  // Flatten
  let flatCode = '';
  let licenseAdded = false;
  let pragmaAdded = false;
  for (const filePath of ordered) {
    const content = sources[filePath].content || sources[filePath];
    for (const line of content.split('\n')) {
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

  const solFile = 'C:\\bsc-scanner\\tmp_test\\BMNPool.sol';
  fs.writeFileSync(solFile, flatCode);

  try {
    execSync(`"C:/Users/moham/AppData/Local/Python/pythoncore-3.14-64/Scripts/solc.exe" "${solFile}" --bin 2>&1`, { encoding: 'utf-8', timeout: 30000 });
    console.log('\nSOLC: OK!');
  } catch(e) {
    console.log('\nSOLC ERROR:');
    console.log(((e.stdout || '') + (e.stderr || '')).substring(0, 500));
  }
})();
