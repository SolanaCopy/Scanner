// Auto-restart wrapper voor de BSC scanner
// Start index.js en herstart automatisch bij crashes

const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

const SCANNER_DIR = __dirname;
const LOG_FILE = path.join(SCANNER_DIR, 'scanner.log');
const RESTART_DELAY = 10000; // 10 sec wachten voor herstart
const MAX_RESTARTS_PER_HOUR = 10;

let restartCount = 0;
let restartWindow = Date.now();
let scannerProcess = null;

function log(msg) {
  const line = `[WATCHDOG] ${new Date().toISOString()} ${msg}`;
  console.log(line);
  try { fs.appendFileSync(LOG_FILE, line + '\n'); } catch(e) {}
}

function startScanner() {
  // Reset restart counter elk uur
  if (Date.now() - restartWindow > 3600000) {
    restartCount = 0;
    restartWindow = Date.now();
  }

  if (restartCount >= MAX_RESTARTS_PER_HOUR) {
    log(`Te veel restarts (${MAX_RESTARTS_PER_HOUR}/uur) — gestopt. Handmatig herstarten nodig.`);
    process.exit(1);
  }

  log(`Scanner starten (restart #${restartCount})...`);

  const logStream = fs.openSync(LOG_FILE, 'a');
  scannerProcess = spawn('node', ['index.js'], {
    cwd: SCANNER_DIR,
    stdio: ['ignore', logStream, logStream],
    env: { ...process.env }
  });

  scannerProcess.on('exit', (code) => {
    log(`Scanner gestopt met code ${code}`);
    restartCount++;

    if (code === 0) {
      log('Normale exit — geen herstart');
      return;
    }

    log(`Herstart over ${RESTART_DELAY/1000}s...`);
    setTimeout(startScanner, RESTART_DELAY);
  });

  scannerProcess.on('error', (err) => {
    log(`Scanner error: ${err.message}`);
    restartCount++;
    setTimeout(startScanner, RESTART_DELAY);
  });
}

// Graceful shutdown
process.on('SIGINT', () => {
  log('SIGINT ontvangen — scanner stoppen...');
  if (scannerProcess) scannerProcess.kill();
  process.exit(0);
});

process.on('SIGTERM', () => {
  log('SIGTERM ontvangen — scanner stoppen...');
  if (scannerProcess) scannerProcess.kill();
  process.exit(0);
});

log('Watchdog gestart');
startScanner();
