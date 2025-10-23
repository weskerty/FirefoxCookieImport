#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const { promisify } = require('util');
const { execSync } = require('child_process');

const colors = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m'
};

function log(color, ...args) {
  console.log(color + args.join(' ') + colors.reset);
}

function parseNetscape(filePath) {
  const lines = fs.readFileSync(filePath, 'utf-8').split(/\r?\n/);
  const cookies = [];

  log(colors.cyan, '\n📖 Parseando formato Netscape...\n');

  for (let lineOriginal of lines) {
    let line = lineOriginal;
    let isHttpOnly = false;

    if (line.startsWith('#HttpOnly_')) {
      isHttpOnly = true;
      line = line.substring(10);
    }

    line = line.trim();
    if (!line || line.startsWith('#')) continue;

    const parts = line.split('\t');
    if (parts.length < 7) continue;

    const domain = parts[0];
    const includeSubdomains = parts[1];
    const pathField = parts[2];
    const secure = parts[3];
    const expiryStr = parts[4];
    const name = parts[5];
    const value = parts.slice(6).join('\t');

    const isSecure = secure.toUpperCase() === 'TRUE';

    let expiry = parseInt(expiryStr) || 0;
    if (expiry < 4000000000) {
      expiry = expiry * 1000;
    }

    log(colors.blue, `📝 ${name} @ ${domain}`);
    log(colors.blue, `   expiry original: ${expiryStr} → expiry Firefox: ${expiry}`);

    cookies.push({
      name,
      value,
      domain,
      path: pathField,
      secure: isSecure,
      httpOnly: isHttpOnly,
      expiry: expiry,
      sameSite: 0
    });
  }

  return cookies;
}

function detectFormat(filePath) {
  const content = fs.readFileSync(filePath, 'utf-8').trim();

  try {
    JSON.parse(content);
    log(colors.green, '✅ Formato detectado: JSON');
    return 'json';
  } catch (e) {
    if (content.includes('# Netscape HTTP Cookie File') || content.includes('\t')) {
      log(colors.green, '✅ Formato detectado: Netscape');
      return 'netscape';
    }
  }

  throw new Error('Formato no reconocido');
}

function parseJSON(filePath) {
  const data = JSON.parse(fs.readFileSync(filePath, 'utf-8'));

  if (Array.isArray(data)) {
    return data.map(c => {
      let expiry = c.expirationDate || c.expiry || c.expires || c.Expires || 0;

      if (expiry < 4000000000) {
        expiry = expiry * 1000;
      }

      return {
        name: c.name || c.Name,
        value: c.value || c.Value || c.content || c.Content || '',
        domain: c.domain || c.Domain || c.host || c.Host,
        path: c.path || c.Path || '/',
        secure: c.secure || c.Secure || c.isSecure || false,
        httpOnly: c.httpOnly || c.HttpOnly || c.isHttpOnly || false,
        expiry: expiry,
        sameSite: c.sameSite || 0
      };
    });
  }

  throw new Error('Formato JSON no reconocido');
}

async function verifyFirefoxSchema(db) {
  const getAsync = promisify(db.get.bind(db));

  log(colors.cyan, '\n🔍 Verificando esquema de Firefox...');

  const schema = await getAsync(
    "SELECT sql FROM sqlite_master WHERE type='table' AND name='moz_cookies'"
  );

  if (!schema) {
    throw new Error('Tabla moz_cookies no encontrada');
  }

  log(colors.green, '✅ Esquema verificado\n');
}

async function importFromFile(cookieFile, firefoxDbPath) {
  const format = detectFormat(cookieFile);
  const cookies = format === 'json' ? parseJSON(cookieFile) : parseNetscape(cookieFile);

  log(colors.green, `\n✅ Total parseadas: ${cookies.length} cookies\n`);

  const db = new sqlite3.Database(firefoxDbPath);
  const runAsync = promisify(db.run.bind(db));
  const getAsync = promisify(db.get.bind(db));

  await verifyFirefoxSchema(db);

  let imported = 0, updated = 0, skipped = 0;

  log(colors.cyan, '📥 Comenzando importación...\n');

  for (const cookie of cookies) {
    const now = Date.now() * 1000;

    const schemeMap = cookie.secure ? 2 : 0;

    log(colors.yellow, `\n🔄 ${cookie.name} @ ${cookie.domain}`);
    log(colors.blue, `   Netscape → Firefox:`);
    log(colors.blue, `   expiry: ${cookie.expiry} ms (${new Date(cookie.expiry).toISOString()})`);
    log(colors.blue, `   lastAccessed: ${now} µs`);
    log(colors.blue, `   creationTime: ${now} µs`);
    log(colors.blue, `   isSecure: ${cookie.secure ? 1 : 0}`);
    log(colors.blue, `   isHttpOnly: ${cookie.httpOnly ? 1 : 0}`);
    log(colors.blue, `   sameSite: ${cookie.sameSite}`);
    log(colors.blue, `   schemeMap: ${schemeMap}`);

    try {
      const existing = await getAsync(
        `SELECT id FROM moz_cookies
        WHERE name=? AND host=? AND path=? AND originAttributes=''`,
        [cookie.name, cookie.domain, cookie.path]
      );

      if (existing) {
        await runAsync(
          `UPDATE moz_cookies
          SET value=?, expiry=?, lastAccessed=?, isSecure=?, isHttpOnly=?, sameSite=?, schemeMap=?
          WHERE id=?`,
          [cookie.value, cookie.expiry, now, cookie.secure ? 1 : 0,
          cookie.httpOnly ? 1 : 0, cookie.sameSite, schemeMap, existing.id]
        );
        log(colors.green, `   ✅ ACTUALIZADA (id: ${existing.id})`);
        updated++;
      } else {
        await runAsync(
          `INSERT INTO moz_cookies
          (originAttributes, name, value, host, path, expiry, lastAccessed,
           creationTime, isSecure, isHttpOnly, inBrowserElement, sameSite,
           schemeMap, isPartitionedAttributeSet)
          VALUES ('', ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, 0)`,
                       [cookie.name, cookie.value, cookie.domain, cookie.path, cookie.expiry,
                       now, now, cookie.secure ? 1 : 0, cookie.httpOnly ? 1 : 0, cookie.sameSite, schemeMap]
        );
        log(colors.green, `   ✅ INSERTADA`);
        imported++;
      }
    } catch (err) {
      log(colors.red, `   ❌ ERROR: ${err.message}`);
      skipped++;
    }
  }

  log(colors.cyan, '\n🧹 Optimizando base de datos...');
  await runAsync('VACUUM');
  await runAsync('REINDEX');

  db.close();

  return { imported, updated, skipped };
}

async function main() {
  const readline = require('readline');
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });
  const question = (q) => new Promise(res => rl.question(q, res));

  try {
    log(colors.bright + colors.cyan, '\n╔════════════════════════════════════════════╗');
    log(colors.bright + colors.cyan, '║  Firefox Cookie Importer v3.0    ║');
    log(colors.bright + colors.cyan, '╚════════════════════════════════════════════╝\n');

    log(colors.red, '🔴 Cerrando Firefox/Zen...');
    try {
      execSync('pkill -9 firefox 2>/dev/null || pkill -9 zen 2>/dev/null || killall -9 firefox 2>/dev/null', { stdio: 'ignore' });
      await new Promise(resolve => setTimeout(resolve, 2000));
      log(colors.green, '✅ Navegador cerrado\n');
    } catch (e) {
      log(colors.yellow, '⚠️  Cierra manualmente el navegador\n');
    }

    const firefoxProfile = await question('Ruta al perfil de Firefox/Zen: ');
    const firefoxDbPath = path.join(firefoxProfile, 'cookies.sqlite');

    if (!fs.existsSync(firefoxDbPath)) {
      throw new Error('cookies.sqlite no encontrado');
    }


    ['-wal', '-shm'].forEach(ext => {
      const p = firefoxDbPath + ext;
      if (fs.existsSync(p)) {
        fs.unlinkSync(p);
        log(colors.yellow, `🗑️  Eliminado: ${path.basename(p)}`);
      }
    });

    const backupPath = `${firefoxDbPath}.backup.${Date.now()}`;
    fs.copyFileSync(firefoxDbPath, backupPath);
    log(colors.green, `✅ Backup: ${backupPath}`);

    const cookieFile = await question('\nRuta al archivo de cookies (Netscape .txt o JSON): ');
    if (!fs.existsSync(cookieFile)) {
      throw new Error('Archivo no encontrado');
    }

    rl.close();

    const stats = await importFromFile(cookieFile, firefoxDbPath);

    log(colors.bright + colors.green, '\n╔════════════════════════════════════════════╗');
    log(colors.bright + colors.green, '║           IMPORTACIÓN COMPLETADA          ║');
    log(colors.bright + colors.green, '╚════════════════════════════════════════════╝');
    log(colors.green, `✅ Importadas:   ${stats.imported}`);
    log(colors.yellow, `🔄 Actualizadas: ${stats.updated}`);
    log(colors.red, `⚠️  Omitidas:    ${stats.skipped}`);
    log(colors.cyan, '\n🔧 Ahora abre el navegador y verifica\n');

  } catch (err) {
    log(colors.red, '\n💥 ERROR:', err.message);
    console.error(err.stack);
    process.exit(1);
  }
}

main();
