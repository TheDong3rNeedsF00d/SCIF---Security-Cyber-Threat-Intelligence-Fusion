const initSqlJs = require("sql.js");
const path = require("path");
const fs = require("fs");

const DB_PATH = process.env.DB_PATH || path.join(__dirname, "../data/scif.db");

let _db = null;

// sql.js runs SQLite in memory — we load from disk on startup and save back on writes
function saveDb() {
  const data = _db.export();
  fs.writeFileSync(DB_PATH, Buffer.from(data));
}

async function initDb() {
  const SQL = await initSqlJs();

  if (fs.existsSync(DB_PATH)) {
    const fileBuffer = fs.readFileSync(DB_PATH);
    _db = new SQL.Database(fileBuffer);
  } else {
    _db = new SQL.Database();
  }

  _db.run(`
    CREATE TABLE IF NOT EXISTS campaigns (
      id      INTEGER PRIMARY KEY AUTOINCREMENT,
      name    TEXT NOT NULL,
      created TEXT NOT NULL DEFAULT (datetime('now')),
      updated TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS workbook_entries (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      campaign_id INTEGER REFERENCES campaigns(id) ON DELETE CASCADE,
      type        TEXT NOT NULL,
      value       TEXT NOT NULL,
      ioc_type    TEXT,
      note        TEXT,
      ts          TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_entries_campaign ON workbook_entries(campaign_id);
  `);

  saveDb();
  return _db;
}

function getDb() {
  if (!_db) throw new Error("DB not initialized — call initDb() first");
  return _db;
}

// Wrap sql.js query results into array of objects — sql.js returns raw column arrays
function queryAll(sql, params = []) {
  const stmt = _db.prepare(sql);
  stmt.bind(params);
  const rows = [];
  while (stmt.step()) {
    rows.push(stmt.getAsObject());
  }
  stmt.free();
  return rows;
}

function queryOne(sql, params = []) {
  return queryAll(sql, params)[0] || null;
}

function run(sql, params = []) {
  _db.run(sql, params);
  saveDb(); // persist to disk after every write
}

function runGetId(sql, params = []) {
  _db.run(sql, params);
  const result = queryOne("SELECT last_insert_rowid() as id");
  saveDb();
  return result?.id;
}

module.exports = { initDb, getDb, queryAll, queryOne, run, runGetId, saveDb };