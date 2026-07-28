const express = require("express");
const { queryAll, queryOne, run, runGetId } = require("../db/database");
const { standard } = require("../middleware/rateLimit");

const router = express.Router();

router.get("/campaigns", standard, (req, res) => {
  res.json(queryAll("SELECT * FROM campaigns ORDER BY updated DESC"));
});

router.post("/campaigns", standard, (req, res) => {
  const name = (req.body?.name || "").trim().slice(0, 200);
  if (!name) return res.status(400).json({ error: "name required" });
  const id = runGetId(
    "INSERT INTO campaigns (name, created, updated) VALUES (?, datetime('now'), datetime('now'))",
    [name]
  );
  res.json({ id, name });
});

router.delete("/campaigns/:id", standard, (req, res) => {
  const id = parseInt(req.params.id);
  if (!id) return res.status(400).json({ error: "bad id" });
  run("DELETE FROM campaigns WHERE id = ?", [id]);
  res.json({ deleted: id });
});

router.get("/campaigns/:id/entries", standard, (req, res) => {
  const id = parseInt(req.params.id);
  if (!id) return res.status(400).json({ error: "bad id" });
  res.json(queryAll("SELECT * FROM workbook_entries WHERE campaign_id = ? ORDER BY ts DESC", [id]));
});

router.post("/campaigns/:id/entries", standard, (req, res) => {
  const campaign_id = parseInt(req.params.id);
  if (!campaign_id) return res.status(400).json({ error: "bad id" });

  const { type, value, ioc_type, note } = req.body || {};
  if (!type || !value) return res.status(400).json({ error: "type and value required" });

  const id = runGetId(
    "INSERT INTO workbook_entries (campaign_id, type, value, ioc_type, note, ts) VALUES (?, ?, ?, ?, ?, datetime('now'))",
    [campaign_id, type.slice(0, 50), value.slice(0, 512), (ioc_type || "").slice(0, 50), (note || "").slice(0, 2000)]
  );

  run("UPDATE campaigns SET updated = datetime('now') WHERE id = ?", [campaign_id]);
  res.json({ id, campaign_id });
});

router.delete("/entries/:id", standard, (req, res) => {
  const id = parseInt(req.params.id);
  if (!id) return res.status(400).json({ error: "bad id" });
  run("DELETE FROM workbook_entries WHERE id = ?", [id]);
  res.json({ deleted: id });
});

router.get("/campaigns/:id/export", standard, (req, res) => {
  const id = parseInt(req.params.id);
  if (!id) return res.status(400).json({ error: "bad id" });
  const campaign = queryOne("SELECT * FROM campaigns WHERE id = ?", [id]);
  if (!campaign) return res.status(404).json({ error: "not found" });
  const entries = queryAll("SELECT * FROM workbook_entries WHERE campaign_id = ? ORDER BY ts DESC", [id]);
  res.json({ campaign, entries, exported: new Date().toISOString() });
});

module.exports = router;