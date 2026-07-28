const express = require("express");
const fetch = require("node-fetch");
const { validateIOC } = require("../middleware/sanitize");
const { iocPivot } = require("../middleware/rateLimit");

const router = express.Router();

const VT_ENDPOINTS = {
  ip: v => `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(v)}`,
  hash: v => `https://www.virustotal.com/api/v3/files/${encodeURIComponent(v)}`,
  domain: v => `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(v)}`,
};

router.get("/pivot", iocPivot, validateIOC, async (req, res) => {
  const { value, type } = req.ioc;
  const out = {};
  const jobs = [];

  if (type === "ip") {
    jobs.push(
      fetch(`https://ipinfo.io/${encodeURIComponent(value)}/json`)
        .then(r => r.json()).then(d => { out.ipinfo = d; }).catch(() => {})
    );

    jobs.push(
      fetch(`https://internetdb.shodan.io/${encodeURIComponent(value)}`)
        .then(r => r.status === 404
          ? { ports: [], vulns: [], tags: [], hostnames: [], notFound: true }
          : r.json()
        )
        .then(d => { out.shodan = d; }).catch(() => {})
    );

    if (process.env.ABUSEIPDB_KEY) {
      jobs.push(
        fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(value)}&maxAgeInDays=90&verbose`, {
          headers: { Key: process.env.ABUSEIPDB_KEY, Accept: "application/json" },
        }).then(r => r.json()).then(d => { out.abuseipdb = d.data; }).catch(() => {})
      );
    }
  }

  // VT returns 404 for IPs/domains with no data, not an error — catch handles it
  if (VT_ENDPOINTS[type] && process.env.VIRUSTOTAL_KEY) {
    jobs.push(
      fetch(VT_ENDPOINTS[type](value), { headers: { "x-apikey": process.env.VIRUSTOTAL_KEY } })
        .then(r => r.json()).then(d => { out.virustotal = d.data?.attributes; }).catch(() => {})
    );
  }

  // abuse.ch returns 200 even for unknown IOCs, check data field before using
  jobs.push(
    fetch("https://threatfox-api.abuse.ch/api/v1/", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Auth-Key": process.env.THREATFOX_KEY || "",
      },
      body: JSON.stringify({ query: "search_ioc", search_term: value }),
    }).then(r => r.json()).then(d => { out.threatfox = d.data || []; }).catch(() => {})
  );

  jobs.push(
    fetch("https://urlhaus-api.abuse.ch/v1/host/", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Auth-Key": process.env.URLHAUS_KEY || "",
      },
      body: JSON.stringify({ host: value }),
    }).then(r => r.json()).then(d => { out.urlhaus = d; }).catch(() => {})
  );

  await Promise.allSettled(jobs);
  res.json({ ioc: value, type, results: out });
});

module.exports = router;