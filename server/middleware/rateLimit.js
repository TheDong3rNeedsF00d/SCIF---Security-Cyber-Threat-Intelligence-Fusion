const rateLimit = require("express-rate-limit");

const make = (max, windowMs = 60_000) =>
  rateLimit({ windowMs, max, standardHeaders: true, legacyHeaders: false,
    message: { error: "rate limit exceeded" } });

module.exports = {
  standard: make(60),
  iocPivot: make(20),   // estimating each pivot fans out around 5 upstream apis
  auth: make(50, 15 * 60_000),
};
