const express = require("express");
const router = express.Router();
const rateLimit = require("express-rate-limit");
const oauthController = require("../controllers/oauth.controller");

// Rate limiting configuration
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
});

// Apply rate limiting to all routes
router.use(limiter);

// Token generation endpoint
router.post("/token", oauthController.generateToken);

// Token validation endpoint
router.post("/validate", oauthController.validateToken);

module.exports = router;
