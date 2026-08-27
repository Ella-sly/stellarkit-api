// API Key Authentication Middleware
// Optional mode: activated via REQUIRE_API_KEY=true env var
// Clients send key via X-API-Key header
// Keys configurable via API_KEYS env var (comma-separated)
// Keys are hashed with SHA-256 on startup; plaintext is cleared from memory
// Returns 401 for missing/invalid key when enabled
// /health and / endpoints are always public

const crypto = require('crypto');

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest();
}

// Hash all configured keys once at startup and clear the plaintext env var.
let _hashedKeys = null;

function getHashedKeys() {
  if (_hashedKeys !== null) return _hashedKeys;

  const raw = process.env.API_KEYS || '';
  const keys = raw.split(',').map(k => k.trim()).filter(Boolean);
  _hashedKeys = keys.map(sha256);

  // Clear plaintext keys from the environment after hashing
  if (process.env.API_KEYS !== undefined) {
    process.env.API_KEYS = '';
  }

  return _hashedKeys;
}

// Expose for testing — allows resetting the cached hashes between test runs.
function _resetHashedKeys() {
  _hashedKeys = null;
}

const apiKeyMiddleware = (req, res, next) => {
  const requireApiKey = process.env.REQUIRE_API_KEY === 'true';

  if (!requireApiKey) {
    return next();
  }

  // Allow public access to health check and root endpoint
  if (req.path === '/health' || req.path === '/') {
    return next();
  }

  const rawApiKey = req.headers["x-api-key"];
  const apiKey = rawApiKey ? rawApiKey.trim() : null;

  if (!apiKey) {
    return res.status(401).json({
      success: false,
      error: {
        type: 'Unauthorized',
        message: 'Missing API key. Please provide X-API-Key header.',
      },
    });
  }

  const hashedKeys = getHashedKeys();

  if (hashedKeys.length === 0) {
    return res.status(401).json({
      success: false,
      error: {
        type: 'Unauthorized',
        message: 'API key authentication is enabled but no valid keys are configured.',
      },
    });
  }

  // Hash the incoming key and compare against stored hashes (constant-time)
  const incomingHash = sha256(apiKey);
  const keyIsValid = hashedKeys.some(storedHash =>
    crypto.timingSafeEqual(storedHash, incomingHash)
  );

  if (!keyIsValid) {
    return res.status(401).json({
      success: false,
      error: {
        type: 'Unauthorized',
        message: 'Invalid API key.',
      },
    });
  }

  next();
};

module.exports = apiKeyMiddleware;
module.exports._resetHashedKeys = _resetHashedKeys;