const crypto = require("crypto");

// Reset module cache before each test so env changes take effect
let apiKeyMiddleware;
let _resetHashedKeys;

beforeEach(() => {
  jest.resetModules();
  const mod = require("../src/middleware/apiKeyAuth");
  apiKeyMiddleware = mod;
  _resetHashedKeys = mod._resetHashedKeys;
});

function makeReqRes(path = "/account/test", apiKey = undefined) {
  const req = { headers: {}, path };
  if (apiKey !== undefined) req.headers["x-api-key"] = apiKey;
  const res = {
    status: jest.fn().mockReturnThis(),
    json: jest.fn().mockReturnThis(),
  };
  const next = jest.fn();
  return { req, res, next };
}

describe("API Key Middleware — hashing", () => {
  describe("When API key authentication is not required", () => {
    beforeEach(() => {
      process.env.REQUIRE_API_KEY = "false";
    });

    it("calls next() without checking keys", () => {
      const { req, res, next } = makeReqRes();
      apiKeyMiddleware(req, res, next);
      expect(next).toHaveBeenCalled();
      expect(res.status).not.toHaveBeenCalled();
    });
  });

  describe("When API key authentication is required", () => {
    beforeEach(() => {
      process.env.REQUIRE_API_KEY = "true";
      process.env.API_KEYS = "validkey1,validkey2";
      _resetHashedKeys();
    });

    afterEach(() => {
      _resetHashedKeys();
    });

    describe("public paths", () => {
      it("allows /health without a key", () => {
        const { req, res, next } = makeReqRes("/health");
        apiKeyMiddleware(req, res, next);
        expect(next).toHaveBeenCalled();
      });

      it("allows / without a key", () => {
        const { req, res, next } = makeReqRes("/");
        apiKeyMiddleware(req, res, next);
        expect(next).toHaveBeenCalled();
      });
    });

    describe("protected paths", () => {
      it("returns 401 when no X-API-Key header is provided", () => {
        const { req, res, next } = makeReqRes();
        apiKeyMiddleware(req, res, next);
        expect(res.status).toHaveBeenCalledWith(401);
        expect(res.json).toHaveBeenCalledWith({
          success: false,
          error: {
            type: "Unauthorized",
            message: "Missing API key. Please provide X-API-Key header.",
          },
        });
      });

      it("returns 401 when X-API-Key header is empty", () => {
        const { req, res, next } = makeReqRes("/account/test", "");
        apiKeyMiddleware(req, res, next);
        expect(res.status).toHaveBeenCalledWith(401);
      });

      it("returns 401 when the key is invalid", () => {
        const { req, res, next } = makeReqRes("/account/test", "wrongkey");
        apiKeyMiddleware(req, res, next);
        expect(res.status).toHaveBeenCalledWith(401);
        expect(res.json).toHaveBeenCalledWith({
          success: false,
          error: { type: "Unauthorized", message: "Invalid API key." },
        });
      });

      it("calls next() when a valid key is provided (validkey1)", () => {
        const { req, res, next } = makeReqRes("/account/test", "validkey1");
        apiKeyMiddleware(req, res, next);
        expect(next).toHaveBeenCalled();
        expect(res.status).not.toHaveBeenCalled();
      });

      it("calls next() when a valid key is provided (validkey2)", () => {
        const { req, res, next } = makeReqRes("/account/test", "validkey2");
        apiKeyMiddleware(req, res, next);
        expect(next).toHaveBeenCalled();
      });

      it("trims whitespace from the incoming key before hashing", () => {
        const { req, res, next } = makeReqRes("/account/test", "  validkey1  ");
        apiKeyMiddleware(req, res, next);
        expect(next).toHaveBeenCalled();
      });

      it("returns 401 when API_KEYS is empty", () => {
        process.env.API_KEYS = "";
        _resetHashedKeys();
        const { req, res, next } = makeReqRes("/account/test", "somekey");
        apiKeyMiddleware(req, res, next);
        expect(res.status).toHaveBeenCalledWith(401);
        expect(res.json).toHaveBeenCalledWith({
          success: false,
          error: {
            type: "Unauthorized",
            message: "API key authentication is enabled but no valid keys are configured.",
          },
        });
      });

      it("returns 401 when API_KEYS is not set", () => {
        delete process.env.API_KEYS;
        _resetHashedKeys();
        const { req, res, next } = makeReqRes("/account/test", "somekey");
        apiKeyMiddleware(req, res, next);
        expect(res.status).toHaveBeenCalledWith(401);
        expect(res.json).toHaveBeenCalledWith({
          success: false,
          error: {
            type: "Unauthorized",
            message: "API key authentication is enabled but no valid keys are configured.",
          },
        });
      });
    });

    describe("SHA-256 hashing behaviour", () => {
      it("hashes keys on first use and clears API_KEYS from env", () => {
        process.env.API_KEYS = "secretkey";
        _resetHashedKeys();
        const { req, res, next } = makeReqRes("/account/test", "secretkey");
        apiKeyMiddleware(req, res, next);
        // Plaintext should be cleared after hashing
        expect(process.env.API_KEYS).toBe("");
        expect(next).toHaveBeenCalled();
      });

      it("incoming key is compared by its SHA-256 hash, not plaintext", () => {
        // Set up a key whose SHA-256 we know
        const plaintext = "my-secret-key";
        process.env.API_KEYS = plaintext;
        _resetHashedKeys();

        // Valid key passes
        const { req: r1, res: res1, next: n1 } = makeReqRes("/account/test", plaintext);
        apiKeyMiddleware(r1, res1, n1);
        expect(n1).toHaveBeenCalled();

        // A different string that happens to be the hex of the hash should NOT pass
        const hexHash = crypto.createHash("sha256").update(plaintext).digest("hex");
        const { req: r2, res: res2, next: n2 } = makeReqRes("/account/test", hexHash);
        apiKeyMiddleware(r2, res2, n2);
        expect(res2.status).toHaveBeenCalledWith(401);
      });
    });
  });
});
