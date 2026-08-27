"use strict";

/**
 * Tests for the ALLOWED_ORIGINS CORS whitelist.
 *
 * Covers:
 *   - Whitelisted origin receives CORS headers
 *   - Non-whitelisted origin receives a 403
 *   - When ALLOWED_ORIGINS is not set, all origins are allowed (dev fallback)
 */

const request = require("supertest");

describe("CORS origin whitelist", () => {
  describe("when ALLOWED_ORIGINS is set", () => {
    let app;

    beforeAll(() => {
      process.env.ALLOWED_ORIGINS = "https://allowed.example.com,https://other.example.com";
      jest.resetModules();
      jest.mock("../src/config/stellar", () => ({
        ...jest.requireActual("../src/config/stellar"),
        server: {
          ledgers: jest.fn().mockReturnValue({
            order: jest.fn().mockReturnThis(),
            limit: jest.fn().mockReturnThis(),
            call: jest.fn().mockResolvedValue({ records: [] }),
          }),
          feeStats: jest.fn().mockResolvedValue({
            fee_charged: { min: "100", p10: "100", p50: "200", p95: "500", p99: "1000", max: "5000" },
            last_ledger_base_fee: "100",
            ledger_capacity_usage: "0.5",
          }),
        },
      }));
      app = require("../src/index");
    });

    afterAll(() => {
      delete process.env.ALLOWED_ORIGINS;
      jest.resetModules();
    });

    it("returns CORS headers for a whitelisted origin", async () => {
      const res = await request(app)
        .get("/health")
        .set("Origin", "https://allowed.example.com");

      expect(res.statusCode).toBe(200);
      expect(res.headers["access-control-allow-origin"]).toBe("https://allowed.example.com");
    });

    it("returns 403 for a non-whitelisted origin", async () => {
      const res = await request(app)
        .get("/health")
        .set("Origin", "https://evil.example.com");

      expect(res.statusCode).toBe(403);
    });

    it("allows requests with no Origin header (non-browser / server-to-server)", async () => {
      const res = await request(app).get("/health");
      expect(res.statusCode).toBe(200);
    });
  });

  describe("when ALLOWED_ORIGINS is not set", () => {
    let app;

    beforeAll(() => {
      delete process.env.ALLOWED_ORIGINS;
      jest.resetModules();
      jest.mock("../src/config/stellar", () => ({
        ...jest.requireActual("../src/config/stellar"),
        server: {
          ledgers: jest.fn().mockReturnValue({
            order: jest.fn().mockReturnThis(),
            limit: jest.fn().mockReturnThis(),
            call: jest.fn().mockResolvedValue({ records: [] }),
          }),
          feeStats: jest.fn().mockResolvedValue({
            fee_charged: { min: "100", p10: "100", p50: "200", p95: "500", p99: "1000", max: "5000" },
            last_ledger_base_fee: "100",
            ledger_capacity_usage: "0.5",
          }),
        },
      }));
      app = require("../src/index");
    });

    afterAll(() => {
      jest.resetModules();
    });

    it("allows any origin (development fallback)", async () => {
      const res = await request(app)
        .get("/health")
        .set("Origin", "https://any-origin.example.com");

      expect(res.statusCode).toBe(200);
      expect(res.headers["access-control-allow-origin"]).toBeDefined();
    });
  });
});
