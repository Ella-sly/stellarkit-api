"use strict";

/**
 * Tests for GET /soroban/contract/:id/wasm
 *
 * Covers:
 *   - Returns { contractId, wasmHash, wasmSize, installedLedger, expiryLedger }
 *   - Returns 404 when the contract does not exist
 *   - Returns 400 for an invalid contract ID
 *   - Response is cached (X-Cache: HIT on second request)
 */

const request = require("supertest");
const cacheService = require("../src/services/cache");

jest.mock("../src/config/stellar", () => {
  const original = jest.requireActual("../src/config/stellar");
  return {
    ...original,
    sorobanServer: { getLedgerEntries: jest.fn() },
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
  };
});

const { sorobanServer } = require("../src/config/stellar");
const { xdr, Contract, StrKey } = require("@stellar/stellar-sdk");
const app = require("../src/index");

// ── Helpers ──────────────────────────────────────────────────────────────────

function buildInstanceEntry({ contractId, wasmHash = Buffer.alloc(32, 7) }) {
  const address = new Contract(contractId).address().toScAddress();
  const executable = new xdr.ContractExecutable("contractExecutableWasm", wasmHash);
  const instance = new xdr.ScContractInstance({ executable, storage: null });
  const contractData = new xdr.ContractDataEntry({
    ext: new xdr.ExtensionPoint(0),
    contract: address,
    key: xdr.ScVal.scvLedgerKeyContractInstance(),
    durability: xdr.ContractDataDurability.persistent(),
    val: xdr.ScVal.scvContractInstance(instance),
  });
  return {
    lastModifiedLedgerSeq: 100,
    liveUntilLedgerSeq: 200,
    val: xdr.LedgerEntryData.contractData(contractData),
  };
}

function buildWasmEntry({ code = Buffer.alloc(512, 0xde), lastModified = 50, liveUntil = 300 } = {}) {
  const contractCode = new xdr.ContractCodeEntry({
    ext: new xdr.ContractCodeEntryExt(0),
    hash: Buffer.alloc(32, 7),
    code,
  });
  return {
    lastModifiedLedgerSeq: lastModified,
    liveUntilLedgerSeq: liveUntil,
    val: xdr.LedgerEntryData.contractCode(contractCode),
  };
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe("GET /soroban/contract/:id/wasm", () => {
  const contractId = StrKey.encodeContract(Buffer.alloc(32, 5));
  const wasmHash = Buffer.alloc(32, 7);

  beforeEach(() => {
    jest.clearAllMocks();
    cacheService.flush();
  });

  it("returns normalised WASM metadata shape", async () => {
    sorobanServer.getLedgerEntries
      .mockResolvedValueOnce({ entries: [buildInstanceEntry({ contractId, wasmHash })] })
      .mockResolvedValueOnce({ entries: [buildWasmEntry({ code: Buffer.alloc(512, 0xde), lastModified: 50, liveUntil: 300 })] });

    const res = await request(app).get(`/soroban/contract/${contractId}/wasm`);

    expect(res.statusCode).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.data).toEqual({
      contractId,
      wasmHash: wasmHash.toString("hex"),
      wasmSize: 512,
      installedLedger: 50,
      expiryLedger: 300,
    });
  });

  it("returns 404 when the contract does not exist", async () => {
    sorobanServer.getLedgerEntries.mockResolvedValue({ entries: [] });

    const res = await request(app).get(`/soroban/contract/${contractId}/wasm`);

    expect(res.statusCode).toBe(404);
    expect(res.body.error.type).toBe("ContractNotFound");
  });

  it("returns 400 for an invalid contract ID", async () => {
    const res = await request(app).get("/soroban/contract/NOT_A_CONTRACT/wasm");

    expect(res.statusCode).toBe(400);
    expect(res.body.error.type).toBe("ValidationError");
    expect(sorobanServer.getLedgerEntries).not.toHaveBeenCalled();
  });

  describe("caching", () => {
    it("sets X-Cache: MISS on the first request", async () => {
      sorobanServer.getLedgerEntries
        .mockResolvedValueOnce({ entries: [buildInstanceEntry({ contractId, wasmHash })] })
        .mockResolvedValueOnce({ entries: [buildWasmEntry()] });

      const res = await request(app).get(`/soroban/contract/${contractId}/wasm`);
      expect(res.headers["x-cache"]).toBe("MISS");
    });

    it("sets X-Cache: HIT on a repeated request and only calls RPC once", async () => {
      sorobanServer.getLedgerEntries
        .mockResolvedValueOnce({ entries: [buildInstanceEntry({ contractId, wasmHash })] })
        .mockResolvedValueOnce({ entries: [buildWasmEntry()] });

      await request(app).get(`/soroban/contract/${contractId}/wasm`);
      const res = await request(app).get(`/soroban/contract/${contractId}/wasm`);

      expect(res.headers["x-cache"]).toBe("HIT");
      expect(sorobanServer.getLedgerEntries).toHaveBeenCalledTimes(2); // instance + wasm on first call only
    });
  });
});
