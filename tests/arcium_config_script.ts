import { expect } from "chai";
import { createRequire } from "module";

const requireFromTest = createRequire(
  `${process.cwd()}/tests/arcium_config_script.ts`
);
const {
  ARCIUM_STATUS,
  arciumStateFromAccount,
  buildDesiredConfig,
  bytesToHex,
  decodeX25519PublicKey,
  findConfigMismatches,
  parseStatus,
  statusRequiresDeployment,
  statusName,
} = requireFromTest("../scripts/devnet/arcium-config");

const PROGRAM_ID = "Arcj82pX7HxYKLR92qvgZUAd7vGS1k4hQvAFcPATFdEQ";
const MXE_ACCOUNT = "11111111111111111111111111111115";
const CLUSTER_ACCOUNT = "11111111111111111111111111111116";
const MEMPOOL_ACCOUNT = "11111111111111111111111111111117";
const GOVERNANCE = "11111111111111111111111111111112";
const TEE_KEY_HEX = "07".repeat(32);

describe("arcium devnet config script", () => {
  it("parses status names and numeric codes", () => {
    expect(parseStatus("mirror")).to.equal(ARCIUM_STATUS.mirror);
    expect(parseStatus("2")).to.equal(ARCIUM_STATUS.enforced);
    expect(statusName(ARCIUM_STATUS.paused)).to.equal("paused");
    expect(() => parseStatus("active")).to.throw(
      "Invalid SUBLY402_ARCIUM_STATUS"
    );
  });

  it("decodes tee x25519 keys from hex or base64", () => {
    const hexBytes = decodeX25519PublicKey(TEE_KEY_HEX);
    const base64Bytes = decodeX25519PublicKey(
      Buffer.from(hexBytes).toString("base64")
    );

    expect(hexBytes).to.deep.equal(new Array(32).fill(7));
    expect(base64Bytes).to.deep.equal(hexBytes);
    expect(bytesToHex(hexBytes)).to.equal(TEE_KEY_HEX);
    expect(() => decodeX25519PublicKey("abcd")).to.throw(
      "must decode to 32 bytes"
    );
  });

  it("requires deployment fields for mirror mode", () => {
    expect(() =>
      buildDesiredConfig({}, { governance: GOVERNANCE }, ARCIUM_STATUS.mirror)
    ).to.throw("SUBLY402_ARCIUM_PROGRAM_ID is required");
  });

  it("requires deployment fields when creating config even if target status is disabled", () => {
    expect(statusRequiresDeployment(ARCIUM_STATUS.disabled)).to.equal(false);
    expect(() =>
      buildDesiredConfig(
        {},
        { governance: GOVERNANCE },
        ARCIUM_STATUS.disabled,
        { requireDeployment: true }
      )
    ).to.throw("SUBLY402_ARCIUM_PROGRAM_ID is required");
  });

  it("builds desired deployment config from env", () => {
    const desired = buildDesiredConfig(
      {
        SUBLY402_ARCIUM_PROGRAM_ID: PROGRAM_ID,
        SUBLY402_ARCIUM_MXE_ACCOUNT: MXE_ACCOUNT,
        SUBLY402_ARCIUM_CLUSTER_ACCOUNT: CLUSTER_ACCOUNT,
        SUBLY402_ARCIUM_MEMPOOL_ACCOUNT: MEMPOOL_ACCOUNT,
        SUBLY402_ARCIUM_COMP_DEF_VERSION: "7",
        SUBLY402_ARCIUM_TEE_X25519_PUBKEY_HEX: TEE_KEY_HEX,
        SUBLY402_ARCIUM_MIN_LIQUID_RESERVE_BPS: "1000",
        SUBLY402_ARCIUM_MAX_STRATEGY_ALLOCATION_BPS: "9000",
        SUBLY402_ARCIUM_SETTLEMENT_BUFFER_AMOUNT: "123",
        SUBLY402_ARCIUM_STRATEGY_WITHDRAWAL_SLA_SEC: "456",
      },
      { governance: GOVERNANCE },
      ARCIUM_STATUS.mirror
    );

    expect(desired.arciumProgramId.toBase58()).to.equal(PROGRAM_ID);
    expect(desired.mxeAccount.toBase58()).to.equal(MXE_ACCOUNT);
    expect(desired.clusterAccount.toBase58()).to.equal(CLUSTER_ACCOUNT);
    expect(desired.mempoolAccount.toBase58()).to.equal(MEMPOOL_ACCOUNT);
    expect(desired.compDefVersion).to.equal(7);
    expect(desired.teeX25519Pubkey).to.deep.equal(new Array(32).fill(7));
    expect(desired.strategyController.toBase58()).to.equal(GOVERNANCE);
    expect(desired.minLiquidReserveBps).to.equal(1000);
    expect(desired.maxStrategyAllocationBps).to.equal(9000);
    expect(desired.settlementBufferAmount.toString()).to.equal("123");
    expect(desired.strategyWithdrawalSlaSec.toString()).to.equal("456");
  });

  it("rejects default deployment pubkeys when deployment is required", () => {
    expect(() =>
      buildDesiredConfig(
        {
          SUBLY402_ARCIUM_PROGRAM_ID: "11111111111111111111111111111111",
          SUBLY402_ARCIUM_MXE_ACCOUNT: MXE_ACCOUNT,
          SUBLY402_ARCIUM_CLUSTER_ACCOUNT: CLUSTER_ACCOUNT,
          SUBLY402_ARCIUM_MEMPOOL_ACCOUNT: MEMPOOL_ACCOUNT,
          SUBLY402_ARCIUM_TEE_X25519_PUBKEY_HEX: TEE_KEY_HEX,
        },
        { governance: GOVERNANCE },
        ARCIUM_STATUS.mirror,
        { requireDeployment: true }
      )
    ).to.throw("SUBLY402_ARCIUM_PROGRAM_ID is required and cannot be");
  });

  it("compares decoded numeric account fields without false mismatches", () => {
    const desired = buildDesiredConfig(
      {
        SUBLY402_ARCIUM_PROGRAM_ID: PROGRAM_ID,
        SUBLY402_ARCIUM_MXE_ACCOUNT: MXE_ACCOUNT,
        SUBLY402_ARCIUM_CLUSTER_ACCOUNT: CLUSTER_ACCOUNT,
        SUBLY402_ARCIUM_MEMPOOL_ACCOUNT: MEMPOOL_ACCOUNT,
        SUBLY402_ARCIUM_COMP_DEF_VERSION: "7",
        SUBLY402_ARCIUM_TEE_X25519_PUBKEY_HEX: TEE_KEY_HEX,
        SUBLY402_ARCIUM_MIN_LIQUID_RESERVE_BPS: "1000",
        SUBLY402_ARCIUM_MAX_STRATEGY_ALLOCATION_BPS: "9000",
        SUBLY402_ARCIUM_SETTLEMENT_BUFFER_AMOUNT: "123",
        SUBLY402_ARCIUM_STRATEGY_WITHDRAWAL_SLA_SEC: "456",
      },
      { governance: GOVERNANCE },
      ARCIUM_STATUS.mirror
    );
    const account = {
      ...desired,
      compDefVersion: { toNumber: () => 7 },
      minLiquidReserveBps: { toNumber: () => 1000 },
      maxStrategyAllocationBps: { toNumber: () => 9000 },
    };

    expect(findConfigMismatches(account, desired)).to.deep.equal([]);
  });

  it("uses an existing decoded account as config fallback", () => {
    const desired = buildDesiredConfig(
      {
        SUBLY402_ARCIUM_PROGRAM_ID: PROGRAM_ID,
        SUBLY402_ARCIUM_MXE_ACCOUNT: MXE_ACCOUNT,
        SUBLY402_ARCIUM_CLUSTER_ACCOUNT: CLUSTER_ACCOUNT,
        SUBLY402_ARCIUM_MEMPOOL_ACCOUNT: MEMPOOL_ACCOUNT,
        SUBLY402_ARCIUM_COMP_DEF_VERSION: "7",
        SUBLY402_ARCIUM_TEE_X25519_PUBKEY_HEX: TEE_KEY_HEX,
        SUBLY402_ARCIUM_MIN_LIQUID_RESERVE_BPS: "1000",
        SUBLY402_ARCIUM_MAX_STRATEGY_ALLOCATION_BPS: "9000",
        SUBLY402_ARCIUM_SETTLEMENT_BUFFER_AMOUNT: "123",
        SUBLY402_ARCIUM_STRATEGY_WITHDRAWAL_SLA_SEC: "456",
      },
      { governance: GOVERNANCE },
      ARCIUM_STATUS.mirror
    );
    const accountState = arciumStateFromAccount({
      ...desired,
      status: ARCIUM_STATUS.enforced,
    });

    const fallback = buildDesiredConfig(
      {},
      { governance: GOVERNANCE, arcium: accountState },
      ARCIUM_STATUS.disabled,
      { requireDeployment: true }
    );

    expect(fallback.arciumProgramId.toBase58()).to.equal(PROGRAM_ID);
    expect(fallback.teeX25519Pubkey).to.deep.equal(new Array(32).fill(7));
    expect(fallback.settlementBufferAmount.toString()).to.equal("123");
  });
});
