import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { Connection, Keypair, PublicKey, SystemProgram } from "@solana/web3.js";
import { expect } from "chai";
import BN from "bn.js";

import { Subly402Vault } from "../target/types/subly402_vault";

const idl = require("../target/idl/subly402_vault.json") as Subly402Vault;

function instructionDiscriminator(name: string): Buffer {
  const instruction = idl.instructions.find((item) => item.name === name);
  if (!instruction) {
    throw new Error(`Missing IDL instruction ${name}`);
  }
  return Buffer.from(instruction.discriminator);
}

describe("arcium idl client", () => {
  const provider = new anchor.AnchorProvider(
    new Connection("http://127.0.0.1:8899", "confirmed"),
    new anchor.Wallet(Keypair.generate()),
    {}
  );
  const program = new Program<Subly402Vault>(idl as any, provider);

  const governance = new PublicKey("11111111111111111111111111111112");
  const vaultConfig = new PublicKey("11111111111111111111111111111113");
  const arciumConfig = new PublicKey("11111111111111111111111111111114");
  const arciumProgramId = new PublicKey(
    "Arcj82pX7HxYKLR92qvgZUAd7vGS1k4hQvAFcPATFdEQ"
  );
  const mxeAccount = new PublicKey("11111111111111111111111111111115");
  const clusterAccount = new PublicKey("11111111111111111111111111111116");
  const mempoolAccount = new PublicKey("11111111111111111111111111111117");
  const strategyController = new PublicKey("11111111111111111111111111111118");

  it("builds initializeArciumConfig instructions from the generated IDL", async () => {
    const teeX25519Pubkey = Array.from({ length: 32 }, (_, index) => index + 1);
    const ix = await program.methods
      .initializeArciumConfig(
        1,
        arciumProgramId,
        mxeAccount,
        clusterAccount,
        mempoolAccount,
        7,
        teeX25519Pubkey,
        strategyController,
        1_000,
        9_000,
        new BN(10_000),
        new BN(3_600)
      )
      .accountsPartial({
        governance,
        vaultConfig,
        arciumConfig,
        systemProgram: SystemProgram.programId,
      })
      .instruction();

    expect(Buffer.from(ix.data.subarray(0, 8))).to.deep.equal(
      instructionDiscriminator("initialize_arcium_config")
    );
    expect(ix.programId.toBase58()).to.equal(program.programId.toBase58());
    expect(ix.keys.map((key) => key.pubkey.toBase58())).to.deep.equal([
      governance.toBase58(),
      vaultConfig.toBase58(),
      arciumConfig.toBase58(),
      SystemProgram.programId.toBase58(),
    ]);
    expect(ix.keys[0]).to.include({ isSigner: true, isWritable: true });
    expect(ix.keys[1]).to.include({ isSigner: false, isWritable: false });
    expect(ix.keys[2]).to.include({ isSigner: false, isWritable: true });
  });

  it("builds setArciumStatus instructions from the generated IDL", async () => {
    const ix = await program.methods
      .setArciumStatus(2)
      .accountsPartial({
        governance,
        vaultConfig,
        arciumConfig,
      })
      .instruction();

    expect(Buffer.from(ix.data.subarray(0, 8))).to.deep.equal(
      instructionDiscriminator("set_arcium_status")
    );
    expect(ix.programId.toBase58()).to.equal(program.programId.toBase58());
    expect(ix.keys.map((key) => key.pubkey.toBase58())).to.deep.equal([
      governance.toBase58(),
      vaultConfig.toBase58(),
      arciumConfig.toBase58(),
    ]);
    expect(ix.keys[0]).to.include({ isSigner: true, isWritable: false });
    expect(ix.keys[1]).to.include({ isSigner: false, isWritable: false });
    expect(ix.keys[2]).to.include({ isSigner: false, isWritable: true });
  });

  it("includes Arcium withdrawal and recovery instructions in the generated IDL", () => {
    const names = new Set(
      idl.instructions.map((instruction) => instruction.name)
    );

    expect(names.has("authorize_withdrawal")).to.equal(true);
    expect(names.has("authorize_withdrawal_callback")).to.equal(true);
    expect(names.has("reconcile_withdrawal")).to.equal(true);
    expect(names.has("reconcile_withdrawal_callback")).to.equal(true);
    expect(names.has("prepare_recovery_claim")).to.equal(true);
    expect(names.has("prepare_recovery_claim_callback")).to.equal(true);
    expect(names.has("arcium_force_settle_finalize")).to.equal(true);
  });
});
