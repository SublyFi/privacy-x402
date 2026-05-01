# A402-Solana: Privacy-Focused x402 Protocol Design Document

> Version: 0.4.0
> Date: 2026-04-12
> Status: Draft
> Reference: [A402 Paper](./a402.pdf) (arXiv:2603.01179v2)

---

## 1. Introduction

### 1.1 Background

x402はHTTP 402 "Payment Required"ステータスコードを活用し、ブロックチェーンベースの決済をWebサービスに統合するオープンスタンダードである。AIエージェントがサービスを自律的に発見・利用・決済する「エージェンティックコマース」の基盤として広く採用されている。

しかし、現行のx402には根本的なプライバシーの問題がある。全てのUSDC送金がオンチェーンで公開されるため、ネームサービス（SNS, ENS等）と紐づいたアドレスでは**購入者が第三者に特定される**。従来の商取引では何を買ったかは第三者にはわからないが、x402では「誰が」「誰に」「いくら」払ったかが全て公開される。

### 1.2 Purpose

本プロトコル（A402-Solana）は、A402論文のアーキテクチャに忠実に従い、Solana上で以下を実現する:

1. **送金者匿名性**: オンチェーン観測者から送金者のアドレスを秘匿
2. **選択的開示**: 権限を持つ監査者のみが送金者情報を復号可能（プロバイダー単位の粒度）
3. **x402 HTTP envelope互換**: `HTTP 402` / `PAYMENT-REQUIRED` / `PAYMENT-SIGNATURE` / `PAYMENT-RESPONSE` の通信形状を維持

### 1.3 Design Philosophy

A402論文に忠実にTEE（Trusted Execution Environment）を信頼の基盤とする。

- **Phase 1-4**: TEEベース — 論文通りのアーキテクチャ
- **Phase 5**: Arcium MXE統合 — オンチェーン残高の暗号化による追加プライバシー層

TEEファーストのアプローチを採る理由:
- A402論文のアーキテクチャと直接対応し、検証が容易
- TEE内は通常のRust/TypeScriptで記述でき、開発速度が速い
- Arciumのステートレス制約に起因する設計の複雑さを初期段階で回避
- Arciumは後から追加プライバシー層として段階的に導入可能

### 1.4 Target Environment

初期開発・検証は**Solana Devnet + AWS Nitro Enclaves対応EC2**で実施する。Mainnet移行はPhase 4以降で検討。

### 1.5 論文との既知の差分

本設計はA402論文に忠実に従うが、以下の差分が存在する:

| 差分 | A402論文 | 本プロトコル | 理由 |
|------|---------|------------|------|
| Adaptor Signatures | Schnorr (secp256k1) | Phase 1-2ではTEE内予約 + Phase 3でEd25519 adaptor sig導入 | SolanaはEd25519。Schnorr adaptor sigと非互換 |
| Provider Integration | A402専用プロトコル | x402 HTTP envelope上に `subly402-svm-v1` scheme を載せる | API統合をHTTP 402に寄せ、導入コストを下げる |
| Service Provider TEE | SもTEE内で実行 | Phase 1-2ではProvider本体は変更せず、Phase 3でProvider TEE対応 | 段階導入のため |
| Exec-Pay-Deliver | 暗号学的に保証 | Phase 1-2では保証なし。Phase 3で完全保証 | 上記に伴う制約 |
| On-chain Attestation | オンチェーンでTEE登録 | クライアント/監視者がNitro Attestationを検証し、オンチェーンにはattestation policy hashを固定 | Solana上でattestation証明を直接検証するのは非現実的 |
| TEE Runtime | 抽象TEE | AWS Nitro Enclavesを実装前提に固定 | 運用・鍵管理・復旧設計を具体化するため |
| Receipt Watchtower | challenge period中の監視のみ | receipt mirror必須。Enclave停止時のstale receipt challengeを代行する常設サービス | Enclave障害時のforce-settle安全性をwatchtowerに依存するため、論文より役割が大きい |
| Selective Disclosure | なし（論文スコープ外） | ElGamal暗号化AuditRecord + 階層的鍵導出によるプロバイダー単位の選択的開示 | 監査要件への対応として本設計独自に追加 |

### 1.6 Companion Specifications

- Wire protocol: [subly402-svm-v1-protocol.md](./a402-svm-v1-protocol.md)
- Nitro deployment / ops: [a402-nitro-deployment.md](./a402-nitro-deployment.md)

---

## 2. Privacy Model

### 2.1 Threat Model

**保護対象:**
- 第三者（オンチェーン観測者、ブロックチェーンエクスプローラーのユーザー等）

**前提（A402論文 Section 3.2 準拠）:**
- **Trusted Hardware**: TEEはコードとデータの機密性・完全性を保証する。ホストOSやハイパーバイザーが侵害されてもTEE内部は保護される
- **Nitro-specific Assumptions**:
  - Enclaveは**debug無効**で起動し、EIF署名とPCR0/PCR1/PCR2/PCR3/PCR8が事前に固定される
  - Enclaveには直接ネットワーク・永続ディスクがないため、parent instanceはvsock relay / KMS proxy / 暗号化snapshot保管のみを担う
  - KMSの利用権限はattestation documentのPCR条件により制限され、parent instance単体では秘密鍵・snapshot復号鍵を取得できない
- **Adversarial Parties**: TEE外のプロトコル参加者は任意に腐敗し得る
  - 悪意あるクライアント: 二重使用や無料利用を試みる
  - 悪意あるVault運営者 / parent instance: TEE内のコードを改ざんできないが、I/Oの遮断・順序変更・再送・DoSを試み得る
  - 悪意あるサービスプロバイダー: メッセージの遅延・改ざんを試みる
- **Network Adversary**: 完全に非同期なネットワーク。メッセージの盗聴・改ざん・遅延が可能

### 2.2 What is Hidden

| 情報 | 第三者 | Vault運営者 / Parent | TEE内Vault | 監査者(マスター鍵) | 監査者(Provider別鍵) |
|------|--------|--------------------|-----------|-----------------|---------------------|
| 送金者アドレス | Hidden | Hidden (TLS終端 + TEE保護) | Known | Known | Known (対象のみ) |
| 支払い金額 | Hidden | Hidden (TEE保護) | Known | Known | Known (対象のみ) |
| クライアント残高 | Hidden | Hidden (TEE保護) | Known | N/A | N/A |
| Vault→Provider送金 | Visible | Visible | Visible | Visible | Visible |
| Vault入金者一覧 | Visible | Visible | Visible | Visible | Visible |

**A402との比較**: 前版の設計ではRelayerがクライアント情報を平文で扱っていたが、Nitro Enclave内でTLSを終端し、parent instanceはL4 relayに限定することで**Vault運営者すらクライアント情報にアクセスできない**（A402論文に近い信頼モデル）。

### 2.3 Anonymity Model

ミキサー/プール型の匿名性（A402論文 Section 4.3 Privacy-Preserving Liquidity Vault 準拠）:

```
N人がVaultに入金 → Vault内の誰でもN人のうちの1人として支払い可能
→ 特定の支払いと特定の入金者を紐づけ不可能
```

- 匿名性セットサイズ = Vaultの入金者数N
- 初回deposit（client → vault）はオンチェーンで可視だが、以降の個別決済は匿名化される
- Vault Settlement時はN人分の決済を1つのオンチェーンtxに集約し、個別ASCの痕跡を残さない

### 2.4 Selective Disclosure (Hierarchical Key Derivation)

監査の粒度をプロバイダー単位で制御するため、階層的鍵導出を採用:

```
Master Auditor Secret (マスター秘密鍵)
  │
  ├─ KDF(master_secret, provider_A_address) → Provider A 用 ElGamal鍵ペア
  ├─ KDF(master_secret, provider_B_address) → Provider B 用 ElGamal鍵ペア
  └─ KDF(master_secret, provider_C_address) → Provider C 用 ElGamal鍵ペア
```

各AuditRecordは**対象プロバイダーから導出されたElGamal公開鍵**で暗号化される。

| 開示シナリオ | 渡す鍵 | 復号可能な範囲 |
|------------|--------|-------------|
| 全取引監査 | マスター秘密鍵 | 全プロバイダーへの全支払い |
| 特定プロバイダー監査 | Provider A用導出鍵 | Provider Aへの支払いのみ |
| 複数プロバイダー監査 | Provider A,B用導出鍵 | A,Bへの支払いのみ |

### 2.5 Exec-Pay-Deliver Atomicity に関する制約

A402論文では、Adaptor Signatureにより「実行されたサービスに対してのみ支払いが確定する」Exec-Pay-Deliver アトミシティが暗号学的に保証される。本プロトコルでは段階的に実現する:

**Phase 1-2（x402 HTTP envelope + Enclave予約モデル）:**
- Nitro Enclaveが `PAYMENT-SIGNATURE` を検証し、Providerの `/settle` 後に内部残高を確定する
- **アトミシティは保証されない**: Providerが支払いを受け取った後に結果を返さないリスクがある
- このリスクはProvider信頼モデルに依存し、Phase 3のProvider TEE導入まで残る
- ただしオンチェーンには個別client→provider送金が残らず、privacy目標は達成できる

**Phase 3（Atomic Exchange導入）:**
- Provider側にもTEEを導入し、論文Algorithm 2に完全準拠
- Ed25519 adaptor signatureによる暗号学的アトミシティ保証
- Providerは結果を返さない限り支払いを受け取れない

### 2.6 Known Privacy Gaps

- **初回入金の可視性**: deposit（client → vault）トランザクションはオンチェーンで公開。入金者アドレスは匿名性セットの構成員として可視。将来Token-2022 Confidential Transferで対処可能。

---

## 3. System Architecture

### 3.1 Overview

```
 Client                          AWS Parent Instance                    Nitro Enclave
 ┌─────────────┐            ┌────────────────────────┐           ┌─────────────────────────┐
 │  A402 SDK   │──TLS──────▶│ L4 ingress relay       │──vsock───▶│ A402 Facilitator API    │
 │ verifyAtt   │            │ L4 egress relay        │◀─vsock───│ Vault state manager     │
 └──────┬──────┘            │ KMS proxy              │           │ Audit encryption        │
        │                   │ Encrypted snapshot I/O │           │ Solana signer           │
        │ HTTP 402 retry    └──────────┬─────────────┘           │ Remote Attestation      │
        ▼                              │                         └──────────┬──────────────┘
 ┌──────────────┐                      │                                    │
 │   Provider   │──/verify,/settle─────┘                                    │
 │ x402 endpoint│                                                           │
 └──────┬───────┘                                                           │
        │                                                                   │
        │                                                     TLS over L4 relay
        │                                                                   │
        ▼                                                                   ▼
 ┌──────────────────┐                                            ┌──────────────────┐
 │  Vault Program   │◀──────────────settle_vault─────────────────│ Solana RPC       │
 │  (Anchor)        │◀──────────────deposit/withdraw─────────────│ + WebSocket      │
 │ VaultConfig PDA  │                                            └──────────────────┘
 │ VaultToken PDA   │──── 共有USDCプール
 │ AuditRecord[]    │──── 暗号化監査証跡
 └────────┬─────────┘
          │
          ▼
 ┌──────────────────┐
 │ Provider Token   │
 │ Accounts (USDC)  │
 └──────────────────┘
```

### 3.2 A402 Concept Mapping

| A402 (論文) | 本プロトコル | 備考 |
|------------|------------|------|
| Vault (U) — TEE管理 | Nitro Enclave内 Vault | Enclave内で残高・ASC状態・署名鍵を管理 |
| Client (C) | Client SDK + Solana Keypair | Remote AttestationでNitro PCRとvault signerを検証 |
| Service Provider (S) | x402 endpoint + custom facilitator設定 | Provider API本体は変更せず、payment schemeのみA402-awareにする |
| On-chain Program (L) | Anchor Program on Solana | Escrow + Settlement + Dispute Resolution |
| Attested Runtime Policy | Nitro Enclave + governance-pinned attestation policy | Solana上ではattestation policy hashを固定 |
| Adaptor Signatures | Ed25519ベースの条件付き署名 | Phase 3で導入 |
| Liquidity Vault | 共有Vault PDA + Enclave内部台帳 | 個別残高はEnclave内のみ。オンチェーンは集約残高のみ |
| Batch Settlement | `settle_vault` instruction | N人分のASC決済を1 txに集約 |
| Audit Log | ElGamal暗号化 AuditRecord PDA | Enclave内で暗号化→オンチェーン保存 |
| Force Settlement | `force_settle_init` / `force_settle_finalize` | Enclave障害時のオンチェーン脱出口 |

### 3.3 Component Responsibilities

**Nitro Enclave（オフチェーン、TEE内で実行）:**
- クライアント残高の管理（TEE内メモリ + KMS保護snapshot/WAL）
- ASCの作成・状態管理・クローズ（全てオフチェーン）
- Atomic Exchange（Phase 3で実行→支払い→配信のアトミシティ保証）
- 監査レコードのElGamal暗号化（プロバイダー別導出鍵）
- A402 Facilitator API（`/verify` / `/settle` / `attestation`）
- Remote Attestation（クライアント/監視者がTEEの正当性を検証可能）
- 残高証明書・withdraw authorizationの署名

**On-chain Program（Anchor）:**
- USDCのエスクロー管理（Vault Token Account）
- Vault初期化・設定
- 集約決済（TEEが提出する1つのtxで複数クライアント分の精算）
- 強制決済（Enclave障害時のオンチェーン脱出口 + dispute window）
- 暗号化監査レコードの保存

**AWS Parent Instance（untrusted, ただし可用性を担う）:**
- TLSを終端せず、生のTCPをvsockへ中継するL4 ingress relay
- EnclaveからのSolana RPC / Provider HTTPS向けL4 egress relay
- Nitro用KMS proxy
- 暗号化済みsnapshot / WALの永続化（EBS/S3）

**Receipt Watchtower（Phase 4では必須）:**
- Enclaveが発行した最新の `ParticipantReceipt` を participant ごとに保持する
- Enclave停止時でも `force_settle_challenge` を提出できる
- 見える情報は participant / recipient ATA / free balance / locked balance / max lock expiry / nonce に限られ、個別購入履歴は保持しない

**Client SDK:**
- TEEへのRemote Attestation検証
- Vault deposit/withdraw
- x402互換のfetch（内部で `subly402-svm-v1` payload を生成）
- 監査ツール

---

## 4. x402 Compatibility

### 4.1 Design Principle

**HTTP 402 envelope は維持するが、payment scheme と facilitator はA402専用にする。**

- Providerの業務API本体は変更しない
- Providerは `PAYMENT-REQUIRED` で `accepts[].scheme = "subly402-svm-v1"` を返す
- `PAYMENT-SIGNATURE` / `PAYMENT-RESPONSE` のヘッダ形状はx402互換
- 既存の汎用x402 Facilitatorは使わず、Nitro Enclave内の**custom A402 facilitator**を利用する

### 4.2 Payment Flow

```
 Client SDK                Provider                  Nitro Enclave Facilitator
     │                        │                               │
     │ 1. HTTP Request        │                               │
     ├───────────────────────▶│                               │
     │                        │ 2. 402 PAYMENT-REQUIRED      │
     │                        │    scheme=subly402-svm-v1        │
     │◀───────────────────────┤                               │
     │ 3. verifyAttestation() │                               │
     ├───────────────────────────────────────────────────────▶│
     │◀───────────────────────────────────────────────────────┤
     │ 4. create opaque A402 payment authorization           │
     │    (request hash, provider, amount, expiry, client sig)│
     │                        │                               │
     │ 5. Retry + PAYMENT-SIGNATURE                           │
     ├───────────────────────▶│                               │
     │                        │ 6. /verify(payload)           │
     │                        ├──────────────────────────────▶│
     │                        │                               │
     │                        │ 7. reserve client balance     │
     │                        │    return verification OK     │
     │                        │◀──────────────────────────────┤
     │                        │ 8. Execute service            │
     │                        │ 9. /settle(result_hash, rid)  │
     │                        ├──────────────────────────────▶│
     │                        │                               │
     │                        │ 10. finalize provider credit  │
     │                        │     emit PAYMENT-RESPONSE     │
     │                        │◀──────────────────────────────┤
     │ 11. 200 + Response     │                               │
     │◀───────────────────────┤                               │
     │                        │                               │
     │                        │ 12. later: batch settle on-chain
```

**ポイント:**
- クライアントは通常のx402と同じく**Providerへ直接HTTPリクエスト**する
- `PAYMENT-SIGNATURE` は生のSolana送金txではなく、Enclaveだけが解釈できる**opaque A402 authorization payload**
- Providerはx402と同様に `/verify` → 実行 → `/settle` を行うが、相手はNitro Enclave facilitator
- オンチェーンでは後続の `settle_vault` によりVaultからProviderへ**集約送金**する

### 4.3 HTTP Header Compatibility

| Header | 既存x402 | 本プロトコル | 差分 |
|--------|---------|------------|------|
| `Authorization` | `SIWS <token>` | `SIWS <token>` | 変更なし |
| `PAYMENT-REQUIRED` | 402レスポンス | 402レスポンス | `accepts[].scheme` が `subly402-svm-v1` |
| `PAYMENT-SIGNATURE` | Clientが署名したpayment payload | Clientが生成した**opaque A402 authorization payload** | raw transfer txではない |
| `PAYMENT-RESPONSE` | tx hash等 | settle receipt / batch reference | 形状は維持、意味論がA402向け |

---

## 5. Nitro Enclave Design

### 5.1 TEE Platform

推奨: **AWS Nitro Enclaves**
- Nitro Attestation Document によりPCRベースのRemote Attestationが可能
- AWS KMSはattestation documentのPCR条件に基づいて `Decrypt` / `GenerateDataKey` を制御できる
- Enclaveは親EC2からメモリ分離され、秘密鍵・平文stateをparent instanceへ露出しない
- Nitro Enclaves SDK / vsock / kmstool を用いた実装が可能

**Nitro固有の制約を前提に設計する:**
- Enclaveには**直接ネットワークがない**。入出力はvsock経由のみ
- Enclaveには**永続ストレージがない**。stateは暗号化したsnapshot/WALとして外部保存する
- debug modeは無効化必須。PCR8(EIF署名)をproduction policyに含める
- Parent instanceは**信頼しない**。可用性レイヤとしてのみ扱う

代替TEE（Intel TDX, AMD SEV-SNP）は将来対応対象とし、初版では扱わない

### 5.2 Internal State (TEE内メモリ)

TEE内で管理するデータ（オンチェーンに露出しない）:

```rust
/// Vault全体の内部状態
struct VaultState {
    /// クライアント別残高（TEE内のみ）
    client_balances: HashMap<Pubkey, ClientBalance>,
    /// アクティブなASC
    active_channels: HashMap<ChannelId, ChannelState>,
    /// Vault署名鍵（KMSで保護したencrypted seedから復元）
    vault_signer: Keypair,
    /// 監査者マスター秘密鍵（同上）
    auditor_master_secret: [u8; 32],
    /// 現在有効な監査鍵epoch
    auditor_epoch: u32,
    /// 累積決済額（プロバイダー別）
    pending_settlements: HashMap<Pubkey, u64>,
    /// 残高証明書の発行カウンター
    receipt_nonce: u64,
    /// 通常withdrawのリプレイ防止 nonce
    withdraw_nonce: u64,
    /// 最後に永続化されたsnapshot sequence
    snapshot_seqno: u64,
    /// 最後に適用したfinalized slot
    last_finalized_slot: u64,
}

/// Nitro永続化モデル:
/// - stateはTEE外へ平文で出さない
/// - 各状態遷移をencrypted WALとしてEBS/S3へ保存
/// - 定期的にencrypted snapshotを作成
/// - 復号鍵はNitro attestation付きKMS Decrypt/GenerateDataKeyで
///   enclave内へ復元する
```

struct ClientBalance {
    free: u64,       // 利用可能残高
    locked: u64,     // ASCでロック中の残高
    max_lock_expires_at: i64, // 現在ロック中のreservationの最大expiry。ロックが無ければ0
    total_deposited: u64,
    total_withdrawn: u64,
}

/// A402 Algorithm 1 準拠
struct ChannelState {
    channel_id: ChannelId,
    client: Pubkey,
    provider: Pubkey,
    balance: ChannelBalance,  // (client_free, client_locked, provider_earned)
    status: ChannelStatus,    // Open, Locked, Pending, Closed
    nonce: u64,               // monotonic state counter
}
```

**Nitro上のI/O分離:**

- **ingress**: client/providerからのTLSはparentで終端せず、L4 relayでvsock転送し、enclave内でTLS終端する
- **egress**: enclaveからSolana RPC / Provider HTTPSへ出る通信も、parentのL4 egress relayを経由しつつ、TLSはenclave内で張る
- **persistence**: encrypted WAL / snapshotのみがparent instanceやS3/EBSに保存される

これにより、parent instanceは通信の可用性を握るが、平文payload・秘密鍵・内部stateを読めない。

### 5.3 TEE Registration & Remote Attestation

A402論文 Algorithm 1 (lines 12-15) では、VaultとProviderの両方がオンチェーンでTEE Registrationを行う。しかし、SolanaのオンチェーンプログラムでNitro AttestationDocumentを直接検証するのはcompute unit的に非現実的である。

**本プロトコルの方式: attestation policy hashをオンチェーン固定し、クライアント/監視者が検証する**

```
1. Client → TEE: attestation request
2. TEE: σ_att = Attest(vault_signer_pubkey || tls_pubkey || manifest_hash || snapshot_seqno)
   (AWS Nitro: AttestationDocument with PCR values + user_data/public_key)
3. TEE → Client: σ_att + vault_signer_pubkey + attestation_policy
4. Client: VerifyAtt(σ_att)
   - AWS Nitro root certificateでAttestationDocumentを検証
   - PCR0/PCR1/PCR2/PCR3/PCR8 が on-chain の attestation_policy_hash と一致することを確認
   - vault_signer_pubkey と tls_pubkey が attestation に含まれることを確認
   - debug無効・期待するEIF署名であることを確認
5. Client: vault_signer_pubkey を信頼し、以降の通信に使用
```

実装上は **KMS bootstrap 用 attestation document** と **`/v1/attestation` で返す runtime attestation document** を分離する。前者は KMS response を bootstrap recipient key に束縛するために使い、後者は現在の `snapshot_seqno` と ingress TLS public key を束縛した document を runtime で再生成して返す。

**オンチェーンでの信頼の根拠:**
- `VaultConfig.vault_signer_pubkey` と `VaultConfig.attestation_policy_hash` を固定する
- クライアント/監視者はRemote Attestationで `vault_signer_pubkey` が正当なNitro Enclaveに属することを独立に検証する
- オンチェーンプログラムは `vault_signer_pubkey` の署名を検証し、鍵更新は**in-place updateしない**
- signer rotationが必要な場合は、`新しいVaultをデプロイ → exit window中に移行` を行う

**Nitroでの鍵bootstrap:**

1. Enclave起動時にephemeral key pairを生成
2. Nitro Attestation Documentを付けてKMS `GenerateDataKey` / `Decrypt` を呼ぶ
3. KMS key policyはPCR条件で制限し、attested enclaveにのみ復号済みDEKを返す
4. EnclaveはDEKで encrypted snapshot / encrypted seed material を復元する

この方式により、parent instanceはsnapshotファイルを保持できるが、attested enclaveなしでは復号できない。

### 5.4 Participant Receipts (Force-Settle用)

Enclaveが各残高更新時にparticipant（client / provider）へ発行する署名付き証明書:

```rust
enum ParticipantKind {
    Client,
    Provider,
}

struct ParticipantReceipt {
    participant: Pubkey,
    participant_kind: ParticipantKind,
    recipient_ata: Pubkey,
    free_balance: u64,
    locked_balance: u64,
    max_lock_expires_at: i64, // Client: receiptに含まれるlockの最大expiry、Provider: 0
    nonce: u64,           // monotonic、最新のみ有効
    timestamp: i64,
    snapshot_seqno: u64,
    vault_config: Pubkey,
}
// Enclave vault_signer で Ed25519 署名
```

通常withdraw用には別途、**リプレイ耐性のある署名メッセージ**を使う:

```rust
struct WithdrawAuthorization {
    client: Pubkey,
    recipient_ata: Pubkey,
    amount: u64,
    withdraw_nonce: u64,
    expires_at: i64,
    vault_config: Pubkey,
}
// Enclave vault_signer で署名。on-chainではnonce再利用を拒否する
```

Enclave障害時:

- client は `free_balance` を dispute window 後に回収できる
- client に `locked_balance > 0` がある場合、その portion は `max_lock_expires_at` 経過後に同じ force-settle request から回収できる
- provider は `locked_balance = 0`, `max_lock_expires_at = 0` の receipt を使い、未バッチの earned credit を回収できる

**重要**: stale receipt を防ぐため、Phase 4以降は**Receipt Watchtowerを必須**とする。

- Enclaveは `ParticipantReceipt` 発行のたびに最新 receipt をwatchtowerへ複製する
- `force_settle_challenge` はEnclave本人だけでなく、**participant自身またはwatchtower** が提出できる
- これにより、Enclave停止時でも古いreceiptに対する challenge が可能になる

### 5.5 Atomic Exchange Protocol

#### Phase 1-2: x402 HTTP envelope + Enclave予約モデル

Phase 1-2では、x402のHTTP envelopeを維持しつつ、client が `subly402-svm-v1` payload をローカル生成し、payment verification / reservation / settlementはNitro Enclave facilitatorが担当する。Provider API本体は変更しないが、**既存の汎用facilitatorは利用しない**。アトミシティは依然としてProviderの信頼に依存する。

```
1. Client: `PAYMENT-REQUIRED` から `paymentDetailsHash` を計算し、request hash を含む `subly402-svm-v1` payload をローカル生成
2. Client → Provider: `PAYMENT-SIGNATURE` 付きHTTP再試行
3. Provider → Enclave facilitator `/verify`: payload検証
4. Enclave: クライアント残高からδをロック (free → locked)
5. Provider: service execution
6. Provider → Enclave facilitator `/settle`: 実行完了を通知
7. Enclave: locked → provider_earned（支払い確定）
8. Enclave: pending_settlementsにδを加算（後で `settle_vault` で精算）

タイムアウト処理:
- `/settle` がΔ_lock内に来ない場合: locked → free（支払い取消）
- `/verify` 後にProviderが落ちた場合: reservationを期限切れにし、再利用不能にする
```

**制約**: Providerが `/settle` だけ実行し、結果を返さない場合は支払い損となる。この制約はPhase 3のProvider TEE + adaptor signature導入まで残る。

#### Phase 3: Ed25519 Adaptor Signatures（論文 Algorithm 2 完全準拠）

Provider側にもTEEを導入し、暗号学的にExec-Pay-Deliverアトミシティを保証する。

```
1. Request Submission & Asset Locking:
   - Enclave Vault(U): 残高からδをロック
   - Enclave Vault → Provider TEE(S): (cid, rid, req, δ) を転送

2. TEE-assisted Execution & Adaptor-Signature Payment Commitment:
   - S TEE: res = Execute(req)
   - S TEE: 秘密値 t ← Z_q, T = t·G (Ed25519 curve)
   - S TEE: h = H(res), EncRes = Enc_t(res)
   - S TEE: σ̂_S = pSign(sk_S, m, T)  // Ed25519 adaptor pre-signature
   - S → U: Π = (EncRes, T, σ̂_S)

3. Execution Verification & Conditional Payment:
   - U: pVerify(pk_S, m, T, σ̂_S) を検証
   - U: 条件付き支払い署名 σ_U = Sign(sk_U, m) を発行
   - U → S: σ_U

4. Payment Finalization & Result Delivery:
   Off-chain path: S が t を U に公開
     → U: res = Dec_t(EncRes)
   On-chain path: S が σ_S = AdaptSig(σ̂_S, t) をチェーンに提出
     → U: t = Extract(σ_S, σ̂_S, T) で t を回収 → res = Dec_t(EncRes)
```

実装上は、Provider registration に ASC 用 `participantPubkey` と `participantAttestation` を保持し、`/channel/open` はこの鍵が attested registration 済みでない provider を拒否する。`/channel/deliver` では request body の `provider_pubkey` を信用せず、registration に束縛された `participantPubkey` と一致した場合だけ adaptor pre-signature を受理する。`participantAttestation` は provider enclave の Nitro attestation document と expected policy を含み、facilitator は attestation の certificate chain / COSE signature / PCR / user_data (`providerId`, `participantPubkey`, `attestationPolicyHash`) を検証する。

**Ed25519 Adaptor Signature の実装について:**
- Ed25519のadaptor signatureスキームは学術的に定義されている（[Aumayr et al., 2021]等）
- プロダクション品質のライブラリは限定的。Phase 3で実装 or 既存ライブラリの成熟を待つ
- 代替: secp256k1の署名をSolanaの `Secp256k1SigVerify` precompileで検証する方式も検討可能

### 5.6 Deposit Detection (Enclave側オンチェーン監視)

クライアントのdepositはオンチェーンで直接実行されるため、Enclaveはオフチェーン通知ではなく**オンチェーンイベントの監視**で残高を反映する。ただしNitroでは直接ネットワークがないため、parentのL4 egress relay越しに**TLSをenclave内で張ったRPC接続**を使う。これにより、parentはトラフィックを中継できてもRPC内容を改ざんできない。

```rust
/// Enclave内のdeposit検出ループ
async fn monitor_deposits(rpc: &RpcClient, program_id: &Pubkey) {
    // logsSubscribeでdeposit instructionのsignatureを監視
    let subscription = rpc.logs_subscribe(program_id).await;

    loop {
        let sig = subscription.next().await;
        // finalized後に getTransaction(signature) を取得し、
        // deposit instruction, client signer, client ATA, amount を検証
        // → client_balances[client].free += amount
        // → ParticipantReceiptを生成しクライアントに返却
    }
}
```

**commitment level**: `processed/confirmed` では仮反映せず、`finalized` を待って残高確定とする。

**WebSocket切断時のcatch-up:**

`logsSubscribe` のWebSocket切断は不可避であり、切断〜再接続間のdepositイベントを取りこぼさないために以下の手順を実行する:

1. 切断を検知したら即座に再接続を試行する
2. 再接続成功後、`getSignaturesForAddress(vault_token_account, { until: <last_processed_signature>, commitment: "finalized" })` で切断期間中のdeposit txを取得する
3. 各signatureについて `getTransaction(sig, { commitment: "finalized" })` でinstruction dataをparse し、deposit amount / client signerを検証する
4. WALに `DepositApplied` として記録済みのtxはskipする
5. 未記録のdepositを `client_balances[client].free += amount` し、WALに `DepositApplied` を追記する
6. catch-up完了まで `/verify` を `503 syncing` で拒否する

この手順はEnclave再起動時のrecovery（Nitro deployment spec §8.4）でも同一ロジックを使用する。

### 5.7 Audit Record Generation (TEE内)

決済ごとにTEEが暗号化監査レコードを生成し、オンチェーンに書き込む:

```rust
fn generate_audit_record(
    client: &Pubkey,
    provider: &Pubkey,
    amount: u64,
    auditor_epoch: u32,
    auditor_master_secret: &[u8; 32],
) -> AuditRecordData {
    // プロバイダー別の監査鍵を導出
    let provider_derived_secret = kdf(auditor_master_secret, provider.as_ref());
    let provider_derived_pubkey = derive_elgamal_pubkey(&provider_derived_secret);

    // ElGamal暗号化（TEE内で実行 → 平文は外部に露出しない）
    // ElGamal暗号文は (C1, C2) = (r·G, r·P + m·G) の2点ペアで64 bytes
    let encrypted_sender = elgamal_encrypt(
        &provider_derived_pubkey, client.as_ref()
    );  // → [u8; 64]
    let encrypted_amount = elgamal_encrypt(
        &provider_derived_pubkey, &amount.to_le_bytes()
    );  // → [u8; 64]

    AuditRecordData {
        encrypted_sender,
        encrypted_amount,
        provider: *provider,
        timestamp: current_timestamp(),
        auditor_epoch,
    }
}
```

---

## 6. On-chain Program Design

TEEファーストのため、オンチェーンプログラムはシンプルなエスクロー+決済+紛争解決に徹する。
個別クライアント残高はオンチェーンに存在しない（TEE内部で管理）。

### 6.1 Account Structures

```rust
pub enum VaultStatus {
    Active = 0,
    Paused = 1,
    Migrating = 2,
    Retired = 3,
}

#[account]
pub struct VaultConfig {
    pub bump: u8,                            // PDA bump
    pub vault_id: u64,                       // governance配下で一意な世代番号
    pub governance: Pubkey,                  // pause / migration / retire のみ
    pub status: u8,                          // VaultStatus
    pub vault_signer_pubkey: Pubkey,         // Enclave署名鍵
    pub usdc_mint: Pubkey,
    pub vault_token_account: Pubkey,
    pub auditor_master_pubkey: [u8; 32],
    pub auditor_epoch: u32,                  // current audit key epoch
    pub attestation_policy_hash: [u8; 32],   // PCR群 + EIF署名 + KMS key hash
    pub successor_vault: Pubkey,             // migration時のみ設定、未設定はdefault
    pub exit_deadline: i64,                  // migration/retire締切
    pub lifetime_deposited: u64,             // lifetime counter
    pub lifetime_withdrawn: u64,             // lifetime counter
    pub lifetime_settled: u64,               // lifetime counter
}
/// 現在のエスクロー残高は `vault_token_account.amount` を参照し、
/// lifetime counterから逆算しない。

#[account]
pub struct AuditRecord {
    pub bump: u8,                          // 1
    pub vault: Pubkey,                     // 32
    pub batch_id: u64,                     // 8
    pub index: u8,                         // 1
    pub encrypted_sender: [u8; 64],        // 64 - ElGamal(C1‖C2) sender pubkey
    pub encrypted_amount: [u8; 64],        // 64 - ElGamal(C1‖C2) amount
    pub provider: Pubkey,                  // 32 - 受取人は公開
    pub timestamp: i64,                    // 8
    pub auditor_epoch: u32,                // 4 - どの監査鍵epochで暗号化したか
}
// Size: 214 bytes + 8 discriminator = 222 bytes
// Note: ElGamal暗号文は (C1, C2) = (r·G, r·P + m·G) の2点ペアで各64 bytes。
// randomness r は C1 に内包されるため、別途 nonce フィールドは不要。

/// Force-settle用：participant(client/provider) が提出する残高証明書
#[account]
pub struct ForceSettleRequest {
    pub bump: u8,
    pub vault: Pubkey,
    pub participant: Pubkey,
    pub participant_kind: u8,              // 0=Client, 1=Provider
    pub recipient_ata: Pubkey,
    pub free_balance_due: u64,             // dispute window後すぐ回収可能
    pub locked_balance_due: u64,           // max_lock_expires_at 経過後に回収可能
    pub max_lock_expires_at: i64,          // Provider claim は 0
    pub receipt_nonce: u64,
    pub receipt_signature: [u8; 64],       // EnclaveによるEd25519署名
    pub initiated_at: i64,
    pub dispute_deadline: i64,
    pub is_resolved: bool,
}

#[account]
pub struct UsedWithdrawNonce {
    pub bump: u8,
    pub vault: Pubkey,
    pub client: Pubkey,
    pub withdraw_nonce: u64,
}
```

### 6.2 PDA Seeds

| PDA | Seeds |
|-----|-------|
| VaultConfig | `[b"vault_config", governance, vault_id.to_le_bytes()]` |
| VaultTokenAccount | `[b"vault_token", vault_config]` |
| AuditRecord | `[b"audit", vault_config, batch_id.to_le_bytes(), index]` |
| ForceSettleRequest | `[b"force_settle", vault_config, participant, participant_kind]` |
| UsedWithdrawNonce | `[b"withdraw_nonce", vault_config, client, withdraw_nonce.to_le_bytes()]` |

### 6.3 Instructions

**Vault Management:**

```
initialize_vault(vault_id, vault_signer_pubkey, auditor_master_pubkey, attestation_policy_hash)
  → VaultConfig PDA + VaultTokenAccount PDA を作成
  → vault_id: governance配下の新しいvault世代番号
  → vault_signer_pubkey: Nitro Enclaveの署名鍵
  → auditor_epoch = 0
  → attestation_policy_hash: PCR0/1/2/3/8 + EIF署名 + KMS key hash の固定値
  → status = Active

announce_migration(successor_vault, exit_deadline)
  → governance only
  → status = Migrating
  → signerをin-placeで差し替えず、新Vaultへの移行を告知

pause_vault()
  → governance only
  → status = Paused
  → 異常時に新規verify/settleと signer-authorized on-chain instruction を停止

retire_vault()
  → governance only
  → now >= exit_deadline のとき status = Retired

rotate_auditor(new_auditor_master_pubkey)
  → governance only
  → Enclaveへ新しい auditor master secret がattested channel経由で反映済みであることが前提
  → VaultConfig.auditor_master_pubkey = new_auditor_master_pubkey
  → VaultConfig.auditor_epoch += 1
  → 既存AuditRecordは旧epochの鍵でのみ復号可能。rotationはfuture-onlyでretroactive re-encryptionは行わない
```

**Client Operations (オンチェーン):**

```
deposit(amount: u64)
  → require status == Active
  → USDC CPI転送: client ATA → VaultTokenAccount
  → VaultConfig.lifetime_deposited += amount
  → Enclaveが残高反映:
    Enclaveはdeposit instructionの署名を監視し、finalized txを検証した後に
    client_balances[client].freeを加算する

withdraw(amount: u64, withdraw_nonce: u64, expires_at: i64, enclave_signature: [u8; 64])
  → require status ∈ {Active, Migrating} かつ now <= exit_deadline (Migrating時)
  → Enclaveの署名を検証（vault_signer_pubkeyで）
  → `UsedWithdrawNonce` PDA が未使用であることを確認
  → USDC CPI転送: VaultTokenAccount → client ATA
  → VaultConfig.lifetime_withdrawn += amount
  → `UsedWithdrawNonce` PDA を作成してリプレイを防止
```

**Settlement (Enclaveが実行):**

```
settle_vault(batch_id: u64, batch_chunk_hash: [u8; 32], settlements: Vec<SettlementEntry>)
  → require status ∈ {Active, Migrating} かつ now <= exit_deadline (Migrating時)
  → signer = vault_signer_pubkey (Enclaveのみ実行可能)
  → 各entry: (provider_token_account, amount) のペア
  → USDC CPI転送: VaultTokenAccount → 各Provider TokenAccount
  → 複数クライアントのASC決済を1 txに集約
  → 個別クライアント情報は含まない
  → VaultConfig.lifetime_settled += sum(amounts)
  → Phase 2以降で audit を有効化した後は、同一tx内に
    `record_audit(batch_id, batch_chunk_hash, records)` が存在することを
    `sysvar::instructions` で検証する

record_audit(batch_id: u64, batch_chunk_hash: [u8; 32], records: Vec<AuditRecordData>)
  → require status ∈ {Active, Migrating} かつ now <= exit_deadline (Migrating時)
  → signer = vault_signer_pubkey
  → 暗号化されたAuditRecord PDAを作成
  → 各 record へ現在の `auditor_epoch` を埋め込む
  → `sysvar::instructions` で、同一tx内の `settle_vault` と
    `batch_id` / `batch_chunk_hash` / entry順が一致することを検証する
  → standalone 実行は拒否する
```

**Vault status guard matrix:**

- `Active`: `deposit`, `withdraw`, `settle_vault`, `record_audit` を許可。`force_settle_*` も緊急脱出口として常時利用可能
- `Paused`: `deposit`, `withdraw`, `settle_vault`, `record_audit` を拒否。`force_settle_*` のみ許可
- `Migrating`: `deposit` を拒否。`withdraw`, `settle_vault`, `record_audit` は `exit_deadline` まで許可し、その後は `force_settle_*` のみ許可
- `Retired`: `force_settle_*` と監査用readのみ許可

**Solanaトランザクションサイズ制約によるバッチ上限:**

Solanaの1トランザクションは最大1232 bytes。CPI転送1件あたり約100 bytes + 3,000-5,000 CUを消費するため:

- **Phase 1 `settle_vault` 単独**: 1 txあたり最大**~24件**のプロバイダーへの送金（固定overhead ~248 bytes + 1件あたり ~41 bytes）
- **Phase 2以降 `settle_vault + record_audit` atomic chunk**: 1 txあたり最大**4-5件**（AuditRecord PDA作成が支配的）

バッチサイズを超えた場合は複数txに分割する。これはプライバシーを弱めない（どのtxもVault→Providerのみで、クライアント情報は含まれない）。

```rust
// Enclave側のバッチ分割ロジック
const MAX_SETTLEMENTS_PER_TX_PHASE1: usize = 20;
const MAX_ATOMIC_SETTLEMENTS_PER_TX_WITH_AUDIT: usize = 4;

fn submit_batch(
    batch_id: u64,
    prepared: Vec<PreparedSettlement>,
) {
    let eligible = prepared
        .into_iter()
        .filter(|entry| {
            entry.provider_credit >= AUTO_BATCH_MIN_PROVIDER_PAYOUT
                || entry.oldest_credit_age >= MAX_SETTLEMENT_DELAY_SEC
        })
        .collect::<Vec<_>>();
    let interleaved = round_robin_by_provider(eligible, MAX_SETTLEMENTS_PER_TX_PHASE1);
    let chunks = split_evenly(interleaved, MAX_ATOMIC_SETTLEMENTS_PER_TX_WITH_AUDIT);

    for chunk in chunks {
        let settlement_chunk = aggregate_by_provider(&chunk);
        let audit_chunk = chunk
            .iter()
            .map(|entry| entry.audit.clone())
            .collect::<Vec<_>>();
        let batch_chunk_hash = hash_atomic_chunk(&settlement_chunk, &audit_chunk);
        submit_atomic_settle_and_audit_tx(
            batch_id,
            batch_chunk_hash,
            &settlement_chunk,
            &audit_chunk,
        );
    }
}
```

ここで `settle_vault` に入る `settlement_chunk` は **provider token account ごとの aggregate** であり、`record_audit` は同じ chunk に含まれる個別 request ごとの encrypted record を保持する。automatic batch は小額 provider credit を payout floor 以上に育つまで保留し、`MIN_BATCH_PROVIDERS` と `MIN_ANONYMITY_WINDOW_SEC` を満たすまで provider aggregate をオンチェーン化しない。`MAX_SETTLEMENT_DELAY_SEC` 到達時だけ liveness を優先して flush する。atomic chunk のサイズはできるだけ均等に分配し、最後尾の tiny chunk が単独 provider になる場合は liveness deadline まで保留する。

**Force Settlement (Enclave障害時の脱出口、A402 Algorithm 3 準拠):**

```
force_settle_init(
    free_balance,
    locked_balance,
    max_lock_expires_at,
    receipt_nonce,
    receipt_signature,
    receipt_message,
)
  → participant(client/provider) がEnclave署名付き `ParticipantReceipt` を提出
  → Ed25519署名検証（下記参照）
  → `receipt_message` をデコードし、participant / participant_kind / recipient_ata /
    vault / free_balance / locked_balance / max_lock_expires_at / receipt_nonce が
    instruction引数および口座と一致することを確認
  → ForceSettleRequest PDA 作成
  → dispute_deadline = current_time + DISPUTE_WINDOW (例: 24時間)

force_settle_challenge(newer_receipt_nonce, newer_receipt_signature, newer_receipt_message)
  → participant自身、Receipt Watchtower、または利用可能なEnclaveが
    より新しいnonce の証明書を提出してチャレンジ
  → ForceSettleRequest の recipient_ata / free_balance_due / locked_balance_due /
    max_lock_expires_at / receipt_nonce / receipt_signature を newer receipt で更新

force_settle_finalize()
  → dispute_deadline経過後、有効なチャレンジなし
  → let claimable_now = free_balance_due
      + (current_time >= max_lock_expires_at ? locked_balance_due : 0)
  → require vault_token_account.amount >= claimable_now
      （不足時は `vault_insolvent` として失敗。partial payoutはしない）
  → USDC CPI転送: VaultTokenAccount → recipient_ata (claimable_now分)
  → free_balance_due = 0
  → if current_time >= max_lock_expires_at { locked_balance_due = 0 }
  → 両方0なら ForceSettleRequest.is_resolved = true
```

`force_settle_*` は governance の pause/migration 操作に依存しない**常時利用可能な緊急脱出口**として設計する。`Paused` / `Retired` / `Migrating` の期限超過後は通常系 instruction が停止するため、残高回収経路は `force_settle_*` のみになる。なお trust-minimized recovery の保証対象は**solvent vault** に限る。不足時は protocol error として停止し、governance/top-up を伴う incident response に移る。

**Ed25519署名のオンチェーン検証方法:**

SolanaでEd25519署名をオンチェーン検証するには、`Ed25519Program` precompileを使用する。
通常のSigner検証（トランザクション署名者の確認）とは異なり、**任意のメッセージに対する署名を検証**できる。

```
トランザクション構成:
  Instruction 0: Ed25519Program.createInstructionWithPublicKey({
    publicKey: vault_signer_pubkey,
    message: receipt_message,    // ParticipantReceiptのシリアライズ
    signature: receipt_signature
  })
  Instruction 1: a402_vault::force_settle_init(...)
    → プログラム内で sysvar::instructions を読み、
      Instruction 0 のEd25519検証が成功したことを確認
```

この方式はSolanaで広く使われるパターン（例: Serum, Wormhole）であり、~2,000 CU/署名で検証可能。

### 6.4 AuditRecord PDA のコスト

各AuditRecord PDA (222 bytes) の作成にはrent exemptionとして約0.00159 SOLが必要。

| 規模 | AuditRecord数 | 必要SOL | 備考 |
|------|-------------|---------|------|
| 小規模テスト | 100件 | ~0.156 SOL | Devnet airdropで十分 |
| 中規模 | 10,000件 | ~15.6 SOL | |
| 大規模 | 100,000件 | ~156 SOL | |

**Devnet開発時**: `solana airdrop` でDevnet SOLを確保して利用。

**Mainnet移行時の検討事項:**
- AuditRecordのrent負担者はNitro Enclave signer（`settle_vault` / `record_audit` txのpayer）
- 古いAuditRecordをクローズしてrentを回収する機能（監査期間終了後）

---

## 7. Client SDK

### 7.1 API Design

既存x402の `fetch → 402処理 → PAYMENT-SIGNATURE再送` という利用体験を維持しつつ、内部ではNitro Enclave向けの `subly402-svm-v1` payload を生成する。

```typescript
// @a402/client

// === 既存x402（参考） ===
import { buildSolanaX402Client } from "@alchemy/x402";
const client = buildSolanaX402Client(privateKey);
const res = await client.fetch("https://x402.alchemy.com/solana-mainnet/v2", { body });

// === プライバシー版（本プロトコル） ===
import { A402Client } from "@a402/client";

const client = new A402Client({
  walletKeypair,                              // クライアントのSolana Keypair
  vaultAddress: new PublicKey("..."),          // 参加するVaultアドレス
  enclaveUrl: "https://vault.example.com",    // Nitro Enclave ingress endpoint
});

// 初回: Remote Attestationで TEE を検証
await client.verifyAttestation();

// 使い方は既存x402と同じ — fetchするだけ
const res = await client.fetch("https://x402.alchemy.com/solana-mainnet/v2", {
  method: "POST",
  body: JSON.stringify({
    jsonrpc: "2.0", method: "eth_blockNumber", params: [], id: 1
  }),
});
```

内部では自動的に:
1. Providerから `PAYMENT-REQUIRED` を受信
2. Nitro Enclaveのattestationを検証
3. `subly402-svm-v1` payload をローカル生成
4. `PAYMENT-SIGNATURE` にopaque payloadを載せてProviderへ再送
5. Providerはcustom facilitator経由でverify/settleし、レスポンスを返却

### 7.2 Vault Operations

```typescript
// 入金（オンチェーン直接）
await client.deposit(10_000_000);  // 10 USDC (6 decimals)

// 出金（Enclave署名 + nonce付き）
await client.withdraw(5_000_000);  // Enclaveが署名 → オンチェーンで実行

// 強制出金（Enclave障害時）
const receipt = client.getLatestClientReceipt();
await client.forceSettle(receipt);  // dispute window後に出金
```

### 7.3 Audit Tool

```typescript
import { AuditTool } from "@a402/client";

// マスター鍵で全取引を復号
const auditor = new AuditTool(auditorMasterSecret);
const allRecords = await auditor.decryptAll(vaultAddress);

// 特定プロバイダーのみ復号
const providerRecords = await auditor.decryptForProvider(
  vaultAddress, providerAddress
);

// 導出鍵を第三者に渡す（部分開示）
const exportedKey = auditor.exportProviderKey(providerAddress);
// → この鍵を持つ人はProvider Aへの支払いのみ復号可能
```

---

## 8. Development Phases

### Phase 1 — Nitro MVP: Vault + Custom Facilitator + Batch Settlement

**Goal**: Nitro Enclave経由の送金者匿名性とx402 HTTP envelope互換を最小構成で実現
**Environment**: Solana Devnet + Nitro Enclave対応EC2

- Anchor Program:
  - Account structs: 全Phaseのフィールドを含めてデプロイ（`VaultConfig`, `AuditRecord`, `ForceSettleRequest`, `UsedWithdrawNonce`）。account sizeを後から変更するとrealloc + migrationが必要になるため、初回から確定させる
  - Instructions: `initialize_vault`, `deposit`, `withdraw`, `settle_vault`, `pause_vault`（緊急停止は初日から必要）
  - Phase 2以降の instruction（`record_audit`, `force_settle_*`, `announce_migration`, `retire_vault`）はプログラム upgrade で追加。account structの変更ではないので安全
- Nitro Enclave: クライアント残高管理、custom facilitator（`/verify`, `/settle`）
- Parent Instance: ingress relay / egress relay / KMS proxy / encrypted snapshot storage
- Deposit Detection: Enclaveがdeposit instructionを監視して `finalized` 後に残高反映
- Remote Attestation: クライアントがEnclave検証可能
- KMS-backed snapshot/WAL による再起動復旧
- 基本Client SDK（deposit, withdraw, fetch, verifyAttestation）
- Test: Bankrun + ローカルNitroシミュレーション + Dev Nitro環境

**Privacy**: On-chain observerから送金者匿名。Parent instanceも平文payloadにアクセス不可。
**Exec-Pay-Deliver**: 保証なし（Provider信頼モデル）。HTTP envelopeはx402互換だが、payment semanticsはA402専用。

### Phase 2 — Audit Records + Selective Disclosure

**Goal**: 決済ごとに暗号化監査証跡を生成、プロバイダー単位で開示可能
**Environment**: Solana Devnet

- `record_audit` instruction + AuditRecord PDA
- Enclave内でElGamal暗号化（プロバイダー別導出鍵）
- 階層的鍵導出（KDF + ElGamal鍵ペア）
- settle_vaultのバッチ分割対応（最大~24件/tx、AuditRecord最大4-5件/tx）
- `rotate_auditor` instruction（future-only。`auditor_epoch` を進め、旧epoch鍵は監査側で保持）
- AuditTool（SDK）
- Test: 暗号化/復号の正確性 + プロバイダー別開示の検証

### Phase 3 — Atomic Service Channels + Provider TEE

**Goal**: A402のASC相当のオフチェーン高頻度マイクロペイメント + 暗号学的アトミシティ

- Enclave内ASC状態管理（A402 Algorithm 1 準拠）
- **Provider側TEE導入**: Service ProviderもTEE内でリクエストを実行
- **Ed25519 Adaptor Signatures**: Exec-Pay-Deliver アトミシティを暗号学的に保証（A402 Algorithm 2 完全準拠）
- **Provider鍵束縛**: registration の `participantPubkey` に provider TEE の署名鍵を固定し、ASC deliver 時はその一致を強制する
- Batch Settlement: `settle_vault` で複数ASCを1 tx（最大20-30件）に集約
- Participant Receipts: Enclaveがclient/provider向け署名付き残高証明書を発行
- Client SDK `fetch` wrapper完全版

**Exec-Pay-Deliver**: 暗号学的に保証。Providerは結果を返さない限り支払いを受け取れない。

### Phase 4 — Force Settlement + Dispute Resolution

**Goal**: Enclave障害・migration時のオンチェーン脱出口（Trust-Minimized Asset Security）

- `force_settle_init` / `force_settle_challenge` / `force_settle_finalize`
- ForceSettleRequest PDA + dispute window（client / provider 両対応）
- ParticipantReceipt署名検証: `Ed25519Program` precompile + `sysvar::instructions`
- `announce_migration` + exit window
- Receipt Watchtower（必須）: 最新receiptを保持し、force-settle要求を監視・チャレンジ

### Phase 5 — Arcium MXE Integration

**Goal**: オンチェーン残高の暗号化による追加プライバシー層

- `encrypted-ixs/`: Arcis circuits（update_balance, settle_and_audit）
- ClientDeposit PDAに暗号化残高保存（`[u8; 32]` ciphertext）
- TEE + Arcium のハイブリッド: TEEで状態管理、Arciumでオンチェーン暗号化検証
- TEEなしでもArcium単体で残高秘匿が可能（TEEへの依存度低減）
- 詳細設計: [`docs/phase5-arcium-design.md`](./phase5-arcium-design.md)

### Phase 6 (Future) — Deposit Privacy

- Token-2022 Confidential Transfer を使ったプライベート入金
  - 注: 現時点（2026-04時点）ではMainnet可用性要確認。ZK-Edge testnetでは利用可能
  - 1回のConfidential Transferに7トランザクション必要で、高頻度利用には不向き
- Vault入金者のアドレスも秘匿

---

## 9. Project Structure

```
a402-solana/
├── Anchor.toml
├── Cargo.toml
├── programs/
│   └── a402_vault/
│       ├── Cargo.toml
│       └── src/
│           ├── lib.rs                 # Program entry
│           ├── constants.rs           # PDA seeds, dispute window duration
│           ├── error.rs               # Error codes
│           ├── state.rs               # VaultConfig, AuditRecord, ForceSettleRequest
│           └── instructions/
│               ├── mod.rs
│               ├── initialize_vault.rs
│               ├── announce_migration.rs
│               ├── pause_vault.rs
│               ├── retire_vault.rs
│               ├── deposit.rs
│               ├── withdraw.rs
│               ├── settle_vault.rs
│               ├── record_audit.rs
│               ├── force_settle_init.rs
│               ├── force_settle_challenge.rs
│               ├── force_settle_finalize.rs
│               └── rotate_auditor.rs
├── enclave/                           # Nitro Enclave service
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs                    # Entrypoint (runs inside TEE)
│       ├── state.rs                   # VaultState, ClientBalance, ChannelState
│       ├── attestation.rs             # Remote Attestation
│       ├── facilitator.rs             # /verify /settle /attestation
│       ├── ingress_tls.rs             # TLS termination inside enclave
│       ├── egress_rpc.rs              # Solana RPC/WebSocket client
│       ├── asc_manager.rs             # ASC lifecycle (Phase 3)
│       ├── audit.rs                   # ElGamal encryption + key derivation
│       ├── receipt.rs                 # Participant receipt signing
│       ├── snapshot.rs                # Encrypted snapshot/WAL
│       └── kms_bootstrap.rs           # Attested KMS decrypt/data key bootstrap
├── watchtower/
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs                    # Receipt watchtower entrypoint
│       ├── receipt_store.rs           # Latest ParticipantReceipt per participant
│       └── challenger.rs              # force_settle_challenge submitter
├── parent/                            # Untrusted parent instance services
│   ├── Cargo.toml
│   └── src/
│       ├── ingress_relay.rs           # TCP -> vsock relay
│       ├── egress_relay.rs            # vsock -> TCP relay
│       ├── kms_proxy.rs               # Nitro KMS proxy supervisor
│       └── snapshot_store.rs          # EBS/S3 persistence for encrypted blobs
├── infra/
│   ├── terraform/
│   └── nitro/
│       ├── enclave.eif
│       └── attestation-policy.json
├── sdk/
│   ├── package.json
│   └── src/
│       ├── client.ts                  # A402Client
│       ├── attestation.ts             # Remote Attestation verification
│       ├── types.ts                   # Type definitions
│       └── audit.ts                   # AuditTool
├── encrypted-ixs/                     # Phase 5 (Arcium)
│   ├── Cargo.toml
│   └── src/
│       └── lib.rs
└── tests/
    ├── a402-vault.ts                  # Anchor unit tests
    ├── a402-nitro-integration.ts      # Nitro integration tests
    ├── a402-parent-adversary.ts       # Parent relay compromise simulation
    └── a402-e2e.ts                    # Full E2E tests
```

---

## 10. Verification Plan

| Phase | 検証内容 | 手法 |
|-------|---------|------|
| Phase 1 | Nitro attestation検証、deposit → Enclave残高更新 → settle_vault → withdraw。on-chainにクライアント個別支払いが出ないことを確認 | Bankrun + Nitro integration |
| Phase 1 | Parent relayを侵害してもTLS終端・秘密鍵・平文stateにアクセスできないことを確認 | Adversary simulation |
| Phase 1 | Enclave再起動後にKMS bootstrap + encrypted snapshot/WALから復旧できることを確認 | Fault injection |
| Phase 2 | `settle_vault + record_audit` を同一txで実行し、支払い成功時に監査証跡が欠落しないことを確認 | E2E |
| Phase 2 | `rotate_auditor` 後に新epochのAuditRecordは新鍵でのみ復号でき、旧epochのRecordは旧鍵で継続復号できることを確認 | E2E |
| Phase 3 | ASC open → 複数リクエスト（オフチェーン） → batch settle。1 txに集約されることを確認 | E2E + Nitro + Provider TEE |
| Phase 4 | Enclaveシャットダウン → ParticipantReceipt提出 → dispute window → `free_balance` 回収、`max_lock_expires_at` 後に `locked_balance` も回収できることを確認 | Bankrun + 障害注入 |
| Phase 4 | stale receipt を提出しても Receipt Watchtower が challenge し、過剰引出しが成立しないことを確認 | Adversary simulation |
| Phase 4 | vault残高不足時に `force_settle_finalize` が partial payout せず `vault_insolvent` で停止することを確認 | Insolvency simulation |
| Phase 4 | `announce_migration` 後に旧Vaultからexit/new vault移行ができることを確認 | Migration rehearsal |
| Phase 5 | Arcium encrypted_balance更新。TEEなしでもArcium単体で残高秘匿が機能することを確認 | Arcium devnet |
