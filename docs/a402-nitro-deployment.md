# A402-Solana Nitro Deployment Specification

> Version: 0.1.0
> Date: 2026-04-12
> Status: Draft
> Companion: [a402-solana-design.md](./a402-solana-design.md)

---

## 1. Goals

この文書は、A402-Solana の facilitator / vault runtime を AWS Nitro Enclaves 上で運用するための配備・復旧・移行仕様を定義する。

Phase 1 の目標:

- request / response の平文を parent instance に見せない
- vault signer / auditor secret / snapshot key を parent instance に見せない
- Nitro attestation と KMS policy を組み合わせて enclave identity を固定する
- enclave crash 後に encrypted snapshot / WAL から復旧できる

Phase 1 の非目標:

- multi-active enclave consensus
- cross-region BFT replication
- provider-side enclave の配備

---

## 2. Reference Topology

```text
                Internet
                    │
             TCP 443 passthrough
                    │
                  NLB
                    │
          ┌───────────────────────┐
          │ Parent EC2 Instance   │
          │                       │
          │ ingress_relay         │──vsock 8443──┐
          │ egress_relay          │◀─vsock 9443──┤
          │ kms_proxy supervisor  │◀─vsock 8000──┤
          │ snapshot_store        │◀─vsock 7000──┤
          └───────────────────────┘              │
                                                 ▼
                                      ┌────────────────────┐
                                      │ Nitro Enclave      │
                                      │ rustls/hyper       │
                                      │ facilitator        │
                                      │ vault state        │
                                      │ Solana signer      │
                                      │ KMS bootstrap      │
                                      └────────────────────┘
```

---

## 3. AWS Components

最小構成:

- 1 x EC2 parent instance
- 1 x Nitro Enclave
- 1 x Network Load Balancer
- 1 x customer-managed KMS key for seed/state unwrap
- 1 x S3 bucket または encrypted EBS volume for snapshot/WAL
- 1 x Solana RPC provider
- 1 x Receipt Watchtower service

推奨追加:

- CloudWatch logs / metrics
- separate watcher instance for Solana finality / force-settle monitoring
- second warm-standby parent instance

---

## 4. Parent / Enclave Responsibility Split

### Parent Instance

parent instance は**信頼しない**。責務は可用性と中継だけに限定する。

許可する責務:

- TCP ingress を vsock に中継する
- enclave からの outbound TLS byte stream を internet へ中継する
- KMS proxy process を起動する
- encrypted snapshot / WAL blob を保存する
- health checks と process supervision を行う

禁止する責務:

- TLS termination
- request body parsing
- Solana signer 所持
- payment verification / settlement logic 実行
- snapshot 平文の保持

### Enclave

enclave が保持する秘密:

- vault signer seed
- auditor master secret
- decrypted snapshot / in-memory state
- provider/client receipts の signing context

enclave が実行するロジック:

- `/attestation`, `/verify`, `/settle`, `/cancel`
- deposit detection
- batch construction / submission
- receipt generation
- snapshot/WAL encryption

### Receipt Watchtower

Receipt Watchtower は Phase 4 の trust-minimized asset recovery に**必須**とする。

責務:

- 最新の `ParticipantReceipt` を participant ごとに保持する
- `force_settle_init` を監視する
- より新しい receipt があれば `force_settle_challenge` を送る

許可する責務:

- receipt metadata の保持（`freeBalance`, `lockedBalance`, `maxLockExpiresAt`, `nonce` を含む）
- Solana watch / challenge transaction 提出

禁止する責務:

- facilitator signing
- request body 取得
- payment verification logic 実行

---

## 5. Ingress Path

### 5.1 Required Property

client / provider と facilitator 間の TLS は enclave 内で終端しなければならない。

そのため:

- **NLB TCP mode** を使う
- **ALB は使わない**
- **ACM for Nitro Enclaves with nginx on parent** も Phase 1 では採用しない

理由:

- ALB は HTTP/TLS を parent 手前で復号する
- ACM for Nitro + nginx は private key を enclave に隔離できるが、HTTP plaintext は parent nginx が見る
- A402 の privacy goal では、request path/body/payment payload を parent から隠す必要がある

### 5.2 Listener Layout

- NLB: TCP/443 -> parent instance port 443
- parent `ingress_relay`: TCP/443 を raw byte stream のまま vsock/8443 へ転送
- enclave: vsock/8443 上で rustls + HTTP server を起動

---

## 6. Egress Path

Nitro Enclave は直接ネットワークを持たないため、outbound は parent relay 経由にする。

### 6.1 Traffic Classes

- Solana RPC HTTPS
- Solana WebSocket subscribe
- provider callback / provider verification traffic
- KMS bootstrap traffic

### 6.2 Rules

- TLS session は enclave 内で作る
- parent は destination IP/port への byte pipe のみ提供する
- outbound destination allowlist を parent firewall で制限する

推奨 allowlist:

- configured Solana RPC endpoint
- configured provider domains
- KMS / STS / Nitro-related AWS endpoints

---

## 7. Attestation and KMS Bootstrap

### 7.1 Build Artifacts

deployment artifact:

- signed EIF image
- enclave manifest
- attestation policy JSON

最低限固定する PCR:

- `PCR0`: image measurement
- `PCR1`: kernel / bootstrap measurement
- `PCR2`: application / filesystem-related measurement
- `PCR3`: role-specific runtime inputs
- `PCR8`: EIF signing certificate measurement

### 7.2 Attestation Policy Hash

on-chain に固定する `attestation_policy_hash` は次を canonical JSON 化して SHA-256 する。

```json
{
  "version": 1,
  "pcrs": {
    "0": "<hex>",
    "1": "<hex>",
    "2": "<hex>",
    "3": "<hex>",
    "8": "<hex>"
  },
  "eifSigningCertSha256": "<hex>",
  "kmsKeyArnSha256": "<hex>",
  "protocol": "a402-svm-v1"
}
```

### 7.3 KMS Keys

Phase 1 では少なくとも 2 種類の鍵を使う。

- `a402-root-key`
  - vault signer seed
  - auditor master secret
  - snapshot master key wrapping

- `a402-snapshot-data-key`
  - snapshot / WAL blob の content encryption

### 7.4 KMS Policy Requirements

KMS key policy は Nitro attestation condition keys で制限する。

意図:

- parent instance IAM role だけでは decrypt できない
- attested enclave が出した attestation document がないと data key を受け取れない
- 許可された PCR set と EIF signer 以外は拒否される

### 7.5 Bootstrap Sequence

1. parent が enclave を起動する
2. enclave が ephemeral bootstrap key pair を生成する
3. enclave が attestation document を作る
4. kmstool / KMS proxy 経由で `Decrypt` または `GenerateDataKey` を呼ぶ
5. KMS は attestation 条件を確認し、response を enclave public key に束縛して返す
6. enclave が vault signer seed と snapshot key material を復元する
7. snapshot/WAL recovery を完了してから facilitator API を `ready` にする

注記:

- step 3 の bootstrap document は KMS recipient key を束縛するためのものであり、client に返す `/v1/attestation` document と同一である必要はない
- facilitator は serving 時に NSM で新しい runtime attestation document を生成し、`user_data` に `vault_signer`, `attestation_policy_hash`, `snapshot_seqno` を、`public_key` に ingress TLS public key を束縛する

---

## 8. Persistence Model

Nitro Enclave には永続ディスクがないため、state persistence は次の二層で構成する。

- encrypted WAL
- encrypted snapshot

### 8.1 WAL Entry Types

最低限必要な event:

- `DepositApplied`
- `ReservationCreated`
- `ReservationCancelled`
- `ReservationExpired`
- `SettlementCommitted`
- `ParticipantReceiptIssued`
- `ParticipantReceiptMirrored`
- `AuditorRotated`
- `BatchSubmitted`
- `BatchConfirmed`
- `MigrationAnnounced`

### 8.2 Commit Rule

`/verify` と `/settle` の response を返す前に:

1. 対応する WAL entry を生成する
2. data key で暗号化する
3. parent の `snapshot_store` に append する
4. append ack を受ける
5. その後にのみ success response を返す

この順序を破ると、enclave crash 時に provider/client へ返した receipt と内部 state が不整合になる。

`ParticipantReceipt` 発行時は追加で:

1. `ParticipantReceiptIssued` をWALへ記録する
2. Receipt Watchtower へ同期し、ack を受ける
3. `ParticipantReceiptMirrored` をWALへ記録する

Phase 4 の stale receipt safety は、この mirror step が durable に完了していることを前提とする。

### 8.3 Snapshot Rule

推奨:

- `SNAPSHOT_EVERY_N_EVENTS = 1000`
- `SNAPSHOT_EVERY_SEC = 30`

snapshot には以下を含める:

- vault balances
- active reservations
- provider credit ledger
- current auditor epoch
- pending batch metadata
- latest participant receipt nonce
- last finalized Solana slot

### 8.4 Recovery Sequence

1. latest complete snapshot をロード
2. snapshot seqno より後ろの WAL を順に再生
3. in-flight batch を Solana chain と照合する
4. deposit catch-up: `last_finalized_slot` 以降の deposit を再取得して取りこぼしを補正する
   a. `getSignaturesForAddress(vault_token_account, { until: <last_processed_signature>, commitment: "finalized" })` で deposit tx の signature 一覧を取得
   b. 各 signature について `getTransaction(sig, { commitment: "finalized" })` を取得し、deposit instruction の client signer / amount を検証
   c. WAL に `DepositApplied` として記録済みの tx は skip
   d. 未記録の deposit を `client_balances[client].free += amount` し、WAL に `DepositApplied` を追記
   e. `last_finalized_slot` を更新
5. ready になるまで `/verify` と `/settle` は `503 recovering`

このロジックは定常運用時の WebSocket 切断→再接続時の catch-up と共通化する（a402-solana-design.md §5.6 参照）。

---

## 9. Deployment Lifecycle

### 9.1 Initial Bootstrap

1. Terraform で VPC, NLB, EC2, IAM, KMS, S3/EBS を作成
2. signed EIF を build する
3. PCR 値と `attestation_policy_hash` を確定する
4. `initialize_vault` で `vault_signer_pubkey` と `attestation_policy_hash` を on-chain に固定する
5. enclave を起動し、bootstrap/recovery 完了後に traffic を流す

### 9.2 Upgrading Enclave Code

コード upgrade では signer を on-chain で直接差し替えない。

手順:

1. 新 EIF を build して新 PCR を確定する
2. 新 vault を別アドレスで deploy する
3. `announce_migration(successor_vault, exit_deadline)` を旧 vault に送る
4. 新規 traffic は新 vault へ送る
5. 旧 vault の client / provider balances は participant force-settle または cooperative withdrawal で解放する
   - client receipt に `lockedBalance > 0` がある場合、その portion は `maxLockExpiresAt` 経過後に回収される
6. exit window 後に旧 vault を停止する

### 9.2.1 Auditor Rotation

監査鍵ローテーションは future-only とする。

1. governance が新しい auditor master secret を attested admin channel で enclave に投入する
2. enclave が新 secret の public key を生成して提示する
3. governance が `rotate_auditor(new_auditor_master_pubkey)` を送る
4. 以後の AuditRecord は新 `auditor_epoch` で暗号化する
5. 旧 epoch の secret は historical decryption 用に監査側で保管する

### 9.3 Warm Standby

Phase 1 の HA は active/passive のみを許可する。

- active enclave だけが verify / settle を受ける
- standby enclave は traffic を受けず、snapshot blob のみ同期する
- failover 時は standby が bootstrap + recovery を完了してから NLB target を切り替える

active-active は attested replication protocol が入るまで禁止する。

---

## 10. Monitoring

最低限の指標:

- enclave bootstrap latency
- `/verify` p50 / p95 / error rate
- `/settle` p50 / p95 / error rate
- reservation queue size
- provider credit backlog
- oldest unsettled provider credit age
- snapshot lag
- WAL append latency
- Solana submission failures
- force-settle requests count
- `vault_insolvent` error count

最低限の alert:

- attestation drift
- KMS decrypt failure
- recovery mode > 5 minutes
- batch settlement delay > `MAX_SETTLEMENT_DELAY_SEC`
- snapshot store write failure

---

## 11. Incident Response

### 11.1 Suspected Parent Compromise

想定:

- parent root 奪取
- relay process 改ざん
- disk snapshot 流出

対応:

1. `pause_vault()` で新規 verify / settle を止める
2. enclave の attestation と signer が不変か確認する
3. 新 parent + 新 enclave を別ホストで立ち上げる
4. 旧 vault から migration を告知する

期待される性質:

- parent compromise 単独では signer seed と snapshot plaintext は漏れない

### 11.2 Suspected Enclave Compromise

想定:

- attestation mismatch
- unexpected signer
- PCR drift

対応:

1. 即時に traffic を遮断する
2. `pause_vault()` を実行する
3. 新 vault を deploy して migration を告知する
4. participant に cooperative withdrawal / force-settle を促す
5. Receipt Watchtower が stale receipt challenge を継続できることを確認する
6. `vault_insolvent` が発生した場合、partial payout は行わず top-up または別途resolution手順へ移る

### 11.3 KMS Outage

想定:

- running enclave は継続可能
- fresh restart は不能

対応:

- active enclave を落とさない
- snapshot cadence を下げて write-only mode に移るか、必要なら `pause_vault()` する

---

## 12. Security Checklist

- NLB は TCP passthrough にする
- parent で TLS termination しない
- enclave は debug 無効
- EIF signer 証明書 fingerprint を attestation policy に入れる
- KMS key policy を attestation 条件付きにする
- success response 前に WAL durable append を必須にする
- `vault_signer_pubkey` は on-chain で in-place rotation しない
- provider auth credential を facilitator registration に束縛する
- snapshot/WAL は常に envelope encryption で保存する
- Receipt Watchtower に最新 `ParticipantReceipt` を同期する

---

## 13. Open Items

- warm standby の snapshot 受け渡しを S3 event でやるか EBS snapshot でやるか
- provider callback egress の domain pinning をどこまで厳しくするか
- attestation policy hash に AMI hash や parent role hash を入れるか
- long-lived WebSocket を egress relay でどう health-check するか
