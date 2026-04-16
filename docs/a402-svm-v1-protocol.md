# A402-SVM-V1 Protocol Specification

> Version: 0.1.0
> Date: 2026-04-12
> Status: Draft
> Companion: [a402-solana-design.md](./a402-solana-design.md)

---

## 1. Scope

`a402-svm-v1` は、x402 の HTTP envelope を維持したまま、支払いの意味論を「client が直接 on-chain transfer を出す」方式から「Nitro Enclave 内 vault balance を条件付きで予約し、後で batched settlement する」方式へ置き換える custom payment scheme である。

この spec が固定するもの:

- `PAYMENT-REQUIRED` の `accepts[]` に入る payment details
- `PAYMENT-SIGNATURE` ヘッダに入る payment payload
- provider と facilitator 間の `/verify` `/settle` `/cancel` `/attestation` API
- payment idempotency / reservation / batch settlement の状態機械

この spec がまだ固定しないもの:

- Phase 3 の provider TEE 間メッセージ
- Ed25519 adaptor signature の exact transcript
- signed offers / receipts など x402 extension との正式な相互運用

---

## 2. Compatibility Profile

`a402-svm-v1` は以下を維持する:

- client は paid resource に対して通常の HTTP request を送る
- server は `402 Payment Required` を返す
- client は `PAYMENT-SIGNATURE` を付けて request を再送する
- server は facilitator に verify / settle を委譲する
- server は `PAYMENT-RESPONSE` を返す

`a402-svm-v1` は以下を変更する:

- `PAYMENT-SIGNATURE` の中身は raw Solana transfer transaction ではない
- verify / settle 先は汎用 x402 facilitator ではなく、A402-aware facilitator である
- on-chain settlement は per-request ではなく batched である

---

## 3. Roles

- `Client`: provider へ request を送る buyer-side agent
- `Provider`: paid resource を提供する HTTP server
- `Facilitator`: Nitro Enclave 内で動く A402-aware verifier / reserver / settler
- `ReceiptWatchtower`: 最新の `ParticipantReceipt` を保持し、enclave unavailable 時に stale receipt challenge を代行する
- `Vault Program`: Solana上の escrow / batch settlement / force-settle program
- `Governance`: vault の pause / migration 告知だけを行う operator key

---

## 4. Provider Registration

provider は route ごとの `PAYMENT-REQUIRED` を返す前に、facilitator へ out-of-band 登録されていなければならない。

`ProviderRegistration`:

```json
{
  "providerId": "prov_01JQ8V8T3V9Q8T8M8G9K0J4W7A",
  "displayName": "alchemy-solana-rpc",
  "participantPubkey": "9xQeWvG816bUx9EPfEZmP4nTqYhA6s1xY9q6m7V4sQ9N",
  "participantAttestation": {
    "document": "base64(...)",
    "policy": {
      "version": 1,
      "pcrs": {
        "0": "...",
        "1": "...",
        "2": "...",
        "3": "...",
        "8": "..."
      },
      "eifSigningCertSha256": "...",
      "kmsKeyArnSha256": "...",
      "protocol": "a402-provider-v1"
    },
    "maxAgeMs": 600000
  },
  "settlementTokenAccount": "7xKXtg2CW...", 
  "network": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
  "assetMint": "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
  "allowedOrigins": [
    "https://x402.alchemy.example"
  ],
  "authMode": "bearer",
  "authMaterial": {
    "apiKeyId": "pk_live_provider_123"
  }
}
```

制約:

- `providerId` は facilitator 内で一意
- `settlementTokenAccount` は provider が最終受領する SPL token account
- `authMode` は `bearer` / `api-key` / `mtls` をサポートする
- `bearer` と `api-key` はどちらも provider secret の SHA-256 hash を facilitator へ登録し、`Authorization: Bearer ...` または `x-a402-provider-auth` で提示する
- `allowedOrigins` は `/verify` 時に request origin と照合する
- Phase 3 ASC provider は `participantPubkey` を持たなければならず、対応する `participantAttestation` を facilitator へ提示して attested registration を完了しなければならない
- `participantAttestation.document` は Nitro attestation document または local-dev provider attestation document であり、signed user_data に `providerId`, `participantPubkey`, `attestationPolicyHash` を束縛しなければならない
- facilitator は `participantAttestation.policy.pcrs` を attestation document と照合し、`participantAttestation.policy` から計算した policy hash が user_data の `attestationPolicyHash` と一致することを確認しなければならない

---

## 5. PAYMENT-REQUIRED Schema

provider は `accepts[]` の各要素として以下を返す。

```json
{
  "scheme": "a402-svm-v1",
  "network": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
  "amount": "1000000",
  "asset": {
    "kind": "spl-token",
    "mint": "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
    "decimals": 6,
    "symbol": "USDC"
  },
  "payTo": "7xKXtg2CW...",
  "providerId": "prov_01JQ8V8T3V9Q8T8M8G9K0J4W7A",
  "facilitatorUrl": "https://vault.example.com/v1",
  "vault": {
    "config": "9oX9G2xD...",
    "signer": "6MS8C3c4...",
    "attestationPolicyHash": "1a6c2f1f4f8f2a0f7a0e8d5b5a1a6d2d53b49939f4c7d9626abfce2033d5d2fe"
  },
  "paymentDetailsId": "paydet_01JQ8VB4E4X7M1K5Q7SY4P1Y7H",
  "verifyWindowSec": 60,
  "maxSettlementDelaySec": 900,
  "privacyMode": "vault-batched-v1"
}
```

必須フィールド:

| Field | Type | Meaning |
|------|------|---------|
| `scheme` | string | 固定値 `a402-svm-v1` |
| `network` | string | CAIP-2 形式の Solana network id |
| `amount` | string | atomic units の decimal string |
| `asset.mint` | string | SPL token mint |
| `payTo` | string | provider settlement token account |
| `providerId` | string | facilitator に登録済み provider id |
| `facilitatorUrl` | string | `/verify` `/settle` `/attestation` を提供する base URL |
| `vault.config` | string | VaultConfig PDA |
| `vault.signer` | string | Enclave signer pubkey |
| `vault.attestationPolicyHash` | string | attestation policy hash |
| `paymentDetailsId` | string | provider 発行の一意 id |
| `verifyWindowSec` | integer | verify 後に `/settle` を待つ秒数 |
| `maxSettlementDelaySec` | integer | provider credit が on-chain batch されるまでの最大遅延 |

`paymentDetailsHash` は、client / provider / facilitator で共通に次式で計算する:

```text
paymentDetailsHash = SHA-256(canonical_json(selected_accept_object))
```

ここで `canonical_json` は:

- UTF-8
- key は辞書順
- 余分な whitespace を入れない
- integer は 10 進表記
- string normalization は行わない

---

## 6. PAYMENT-SIGNATURE Payload

`PAYMENT-SIGNATURE` ヘッダの値は、下記 JSON を UTF-8 エンコードし、さらに Base64URL したものとする。

```json
{
  "version": 1,
  "scheme": "a402-svm-v1",
  "paymentId": "pay_01JQ8VKGW2P4M0C31Q1QKQQR4M",
  "client": "4xzJcN4h...",
  "vault": "9oX9G2xD...",
  "providerId": "prov_01JQ8V8T3V9Q8T8M8G9K0J4W7A",
  "payTo": "7xKXtg2CW...",
  "network": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
  "assetMint": "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
  "amount": "1000000",
  "requestHash": "4b6ee3b1ff5a4f4f923ce2d2d7a6cda3dd44f5d466fb40f11bf3f5e7c4d84c22",
  "paymentDetailsHash": "0f3073c55f5016b4310f6123f2142d0f2ef758f2f2efb7e88a2f8d2a5ec7f182",
  "expiresAt": "2026-04-12T00:30:00Z",
  "nonce": "1844674407370955161",
  "clientSig": "base64(ed25519(signature))"
}
```

必須制約:

- `paymentId` は client が一意に生成する
- `vault` は `vault.config` と一致しなければならない
- `payTo` は `payment details.payTo` と一致しなければならない
- `expiresAt` は provider が受理する時点で未来でなければならない
- `nonce` は client ローカルで重複禁止とする

### 6.1 Client Signature Message

client は次の message を Ed25519 で署名する。

```text
A402-SVM-V1-AUTH
version
scheme
paymentId
client
vault
providerId
payTo
network
assetMint
amount
requestHash
paymentDetailsHash
expiresAt
nonce
```

各行は UTF-8 string とし、末尾に `\n` を付ける。整数は 10 進 string に変換する。

---

## 7. Request Hash

`requestHash` は paid request と payment authorization を結びつける。

```text
requestHash = SHA-256(
  "A402-SVM-V1-REQ\n" ||
  METHOD || "\n" ||
  ORIGIN || "\n" ||
  PATH_AND_QUERY || "\n" ||
  BODY_SHA256_HEX || "\n" ||
  PAYMENT_DETAILS_HASH_HEX || "\n"
)
```

規則:

- `METHOD` は大文字 HTTP method
- `ORIGIN` は `scheme://host[:port]`
- `PATH_AND_QUERY` は raw path + raw query
- `BODY_SHA256_HEX` は request body bytes の SHA-256
- body が空なら empty byte string の SHA-256 を使う

provider は `/verify` 時に受け取った request をこの規則で再計算し、facilitator へ渡す。

---

## 8. Facilitator API

base URL は `facilitatorUrl` とし、以下を提供する。

### 8.0 Vault Status Semantics

facilitator は on-chain の vault status と整合するように振る舞う。

- `Active`: `/verify`, `/settle`, `/cancel` を許可
- `Paused`: `/verify`, `/settle`, `/cancel` を `503 vault_paused` で拒否
- `Migrating`: 新規 `/verify` を `503 vault_migrating` で拒否し、既存 reservation に対する `/settle` と `/cancel` だけ `exit_deadline` まで許可
- `Retired`: `/verify`, `/settle`, `/cancel` を拒否

provider は `503 vault_paused` / `503 vault_migrating` を受けた場合、resource handler を継続してはならない。

### 8.1 `GET /v1/attestation`

用途:

- client が Nitro Attestation を検証する
- provider が facilitator の runtime policy を監査する

response:

```json
{
  "vaultConfig": "9oX9G2xD...",
  "vaultSigner": "6MS8C3c4...",
  "attestationPolicyHash": "1a6c2f1f4f8f2a0f7a0e8d5b5a1a6d2d53b49939f4c7d9626abfce2033d5d2fe",
  "attestationDocument": "base64(...)",
  "issuedAt": "2026-04-12T00:00:00Z",
  "expiresAt": "2026-04-12T00:10:00Z"
}
```

### 8.2 `POST /v1/verify`

認証:

- `Authorization: Bearer <provider-api-key>` または mTLS
- bearer mode では `X-A402-Provider-Id` が必須

request:

```json
{
  "paymentPayload": { "...": "..." },
  "paymentDetails": { "...": "..." },
  "requestContext": {
    "method": "POST",
    "origin": "https://x402.alchemy.example",
    "pathAndQuery": "/solana-mainnet/v2",
    "bodySha256": "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a"
  }
}
```

response:

```json
{
  "ok": true,
  "verificationId": "ver_01JQ8VQ6M1MS4KTW46ZF4GJKF3",
  "reservationId": "res_01JQ8VQ6P4MYCNZJ5J8CMWQ66E",
  "reservationExpiresAt": "2026-04-12T00:01:00Z",
  "providerId": "prov_01JQ8V8T3V9Q8T8M8G9K0J4W7A",
  "amount": "1000000",
  "verificationReceipt": "base64(enclave-signed-verification-receipt)"
}
```

`/verify` で facilitator が必ず行う検証:

1. provider 認証が registration と一致する
2. `paymentDetails.scheme == "a402-svm-v1"`
3. `paymentDetails.verifyWindowSec` が正の整数である
4. `paymentDetailsHash` が一致する
5. `requestHash` が `requestContext` から再計算した値と一致する
6. `clientSig` が有効
7. `expiresAt` が未来
8. `providerId`, `payTo`, `assetMint`, `network`, `vault` が registration / vault config と一致する
9. client の `free_balance >= amount`
10. `paymentId` が未使用、または同一 request への idempotent replay である
11. vault status が `Active` である

`/verify` 成功時の副作用:

- `free_balance -= amount`
- `locked_balance += amount`
- `reservationExpiresAt = verified_at + verifyWindowSec`
- reservation state を `RESERVED` にする
- encrypted WAL に `ReservationCreated` を追記し、durable にしてから response を返す

### 8.3 `POST /v1/settle`

認証:

- `/verify` と同じ

request:

```json
{
  "verificationId": "ver_01JQ8VQ6M1MS4KTW46ZF4GJKF3",
  "resultHash": "a9cd98f7b4c3c59e4d5f6f0d215b0bb7f08933f5d6b8e0c5f9893f6ce6d033bd",
  "statusCode": 200
}
```

response:

```json
{
  "ok": true,
  "settlementId": "set_01JQ8VV2SEQQFG28M0WSTC3Q59",
  "offchainSettledAt": "2026-04-12T00:00:22Z",
  "providerCreditAmount": "1000000",
  "batchId": null,
  "participantReceipt": "base64(enclave-signed-provider-participant-receipt)"
}
```

`/settle` 成功時の副作用:

- reservation state を `SETTLED_OFFCHAIN` にする
- `locked_balance -= amount`
- provider credit ledger に `amount` を加算する
- provider 向け `ParticipantReceipt` を発行する
- encrypted WAL に `SettlementCommitted` を追記し、durable にしてから response を返す

`/settle` は reservation がまだ `RESERVED` であり、かつ `now <= reservationExpiresAt` の場合にのみ成功しなければならない。`verifyWindowSec` を過ぎた reservation は background sweeper を待たず、その request 自身で即座に `EXPIRED` に遷移し、locked balance を client free balance へ戻してから `reservation_expired` を返す。

### 8.4 Provider Single-Execution Rule

provider は `verificationId` を**一度だけ実行可能な capability**として扱わなければならない。

provider 側 middleware / server state の推奨状態:

- `VERIFIED_UNSERVED`
- `EXECUTING`
- `SERVED_SUCCESS`
- `SERVED_ERROR`

規則:

1. 同じ `verificationId` に対して handler を起動できるのは 1 回だけ
2. duplicate request が `EXECUTING` 中に来たら `409 duplicate_execution_in_flight` を返すか、同じ in-flight result を待ち合わせる
3. duplicate request が `SERVED_SUCCESS` / `SERVED_ERROR` に来たら、元の HTTP status / body / `PAYMENT-RESPONSE` をそのまま返す
4. clustered deployment では execution cache を共有ストアに置くか、`verificationId` で sticky routing しなければならない

この規則により、同じ signed authorization を複数回 replay しても resource handler は多重実行されない。

### 8.5 `POST /v1/cancel`

用途:

- provider が service 実行前に reservation を明示的に解放する

認証:

- `/verify` と同じ（`Authorization: Bearer <provider-api-key>` または mTLS）
- facilitator は `/verify` response 時に `verificationId` と `providerId` を紐づけて記録する
- `/cancel` request の認証から取得した `providerId` が、当該 `verificationId` の発行先と一致しない場合は `403 provider_mismatch` を返す
- 第三者による reservation の不正キャンセルを防止する

request:

```json
{
  "verificationId": "ver_01JQ8VQ6M1MS4KTW46ZF4GJKF3",
  "reason": "upstream_unavailable"
}
```

response:

```json
{
  "ok": true,
  "cancelledAt": "2026-04-12T00:00:05Z"
}
```

### 8.6 PAYMENT-RESPONSE Schema

provider は response header `PAYMENT-RESPONSE` に少なくとも次を入れる。

```json
{
  "scheme": "a402-svm-v1",
  "paymentId": "pay_01JQ8VKGW2P4M0C31Q1QKQQR4M",
  "verificationId": "ver_01JQ8VQ6M1MS4KTW46ZF4GJKF3",
  "settlementId": "set_01JQ8VV2SEQQFG28M0WSTC3Q59",
  "batchId": null,
  "txSignature": null,
  "participantReceipt": "base64(enclave-signed-provider-participant-receipt)"
}
```

意味:

- `batchId == null` かつ `txSignature == null`: off-chain settled 済み、まだ on-chain batch 前
- batch 完了後に provider が照会する場合、`batchId` と `txSignature` を取得できる
- `participantReceipt` は provider force-settle の根拠になる

---

## 9. State Machine and Idempotency

`paymentId` ごとの状態:

- `UNSEEN`
- `RESERVED`
- `CANCELLED`
- `EXPIRED`
- `SETTLED_OFFCHAIN`
- `BATCHED_ONCHAIN`

遷移:

```text
UNSEEN --verify--> RESERVED
RESERVED --cancel--> CANCELLED
RESERVED --timeout--> EXPIRED
RESERVED --settle--> SETTLED_OFFCHAIN
SETTLED_OFFCHAIN --batch confirmed--> BATCHED_ONCHAIN
```

idempotency rules:

- 同じ `paymentId` + 同じ `requestHash` + 同じ `paymentDetailsHash` での `/verify` 再試行は、同じ `verificationId` を返す
- 同じ `paymentId` で request binding が異なる場合は `409 payment_id_reused`
- `SETTLED_OFFCHAIN` に対する `/settle` 再試行は、同じ `settlementId` を返す
- `CANCELLED` / `EXPIRED` 済み payment への `/settle` は拒否する

provider 側 execution cache rules:

- 同じ `verificationId` の duplicate request は新しい execute を起こしてはならない
- provider が clustered deployment の場合、execution cache は共有ストアまたは sticky routing で一貫させなければならない

---

## 10. Batch Settlement

facilitator は provider ごとの off-chain credit を持ち、on-chain では `settle_vault` でまとめて払う。

### 10.1 Batch Trigger

Phase 1 推奨値:

- `BATCH_WINDOW_SEC = 120`
- `MAX_SETTLEMENT_DELAY_SEC = 900`
- `MAX_SETTLEMENTS_PER_TX = 20`
- `JITTER_SEC = 0..30`

batch は以下のいずれかで発火する:

1. batch window 経過
2. pending provider count が `MAX_SETTLEMENTS_PER_TX` に達した
3. oldest provider credit が `MAX_SETTLEMENT_DELAY_SEC` に達した

### 10.2 Privacy Rules

- 単一 request ごとに on-chain settle してはならない
- 可能な限り複数 provider を同一 batch に混ぜる
- pending credit の選択は provider 間で round-robin に行い、1 provider の連続採用で batch が単独化しないようにする
- facilitator SHOULD defer automatic batch inclusion for provider credits smaller than a configured payout floor (Phase 1 推奨: `AUTO_BATCH_MIN_PROVIDER_PAYOUT = 1_000_000` atomic units = 1 USDC) and wait for aggregation, unless `MAX_SETTLEMENT_DELAY_SEC` has been reached
- batch submit 時刻には jitter を入れる
- provider には `/settle` 成功時点で off-chain receipt を返し、on-chain 着金より前に credit を確定させる
- `MIN_BATCH_PROVIDERS = 2`（Phase 1 推奨値）: batch 内の provider 数がこの値未満の場合、`MAX_SETTLEMENT_DELAY_SEC` まで待機して他の provider の credit と合流させる。`MAX_SETTLEMENT_DELAY_SEC` に達しても `MIN_BATCH_PROVIDERS` 未満なら provider 1件でも settlement する（資金遅延回避を優先）。この場合でも settle_vault tx は Vault→Provider の送金のみで client 情報は含まれないため、linkability は「この期間にこの provider を使った誰かがいる」レベルに留まる

### 10.3 Batch Receipts

batch confirm 後、facilitator は `settlementId -> batchId -> txSignature` を記録し、後続の監査と dispute に使う。

---

## 11. Failure Semantics

- participant receipt の意味論:
  - client receipt は `freeBalance`, `lockedBalance`, `maxLockExpiresAt` を持つ
  - provider receipt は `lockedBalance = 0`, `maxLockExpiresAt = 0` を持つ

- `/verify` 成功後に provider が落ちた場合:
  - reservation は `verifyWindowSec` 経過で `EXPIRED`
  - locked balance は client free balance に戻る

- `/settle` 成功後に provider への HTTP response が失われた場合:
  - provider は同じ `verificationId` で `/settle` を再試行する
  - facilitator は同じ `settlementId` を返す

- enclave crash 後の再起動:
  - encrypted snapshot + WAL から recovery する
  - 未batchの provider credit は provider receipt で force-settle 可能
  - client は participant receipt を使い、`freeBalance` を dispute window 後に回収できる
  - 最新 receipt に `lockedBalance > 0` が残っている場合、その portion は `maxLockExpiresAt` 経過後に同じ force-settle request から回収できる
  - stale receipt challenge のため、ReceiptWatchtower は最新 receipt を保持していなければならない

- on-chain batch 提出時に paired audit chunk が失敗した場合:
  - Solana transaction 全体が rollback される
  - provider credit は `SETTLED_OFFCHAIN` のまま残り、後続 batch window で再送する

---

## 12. Security Invariants

- on-chain observer は `client -> provider` の直接対応を見られない
- parent instance は payment payload, request body, secret key, vault balances を読めない
- provider は facilitator verify を経ずに credit を得られない
- 同じ `paymentId` を別 request に流用できない
- facilitator は durable WAL へ書く前に verify / settle success を返してはならない
- audit mode が有効なとき、on-chain settlement chunk は matching audit chunk と同一 transaction に入らなければならない
- vault unavailability 時も participant receipt により client / provider の残高は回収可能でなければならない
- client の locked portion は、その receipt に束縛された `maxLockExpiresAt` 経過後に回収可能でなければならない
- participant receipt による回収可能性は、少なくとも1つの honest available ReceiptWatchtower が存在し、かつ vault が solvent である前提で成り立つ
- Phase 3 ASC では provider が `/channel/deliver` で提示する `providerPubkey` は registration の `participantPubkey` と一致しなければならず、`participantPubkey` 未登録の provider は `/channel/open` を開始できない

---

## 13. Open Items

- provider auth を `bearer` と `mtls` のどちらで標準化するか
- `requestHash` に signed offers / payment identifier extension を必須化するか
- Phase 3 で `verificationId` と ASC `rid` をどう対応付けるか
