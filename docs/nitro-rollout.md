# Nitro Rollout Status

2026-04-16 時点の Nitro 対応状況です。

今回入れたもの:

- `parent` の `ingress_relay`, `kms_proxy`, `snapshot_store` が `A402_PARENT_INTERCONNECT_MODE=tcp|vsock` で切り替え可能
- `enclave` の ingress listener, KMS proxy client, snapshot store client が `A402_ENCLAVE_INTERCONNECT_MODE=tcp|vsock` で切り替え可能
- `infra/nitro` に Terraform / env / systemd の雛形を追加

まだ未完了のもの:

- enclave から外へ出る Solana RPC / WebSocket / `reqwest` が egress relay 未使用
- `watchtower` への HTTP も egress relay 未使用
- EIF build / PCR 計測 / KMS attestation policy 固定の自動化

つまり今の repo は、Nitro 化の入口までは入ったが、まだ公開運用 ready ではありません。

次の実装順:

1. outbound connector を作る
2. `deposit_detector`, `batch`, `handlers`, `ensure_watchtower_ready` をその connector に寄せる
3. EIF build と PCR 出力を `scripts/` か CI に入れる
4. KMS key policy を実測 PCR に固定する
