# Nitro Rollout

このディレクトリは、A402 を AWS Nitro Enclaves 上で公開 Devnet 配備するための雛形です。

入っているもの:

- `terraform/`: parent EC2 / NLB / IAM / KMS / snapshot bucket の骨格
- `env/`: `parent` と `watchtower` の env テンプレート
- `systemd/`: parent / watchtower 常駐化ユニット

前提:

- Solana program はすでに Devnet に deploy 済み
- `a402-parent`, `a402-watchtower`, `a402-enclave` を build できる
- enclave 用 EIF は別途 build する
- AWS 側の VPC / subnet / AMI は自分の環境に合わせて入れる

手順:

1. `infra/nitro/terraform` に `terraform.tfvars` を作る
2. `terraform init && terraform apply` で EC2 / NLB / KMS / S3 を作る
3. 生成された parent EC2 に `a402-parent`, `a402-watchtower`, EIF を配置する
4. `env/*.example` を `/etc/a402/*.env` にコピーして値を埋める
5. `systemd/*.service` を `/etc/systemd/system/` に配置して `systemctl enable --now` する
6. EIF を Nitro で起動し、`A402_PARENT_INTERCONNECT_MODE=vsock` / `A402_ENCLAVE_INTERCONNECT_MODE=vsock` で接続する

重要:

- この turn で `ingress`, `KMS`, `snapshot_store` は `tcp(dev)` / `vsock(prod)` 両対応にした
- まだ `deposit_detector`, `batch`, `handlers`, `ensure_watchtower_ready` は enclave 内から Solana RPC / HTTP へ直接出る
- つまり、Nitro 本番で完全に動かすには outbound egress を `parent egress_relay` 経由に差し替える追加実装がまだ必要

公開 URL を生かすまでの残タスク:

1. enclave の outbound HTTP / WebSocket / Solana RPC を egress relay 経由の connector に置き換える
2. EIF build と PCR 計測を CI か build script に乗せる
3. KMS key policy を実 PCR に束縛する
4. watchtower への疎通を Nitro egress 経由に寄せる
