# Nitro Rollout

このディレクトリは、A402 を AWS Nitro Enclaves 上で公開 Devnet 配備するための雛形です。

最短手順は [`docs/nitro-devnet-deploy.md`](../../docs/nitro-devnet-deploy.md) を参照してください。

入っているもの:

- `terraform/`: parent EC2 / NLB / IAM / KMS / snapshot bucket の骨格
- `env/`: `parent` と `watchtower` の env テンプレート
- `systemd/`: parent / watchtower 常駐化ユニット
- `enclave/`: EIF build 用 Dockerfile と entrypoint

追加した automation:

- `yarn nitro:prepare`: vault signer ciphertext と runtime env を生成
- `yarn nitro:build-eif`: EIF build と measurements 出力
- `yarn nitro:provision`: PCR から policy hash を確定して on-chain initialize

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
- enclave の outbound HTTP / HTTPS / Solana RPC は `parent egress_relay` 経由で出る
- bootstrap 用の Nitro attestation document は enclave 内で NSM から生成し、KMS decrypt / data key 取得に使う
- `deposit_detector` は `logsSubscribe(finalized)` で vault token account を監視し、切断時は catch-up する
- 本番では `A402_EGRESS_ALLOWLIST` を設定して parent relay の接続先を絞る

公開 URL を生かすまでの残タスク:

1. `A402_EGRESS_ALLOWLIST` と AWS 側 egress 制御を本番値で固定する
2. EIF build と PCR 計測を CI か build script に乗せる
3. KMS key policy を実 PCR に束縛する
