# A402 / Privacy First x402 on Solana

このリポジトリは、Solana Devnet 上で `Privacy First x402` を AWS Nitro Enclaves 前提で公開するための実装です。

一番大事な前提:

- `TEE は必須`
- `TLS は enclave 内で終端`
- `parent instance / NLB / nginx / ALB で平文を見せない`

この README は次の 2 つを目的にしています。

1. 手元準備は、できるだけコマンドをそのまま実行するだけで進める
2. AWS 側は、どの画面で何を設定するかまで丁寧に整理する

## 構成概要

公開構成は次です。

```text
Internet
  -> NLB TCP/443
  -> parent EC2 (Nitro Enclaves enabled)
  -> ingress_relay
  -> vsock
  -> a402-enclave

parent EC2
  - a402-parent
  - a402-watchtower
  - nitro-cli
  - encrypted snapshot/WAL storage
```

役割:

- `programs/a402_vault`: Devnet に deploy する Solana program
- `enclave`: Nitro enclave 内で動く facilitator
- `parent`: parent instance 上の relay / KMS proxy / snapshot store
- `watchtower`: stale receipt challenge 用常駐プロセス

## 最短ルート

最短で公開 Devnet まで持っていく流れは次です。

1. AWS で Region / VPC / KMS key を先に決める
2. ローカルで `.env.devnet.local` を埋める
3. Solana program を Devnet に deploy
4. Nitro 用 runtime env を生成
5. EIF を build して測定値を取得
6. 測定値から `attestation_policy_hash` を確定し、on-chain vault を initialize
7. Terraform で parent EC2 / NLB / S3 を作り、同じ KMS key に attestation 条件付き policy を入れる
8. parent EC2 に binary / env / EIF を配置して起動
9. `https://<NLB>/v1/attestation` を確認

## 前提ツール

ローカル作業マシンに必要:

- Node.js 18+
- Yarn 1.x
- Rust / Cargo
- Solana CLI
- Anchor CLI
- AWS CLI
- Docker
- Terraform
- `nitro-cli`

この repo で確認済みのローカル build:

- `anchor-cli 0.32.1`
- `solana-cli 3.1.12`
- `rustc 1.89.0`
- `node v24`

## 1. ローカル準備

### 1-0. 先に KMS key を 1 本だけ用意する

`yarn nitro:prepare` は vault signer seed をすぐ KMS ciphertext に変換します。
そのため、この時点で `A402_KMS_KEY_ARN` が必要です。

まだ KMS key を作っていない場合は、先に [2-4. KMS key を作る](#2-4-kms-key-を作る) を実施してください。

### 1-1. `.env.devnet.local` を作る

トップに `.env.devnet.local` を作り、最低限これを入れます。

```bash
export A402_SOLANA_RPC_URL='https://<your-devnet-rpc>'
export A402_SOLANA_WS_URL='wss://<your-devnet-ws>'
export ANCHOR_PROVIDER_URL="$A402_SOLANA_RPC_URL"
export ANCHOR_WALLET="$HOME/.config/solana/<wallet>.json"

export AWS_REGION='us-east-1'
export A402_KMS_KEY_ARN='arn:aws:kms:us-east-1:123456789012:key/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
export A402_KMS_KEY_ID="$A402_KMS_KEY_ARN"
export A402_SNAPSHOT_DATA_KEY_ID="$A402_KMS_KEY_ARN"

export A402_EIF_SIGNING_CERT_PATH="$PWD/infra/nitro/certs/eif-signing-cert.pem"
export A402_NITRO_SIGNING_PRIVATE_KEY="$PWD/infra/nitro/certs/eif-signing-key.pem"
```

必要になったら後で足すもの:

- `A402_PUBLIC_ENCLAVE_URL`
- `A402_KMS_PROVISIONER_PRINCIPAL_ARN`
- `A402_ENCLAVE_TLS_CA_SOURCE`

補足:

- `A402_KMS_KEY_ARN` は Nitro runtime で実際に使う KMS key です
- 後の Terraform でも同じ key を `existing_runtime_kms_key_arn` として渡します
- 別の KMS key を作る必要はありません

### 1-2. Solana CLI の接続先を揃える

```bash
source ./.env.devnet.local
solana config set \
  --url "$A402_SOLANA_RPC_URL" \
  --ws "$A402_SOLANA_WS_URL" \
  --keypair "$ANCHOR_WALLET"
```

### 1-3. Program を build / deploy

```bash
NO_DNA=1 anchor build
NO_DNA=1 anchor deploy \
  --provider.cluster "$A402_SOLANA_RPC_URL" \
  --provider.wallet "$ANCHOR_WALLET"
```

### 1-4. Nitro runtime 用の初期情報を生成

このコマンドで次をまとめて行います。

- vault signer seed を生成
- signer seed を KMS ciphertext に変換
- watchtower keypair を生成
- signer / watchtower に Devnet lamports を供給
- `parent.env`, `watchtower.env`, `enclave.env`, `run-enclave.json` を生成

```bash
yarn nitro:prepare
```

生成されるファイル:

- `infra/nitro/generated/nitro-plan.json`
- `infra/nitro/generated/parent.env`
- `infra/nitro/generated/watchtower.env`
- `infra/nitro/generated/enclave.env`
- `infra/nitro/generated/run-enclave.json`

### 1-5. Enclave 内で使う TLS 証明書の source path を指定

Devnet で agent client 中心なら self-signed でも構いません。
この実装は `/v1/attestation` の `tlsPublicKeySha256` まで client 側で検証できます。

```bash
export A402_ENCLAVE_TLS_CERT_SOURCE="$PWD/infra/nitro/certs/server.crt"
export A402_ENCLAVE_TLS_KEY_SOURCE="$PWD/infra/nitro/certs/server.key"
```

任意で mTLS を使う場合:

```bash
export A402_ENCLAVE_TLS_CA_SOURCE="$PWD/infra/nitro/certs/client-ca.crt"
```

### 1-6. EIF を build

```bash
yarn nitro:build-eif
```

生成されるファイル:

- `infra/nitro/generated/a402-enclave.eif`
- `infra/nitro/generated/eif-measurements.json`

### 1-7. PCR から policy hash を確定し、vault を initialize

```bash
yarn nitro:provision
```

この step で次を行います。

- EIF 実測値から `attestation_policy_hash` を算出
- parent EC2 用 IAM role ARN から `PCR3` を導出
- `initialize_vault` を必要なら実行
- `terraform.attestation.auto.tfvars.json` を生成
- client 用参照 env を生成

補足:

- `project_name` を Terraform default (`a402-devnet`) から変える場合は、`yarn nitro:prepare` と `yarn nitro:provision` の前に `A402_NITRO_PROJECT_NAME` を同じ値で設定する

生成されるファイル:

- `infra/nitro/generated/attestation-policy.json`
- `infra/nitro/generated/attestation-policy.hash`
- `infra/nitro/generated/nitro-state.json`
- `infra/nitro/generated/terraform.attestation.auto.tfvars.json`
- `infra/nitro/generated/client.env`

### 1-8. parent / watchtower の release binary を作る

EC2 へ持っていく binary は別で build します。

```bash
NO_DNA=1 cargo build --release -p a402-parent -p a402-watchtower
```

## 2. AWS 側の環境構築

ここはコマンドよりも、設定を間違えないことが大事です。

### 2-1. Region を決める

まず 1 つ Region を決めて固定します。

推奨:

- `us-east-1`

理由:

- Nitro / KMS / NLB / EC2 のドキュメント例が多い
- Devnet RPC を us-east 近辺に置きやすい

### 2-2. VPC / subnet を用意する

必要な構成:

- public subnet を 2 つ以上
- parent EC2 はそのうち 1 つに配置
- NLB は 2 つ以上の public subnet にまたがる

考え方:

- `NLB` は public
- `watchtower` は public にしない
- parent EC2 の inbound は `443` と必要なら `22` だけ

### 2-3. Security Group を決める

parent EC2 には次の考え方で設定します。

許可:

- `443/tcp` from `0.0.0.0/0`
- `22/tcp` from 自分の固定IPだけ

禁止:

- `3200/tcp` を public に開けない
- enclave 用の vsock port を public に出さない

egress:

- 一旦 `0.0.0.0/0` でもよい
- 後で厳密化するなら Solana RPC, AWS KMS/STS, provider domains に絞る

### 2-4. KMS key を作る

KMS key は 1 本で始めて構いません。

用途:

- vault signer seed の復号
- snapshot data key の生成

作成時に見るポイント:

- `Symmetric`
- `Encrypt and decrypt`
- key rotation を `ON`

AWS Console での推奨手順:

1. `KMS` を開く
2. `Customer managed keys` を開く
3. `Create key`
4. `Symmetric` を選ぶ
5. `Encrypt and decrypt` を選ぶ
6. key alias を決める
  例: `alias/a402-devnet-runtime`
7. key administrator は自分の admin role を選ぶ
8. key usage permissions は、まず自分の作業用 principal だけ入れて作成する
9. 作成後に key ARN をコピーする
10. その ARN を `.env.devnet.local` の `A402_KMS_KEY_ARN` に入れる

この repo の Terraform は、後でこの同じ KMS key に `attested enclave の PCR` 条件付き policy を適用できます。

### 2-5. EIF signing certificate を用意する

必要なのは `nitro-cli build-enclave` で EIF に署名するための証明書です。

最低限必要なもの:

- signing certificate
- private key

この証明書は TLS 証明書とは別物です。

区別:

- `EIF signing cert`: enclave image の署名用
- `TLS cert`: client/provider と enclave の HTTPS 用

### 2-6. parent EC2 を決める

推奨:

- Nitro Enclaves 対応 instance type
- Linux
- 最低でも `c6a.xlarge` か同等以上
- ルートボリュームは 30GB 以上

理由:

- enclave に CPU / memory を分割して渡すので、parent 側にも余裕が必要

Terraform で入れる値の考え方:

- `vpc_id`: 対象 VPC
- `nlb_subnet_ids`: public subnet を 2 つ以上
- `instance_subnet_id`: parent EC2 を置く subnet
- `ami_id`: Linux AMI
- `snapshot_bucket_name`: 一意な S3 bucket 名

### 2-7. NLB を使う

ここは重要です。

使うもの:

- `NLB`
- `TCP/443`

使わないもの:

- `ALB`
- parent nginx での TLS terminate
- ACM を parent で terminate する構成

理由:

- TLS の平文を parent に見せたくないため

### 2-8. Terraform apply

`yarn nitro:provision` 実行後にできる
`infra/nitro/generated/terraform.attestation.auto.tfvars.json`
を使います。

```bash
cd infra/nitro/terraform
terraform init
terraform apply \
  -var-file=../generated/terraform.attestation.auto.tfvars.json \
  -var="existing_runtime_kms_key_arn=$A402_KMS_KEY_ARN" \
  -var='aws_region=us-east-1' \
  -var='vpc_id=vpc-xxxxxxxx' \
  -var='nlb_subnet_ids=["subnet-aaaa","subnet-bbbb"]' \
  -var='instance_subnet_id=subnet-aaaa' \
  -var='ami_id=ami-xxxxxxxx' \
  -var='snapshot_bucket_name=a402-devnet-snapshots-xxxxxxxx'
```

必要なら追加するもの:

- `kms_provisioner_principal_arns`

これは `nitro:prepare` を実行する IAM principal を KMS で `Encrypt` できるようにしたい場合に使います。

`existing_runtime_kms_key_arn` を指定すると:

- `nitro:prepare` で使った同じ KMS key を Terraform でも使う
- Terraform は新しい runtime KMS key を作らない
- その key に対して attestation-aware policy を反映する

## 3. Parent EC2 への配置

Terraform apply 後、parent EC2 に以下を配置します。

binary:

- `target/release/a402-parent`
- `target/release/a402-watchtower`

generated files:

- `infra/nitro/generated/a402-enclave.eif`
- `infra/nitro/generated/parent.env`
- `infra/nitro/generated/watchtower.env`
- `infra/nitro/generated/run-enclave.json`

helper scripts:

- `scripts/nitro/start-parent.sh`
- `scripts/nitro/start-watchtower.sh`
- `infra/nitro/systemd/a402-parent.service`
- `infra/nitro/systemd/a402-watchtower.service`

推奨配置:

- `/opt/a402/bin/a402-parent`
- `/opt/a402/bin/a402-watchtower`
- `/opt/a402/bin/start-parent.sh`
- `/opt/a402/bin/start-watchtower.sh`
- `/opt/a402/enclave/a402-enclave.eif`
- `/etc/a402/parent.env`
- `/etc/a402/watchtower.env`
- `/etc/a402/run-enclave.json`

補足:

- `enclave.env` は EIF build 時に image の中へ入る
- parent に `A402_VAULT_SIGNER_SECRET_KEY_B64` を置かない
- parent が持つのは ciphertext と relay 機能だけ

## 4. Parent EC2 上で必要なソフト

parent EC2 に必要:

- `nitro-cli`
- `a402-parent`
- `a402-watchtower`

必要に応じて:

- `jq`
- `curl`
- `systemd`

補足:

- Docker は `EIF を build するマシン` に必要です
- `EIF を run するだけの parent EC2` には通常不要です

## 5. 起動順序

起動順はこの順番です。

1. watchtower
2. parent
3. enclave

### 5-1. 推奨: systemd で起動

systemd unit はすでに repo に入っています。

```bash
sudo cp infra/nitro/systemd/a402-parent.service /etc/systemd/system/
sudo cp infra/nitro/systemd/a402-watchtower.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now a402-watchtower
sudo systemctl enable --now a402-parent
```

### 5-2. 直接起動する場合

raw binary を直接叩くのではなく、env を読む wrapper を使います。

```bash
bash /opt/a402/bin/start-watchtower.sh /etc/a402/watchtower.env
```

```bash
bash /opt/a402/bin/start-parent.sh /etc/a402/parent.env
```

### 5-3. enclave 起動

```bash
NO_DNA=1 nitro-cli run-enclave --config /etc/a402/run-enclave.json
```

repo 配下からなら:

```bash
yarn nitro:run /etc/a402/run-enclave.json
```

状態確認:

```bash
yarn nitro:describe
curl -sk https://<your-nlb-dns>/v1/attestation | jq .
```

## 6. 初回公開 smoke

初回だけ管理 API を使いたい場合は、EIF build 前の `enclave.env` に次を入れます。

```bash
export SUBLY402_ENABLE_PROVIDER_REGISTRATION_API='1'
export SUBLY402_ENABLE_ADMIN_API='1'
export SUBLY402_ADMIN_AUTH_TOKEN='<operator-only-random-token>'
```

その状態で:

1. `yarn nitro:build-eif`
2. `yarn nitro:provision`
3. parent へ再配置
4. enclave 再起動

smoke が終わったら、両方 `0` に戻して EIF を作り直してください。
`prepare` は enclave 側には `SUBLY402_ADMIN_AUTH_TOKEN_SHA256` だけを書き出します。
単一providerのsmokeで即時batchが必要な時だけ
`SUBLY402_ALLOW_ADMIN_PRIVACY_BYPASS_BATCH=1` を使い、公開runtimeでは `0` のままにします。

## 7. 日常的に使うコマンド

```bash
source ./.env.devnet.local
```

```bash
NO_DNA=1 anchor build
```

```bash
NO_DNA=1 anchor deploy \
  --provider.cluster "$A402_SOLANA_RPC_URL" \
  --provider.wallet "$ANCHOR_WALLET"
```

```bash
yarn nitro:prepare
```

```bash
yarn nitro:build-eif
```

```bash
yarn nitro:provision
```

```bash
yarn nitro:describe
```

```bash
yarn nitro:terminate
```

## 8. 生成ファイルの意味

`infra/nitro/generated/nitro-plan.json`

- Nitro 用の plan
- vault / signer / watchtower / KMS まわりの中間情報

`infra/nitro/generated/enclave.env`

- EIF build 時に enclave image へ入る runtime env

`infra/nitro/generated/run-enclave.json`

- `nitro-cli run-enclave --config ...` に渡す設定

`infra/nitro/generated/eif-measurements.json`

- EIF の PCR 実測値

`infra/nitro/generated/terraform.attestation.auto.tfvars.json`

- Terraform に渡す attestation 条件値

`infra/nitro/generated/client.env`

- client 側で参照する公開情報

## 9. よくある詰まりどころ

### `nitro:prepare` が KMS で失敗する

確認:

- `AWS_REGION`
- `A402_KMS_KEY_ARN`
- 実行 IAM principal に `kms:Encrypt` があるか

### `nitro:build-eif` が失敗する

確認:

- `A402_ENCLAVE_TLS_CERT_SOURCE`
- `A402_ENCLAVE_TLS_KEY_SOURCE`
- `A402_EIF_SIGNING_CERT_PATH`
- `A402_NITRO_SIGNING_PRIVATE_KEY`

### `nitro:provision` が失敗する

確認:

- `anchor deploy` 済みか
- `infra/nitro/generated/eif-measurements.json` があるか
- `ANCHOR_WALLET` が funded か

### `curl https://<nlb>/v1/attestation` が失敗する

確認:

- NLB が `TCP/443` か
- parent の `443` が開いているか
- parent / watchtower / enclave の起動順が正しいか
- `A402_WATCHTOWER_URL` が `127.0.0.1:3200` を向いているか

## 10. 参照ドキュメント

- 詳細な Nitro 手順: [docs/nitro-devnet-deploy.md](./docs/nitro-devnet-deploy.md)
- Nitro 雛形: [infra/nitro/README.md](./infra/nitro/README.md)
- ローカル Devnet 手順: [docs/devnet-setup.md](./docs/devnet-setup.md)
