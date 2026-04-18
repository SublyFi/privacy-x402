# Nitro Devnet Deployment

この手順は、`Privacy First x402` を AWS Nitro Enclaves 前提で Devnet 公開するための最短導線です。

前提:

- Solana program を Devnet に deploy できる
- AWS CLI / Terraform / Docker / Nitro CLI が使える
- Devnet RPC URL と funded deploy wallet がある
- EIF signing certificate を用意済み
- parent EC2 は Nitro Enclaves 対応インスタンスを使う

生成物は `infra/nitro/generated/` にまとまります。

## 0. 先に KMS key を作る

`yarn nitro:prepare` は vault signer seed を KMS ciphertext に変換するので、最初に KMS key ARN が必要です。

AWS Console で:

1. `KMS`
2. `Customer managed keys`
3. `Create key`
4. `Symmetric`
5. `Encrypt and decrypt`
6. alias を設定
7. key ARN をコピー

その ARN を `.env.devnet.local` の `A402_KMS_KEY_ARN` に入れます。

## 0. Local env

`.env.devnet.local` に最低限これを入れる:

```bash
export A402_SOLANA_RPC_URL='https://<your-devnet-rpc>'
export A402_SOLANA_WS_URL='wss://<your-devnet-ws>'
export ANCHOR_PROVIDER_URL="$A402_SOLANA_RPC_URL"
export ANCHOR_WALLET="$HOME/.config/solana/<wallet>.json"

export A402_KMS_KEY_ARN='arn:aws:kms:us-east-1:123456789012:key/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
export A402_KMS_KEY_ID="$A402_KMS_KEY_ARN"
export A402_SNAPSHOT_DATA_KEY_ID="$A402_KMS_KEY_ARN"
export A402_EIF_SIGNING_CERT_PATH="$PWD/infra/nitro/certs/eif-signing-cert.pem"
export A402_NITRO_SIGNING_PRIVATE_KEY="$PWD/infra/nitro/certs/eif-signing-key.pem"
export AWS_REGION='us-east-1'
```

TLS 証明書は EIF build 前に source path を指定する:

```bash
export A402_ENCLAVE_TLS_CERT_SOURCE="$PWD/infra/nitro/certs/server.crt"
export A402_ENCLAVE_TLS_KEY_SOURCE="$PWD/infra/nitro/certs/server.key"
```

## 1. Program deploy

```bash
source ./.env.devnet.local
NO_DNA=1 anchor build
NO_DNA=1 anchor deploy \
  --provider.cluster "$A402_SOLANA_RPC_URL" \
  --provider.wallet "$ANCHOR_WALLET"
```

## 2. Nitro prepare

この step で:

- planned `vaultConfig` / `vaultTokenAccount` を確定
- vault signer seed を生成して KMS ciphertext 化
- watchtower keypair を生成して funding
- `parent.env`, `watchtower.env`, `enclave.env`, `run-enclave.json` を生成

```bash
yarn nitro:prepare
```

出力:

- `infra/nitro/generated/nitro-plan.json`
- `infra/nitro/generated/parent.env`
- `infra/nitro/generated/watchtower.env`
- `infra/nitro/generated/enclave.env`
- `infra/nitro/generated/run-enclave.json`

## 3. Build signed EIF

```bash
yarn nitro:build-eif
```

出力:

- `infra/nitro/generated/a402-enclave.eif`
- `infra/nitro/generated/eif-measurements.json`

重要:

- Nitro では `attestation_policy_hash` を EIF の中に固定しない
- enclave runtime は実測 PCR と `A402_KMS_KEY_ARN_SHA256` / `A402_EIF_SIGNING_CERT_SHA256` から hash を導出する
- そのため EIF build 後に policy hash を確定しても循環依存にならない

## 4. On-chain initialize + policy materialize

EIF の実測値から policy hash を作り、`initialize_vault` に固定する。

```bash
yarn nitro:provision
```

出力:

- `infra/nitro/generated/attestation-policy.json`
- `infra/nitro/generated/attestation-policy.hash`
- `infra/nitro/generated/terraform.attestation.auto.tfvars.json`
- `infra/nitro/generated/nitro-state.json`
- `infra/nitro/generated/client.env`

## 4.5. parent / watchtower release binary も build する

```bash
NO_DNA=1 cargo build --release -p a402-parent -p a402-watchtower
```

## 5. Terraform apply

`infra/nitro/generated/terraform.attestation.auto.tfvars.json` を `infra/nitro/terraform/` にコピーするか、`-var-file` で渡す。

例:

```bash
cd infra/nitro/terraform
terraform init
terraform apply \
  -var-file=../generated/terraform.attestation.auto.tfvars.json \
  -var="existing_runtime_kms_key_arn=$A402_KMS_KEY_ARN" \
  -var='aws_region=us-east-1' \
  -var='vpc_id=vpc-xxxx' \
  -var='nlb_subnet_ids=["subnet-a","subnet-b"]' \
  -var='instance_subnet_id=subnet-a' \
  -var='ami_id=ami-xxxx' \
  -var='snapshot_bucket_name=a402-devnet-snapshots-xxxx'
```

`kms_provisioner_principal_arns` も必要ならこの tfvars に追加する。

重要:

- `existing_runtime_kms_key_arn` には `nitro:prepare` で使った同じ KMS key を渡す
- Terraform はその key に attestation-aware policy を適用する
- ここで別の KMS key を作らない

## 6. Parent instance setup

EC2 に以下を配置する:

- `target/release/a402-parent`
- `target/release/a402-watchtower`
- `infra/nitro/generated/a402-enclave.eif`
- `infra/nitro/generated/parent.env`
- `infra/nitro/generated/watchtower.env`
- `infra/nitro/generated/run-enclave.json`
- `scripts/nitro/start-parent.sh`
- `scripts/nitro/start-watchtower.sh`
- `infra/nitro/systemd/a402-parent.service`
- `infra/nitro/systemd/a402-watchtower.service`

推奨配置:

- `/opt/a402/bin/a402-parent`
- `/opt/a402/bin/a402-watchtower`
- `/opt/a402/bin/start-parent.sh`
- `/opt/a402/bin/start-watchtower.sh`
- `/opt/a402/bin/run-enclave.sh`
- `/opt/a402/enclave/a402-enclave.eif`
- `/etc/a402/parent.env`
- `/etc/a402/watchtower.env`
- `/etc/a402/run-enclave.json`

## 7. Start runtime

推奨は systemd:

```bash
sudo cp infra/nitro/systemd/a402-parent.service /etc/systemd/system/
sudo cp infra/nitro/systemd/a402-watchtower.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now a402-watchtower
sudo systemctl enable --now a402-parent
```

直接起動する場合は env を読む wrapper を使う。

watchtower:

```bash
bash /opt/a402/bin/start-watchtower.sh /etc/a402/watchtower.env
```

parent:

```bash
bash /opt/a402/bin/start-parent.sh /etc/a402/parent.env
```

enclave:

```bash
NO_DNA=1 nitro-cli run-enclave --config /etc/a402/run-enclave.json
```

repo から直接なら:

```bash
yarn nitro:run /etc/a402/run-enclave.json
```

状態確認:

```bash
yarn nitro:describe
curl -sk https://<nlb-dns>/v1/attestation | jq .
```

## 8. Public smoke

初回だけ:

- `A402_ENABLE_PROVIDER_REGISTRATION_API=1`
- `A402_ENABLE_ADMIN_API=1`

で EIF を作り直し、公開 smoke を通したら両方 `0` に戻して EIF を再buildする。

## Notes

- `watchtower` は public に出さない
- `ALB` や parent nginx で TLS terminate しない
- `A402_VAULT_SIGNER_SECRET_KEY_B64` を parent に置かない
- Nitro runtime では `A402_ATTESTATION_POLICY_HASH_HEX` を image に焼かず、runtime 測定値から導出する
