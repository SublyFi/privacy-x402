# Architecture Diagrams

## 1. System Overview

```mermaid
graph TB
    subgraph Clients["AI Agents"]
        A1["Agent A"]
        A2["Agent B"]
        A3["Agent C"]
    end

    subgraph Arcium["Arcium MPC Network"]
        direction TB
        YV["Encrypted Yield Vault\nbalance / yield: encrypted"]
        AUTH["Budget Authorizer\nauthorize_budget()"]
        YV --- AUTH
    end

    subgraph TEE["AWS Nitro Enclave"]
        direction TB
        FAC["x402 Privacy Facilitator\n/verify /settle /cancel"]
        BATCH["Batch Engine\n120s window, max 20 settlements"]
        FAC --- BATCH
    end

    subgraph DeFi["DeFi Protocols"]
        LEND["Lending\nKamino / MarginFi"]
        LST["Liquid Staking\nMarinade / Jito"]
    end

    subgraph Solana["Solana On-Chain"]
        VAULT["A402 Vault Program\nEscrow + Batch Settlement"]
        AUDIT["Audit Records\nElGamal encrypted"]
        FS["Force Settle\nDispute Resolution"]
    end

    subgraph Providers["Service Providers"]
        P1["API Provider A"]
        P2["API Provider B"]
    end

    WT["Receipt Watchtower"]

    A1 -- "1. Deposit USDC" --> VAULT
    A2 -- "1. Deposit USDC" --> VAULT
    A3 -- "1. Deposit USDC" --> VAULT
    VAULT -- "2. Balance update" --> YV
    YV -- "3. Pool funds" --> LEND
    YV -- "3. Pool funds" --> LST
    LEND -- "Yield" --> YV
    LST -- "Yield" --> YV
    A1 -- "4. Request budget" --> AUTH
    A2 -- "4. Request budget" --> AUTH
    A3 -- "4. Request budget" --> AUTH
    AUTH -- "5. Authorization token" --> FAC
    A1 -- "6. x402 API call" --> FAC
    A2 -- "6. x402 API call" --> FAC
    A3 -- "6. x402 API call" --> FAC
    FAC -- "7. Forward request" --> P1
    FAC -- "7. Forward request" --> P2
    BATCH -- "8. Batch settle\nProvider totals only" --> VAULT
    VAULT --- AUDIT
    VAULT --- FS
    FAC -. "Replicate receipts" .-> WT
    WT -. "Challenge stale receipts" .-> FS

    style Arcium fill:#e8d5f5,stroke:#9b59b6,stroke-width:2px
    style TEE fill:#d5e8f5,stroke:#3498db,stroke-width:2px
    style Solana fill:#d5f5e3,stroke:#27ae60,stroke-width:2px
    style DeFi fill:#fdebd0,stroke:#f39c12,stroke-width:2px
    style Clients fill:#f9e79f,stroke:#f1c40f,stroke-width:2px
    style Providers fill:#fadbd8,stroke:#e74c3c,stroke-width:2px
```

## 2. Payment Flow

```mermaid
sequenceDiagram
    participant Agent as AI Agent
    participant Arcium as Arcium MPC
    participant TEE as Nitro Enclave
    participant Provider as API Provider
    participant Chain as Solana

    Note over Agent,Chain: Deposit and Yield
    Agent->>Chain: Deposit USDC to Vault
    Chain-->>Arcium: Balance update encrypted
    Arcium->>Arcium: Pool funds to DeFi
    Arcium->>Arcium: accrue_yield in MPC

    Note over Agent,Chain: Budget Authorization
    Agent->>Arcium: authorize_budget $50
    Arcium->>Arcium: Verify encrypted balance >= $50
    Arcium->>Arcium: Lock $50 in encrypted state
    Arcium-->>TEE: Authorization token

    Note over Agent,Chain: Private x402 Payments
    Agent->>Provider: GET /api/data
    Provider-->>Agent: 402 Payment Required $0.01
    Agent->>TEE: Payment signature + request
    TEE->>TEE: Verify balance, lock $0.01
    TEE->>Provider: Forward request
    Provider-->>TEE: Response + receipt
    TEE-->>Agent: Response data

    Note over Agent,Chain: Batch Settlement
    TEE->>TEE: Collect 120s of payments
    TEE->>Chain: settle_vault Provider A $1.50 Provider B $0.80
    Note right of Chain: Only aggregate amounts visible
    TEE->>Chain: record_audit ElGamal encrypted
```

## 3. Privacy Boundaries

```mermaid
graph LR
    subgraph visible["On-Chain -- Public"]
        V1["Vault TVL: $100K"]
        V2["Batch: Provider A = $1,500"]
        V3["Batch: Provider B = $800"]
        V4["Audit: ElGamal ciphertext"]
    end

    subgraph arcium_hidden["Arcium MPC -- Hidden from everyone"]
        H1["Agent A balance: $5,000"]
        H2["Agent B balance: $3,200"]
        H3["Agent A yield: $45.20"]
        H4["Yield strategy allocation"]
    end

    subgraph tee_hidden["TEE -- Hidden from on-chain"]
        T1["Agent A paid Provider A: $0.50"]
        T2["Agent B paid Provider A: $1.00"]
        T3["Agent A paid Provider B: $0.80"]
        T4["Payment frequency patterns"]
    end

    style visible fill:#d5f5e3,stroke:#27ae60,stroke-width:2px
    style arcium_hidden fill:#e8d5f5,stroke:#9b59b6,stroke-width:2px
    style tee_hidden fill:#d5e8f5,stroke:#3498db,stroke-width:2px
```

## 4. Trust Model Comparison

```mermaid
graph TD
    subgraph current["Current: TEE + Arcium"]
        direction LR
        C_TEE["TEE Nitro\nTrust: AWS HW"]
        C_ARC["Arcium MPC\nTrust: N-of-M nodes"]
        C_ON["On-Chain\nTrust: Math"]
        C_ARC -- "authorization" --> C_TEE
        C_TEE -- "batch totals" --> C_ON
    end

    subgraph future["Future: ZK + Arcium"]
        direction LR
        F_ZK["ZK Facilitator\nTrust: Math only"]
        F_ARC2["Arcium MPC\nTrust: N-of-M nodes"]
        F_ON2["On-Chain\nTrust: Math"]
        F_ARC2 -- "authorization" --> F_ZK
        F_ZK -- "ZK proof" --> F_ON2
    end

    current -- "Migration path\nwhen CT available" --> future

    style current fill:#d5e8f5,stroke:#3498db,stroke-width:2px
    style future fill:#d5f5e3,stroke:#27ae60,stroke-width:2px
```

## 5. Arcium Yield Vault Detail

```mermaid
graph TB
    subgraph vault["Arcium Encrypted Vault"]
        direction TB
        DEP["deposit\nShared encrypted input"]
        YIELD["accrue_yield\nMxe encrypted state"]
        AUTHZ["authorize_budget\nverify + lock, reveal bool"]
        RECON["reconcile\nTEE consumed update"]
        BAL["reveal_balance\nowner-only decryption"]

        DEP --> YIELD --> AUTHZ --> RECON
        BAL -.-> DEP
    end

    AGENT["AI Agent"] -- "encrypt amount" --> DEP
    AGENT -- "encrypt budget" --> AUTHZ
    DEFI["DeFi Yield"] -- "encrypted yield" --> YIELD
    AUTHZ -- "approved: bool" --> FACIL["TEE Facilitator"]
    FACIL -- "consumed amounts" --> RECON
    AGENT -- "decrypt own balance" --> BAL

    style vault fill:#e8d5f5,stroke:#9b59b6,stroke-width:2px
```
