# A402 Architecture

## How It Works

```mermaid
graph LR
    subgraph agents["AI Agents"]
        A["🤖"]
    end

    subgraph subly["A402 Protocol"]
        direction TB
        VAULT["💰 Yield Vault\nDeposit + Earn"]
        PRIV["🔒 Privacy Layer\nBatch + Anonymize"]
        VAULT --> PRIV
    end

    subgraph providers["Service Providers"]
        P["🌐 APIs"]
    end

    A -- "Deposit\nUSDC" --> VAULT
    A -- "Pay privately\nx402" --> PRIV
    PRIV -- "Aggregate\nsettlement" --> P

    style agents fill:#f9e79f,stroke:#f1c40f,stroke-width:2px,color:#000
    style subly fill:#e8d5f5,stroke:#9b59b6,stroke-width:2px,color:#000
    style providers fill:#d5f5e3,stroke:#27ae60,stroke-width:2px,color:#000
```

## Privacy: What's Visible vs Hidden

```mermaid
graph TB
    subgraph onchain["What the blockchain sees"]
        O1["Vault total: $100K"]
        O2["Provider A received: $1,500"]
        O3["Provider B received: $800"]
    end

    subgraph hidden["What stays private"]
        H1["Which agent paid which provider ❌"]
        H2["Individual payment amounts ❌"]
        H3["Payment frequency and timing ❌"]
        H4["Agent balances and yield ❌"]
    end

    style onchain fill:#d5f5e3,stroke:#27ae60,stroke-width:2px,color:#000
    style hidden fill:#fadbd8,stroke:#e74c3c,stroke-width:2px,color:#000
```

## The PayFi Loop

```mermaid
graph TB
    D["1. Deposit"] --> Y["2. Earn Yield"]
    Y --> P["3. Pay with Yield"]
    P --> S["4. Private Settlement"]
    S --> D

    style D fill:#d5e8f5,stroke:#3498db,stroke-width:2px,color:#000
    style Y fill:#fdebd0,stroke:#f39c12,stroke-width:2px,color:#000
    style P fill:#e8d5f5,stroke:#9b59b6,stroke-width:2px,color:#000
    style S fill:#d5f5e3,stroke:#27ae60,stroke-width:2px,color:#000
```

## x402 Payment Flow

```mermaid
sequenceDiagram
    participant Agent as AI Agent
    participant A402 as A402
    participant API as API Service

    Agent->>API: Request data
    API-->>Agent: 402 Payment Required
    Agent->>A402: Pay from Yield Vault
    A402->>API: Forward request privately
    API-->>A402: Response
    A402-->>Agent: Data delivered
    Note over A402: Payments batched and settled\nonly as provider aggregates
```

## Tech Stack

```mermaid
graph TB
    subgraph privacy["Privacy"]
        MPC["Arcium MPC\nEncrypted balances"]
        TEE["Nitro Enclave\nPrivate payments"]
    end

    subgraph protocol["Protocol"]
        X402["x402 Standard\nHTTP-native payments"]
        VAULT["Solana Vault\nEscrow + Settlement"]
    end

    subgraph defi["DeFi"]
        YIELD["Yield Strategies\nLST + Lending"]
    end

    MPC -- "authorize" --> TEE
    TEE -- "batch settle" --> VAULT
    VAULT -- "pool deploy" --> YIELD
    YIELD -- "yield" --> MPC
    X402 -.- TEE

    style privacy fill:#e8d5f5,stroke:#9b59b6,stroke-width:2px,color:#000
    style protocol fill:#d5e8f5,stroke:#3498db,stroke-width:2px,color:#000
    style defi fill:#fdebd0,stroke:#f39c12,stroke-width:2px,color:#000
```
