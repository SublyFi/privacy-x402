import type { Request, Response, NextFunction } from "express";
import { createHash } from "crypto";
import { address as solanaAddress } from "@solana/kit";
import {
  findAssociatedTokenPda,
  TOKEN_PROGRAM_ADDRESS,
} from "@solana-program/token";
import { subly402Middleware } from "./middleware";
import type {
  Subly402ProviderConfig,
  Subly402FacilitatorClientOptions,
  Subly402RouteAccept,
  Subly402RouteConfig,
  Subly402Routes,
} from "./types";

type AttestationSummary = {
  vaultConfig: string;
  vaultSigner: string;
  attestationPolicyHash: string;
};

const INTERNAL_WIRE_SCHEME = "subly402-svm-v1";
const DEFAULT_ASSET_DECIMALS = 6;
const DEFAULT_ASSET_SYMBOL = "USDC";

function normalizeBaseUrl(url: string): string {
  return url.replace(/\/$/, "");
}

function networkMatches(pattern: string, network: string): boolean {
  if (pattern === "*" || pattern === network) {
    return true;
  }
  if (pattern.endsWith(":*")) {
    return network.startsWith(pattern.slice(0, -1));
  }
  return false;
}

function deriveProviderId(
  network: string,
  assetMint: string,
  payTo: string
): string {
  const hash = createHash("sha256")
    .update("SUBLY402-OPEN-PROVIDER-V1\n")
    .update(network)
    .update("\n")
    .update(assetMint)
    .update("\n")
    .update(payTo)
    .update("\n")
    .digest("hex");
  return `payto_${hash.slice(0, 32)}`;
}

async function deriveAssociatedTokenAccount(
  owner: string,
  mint: string
): Promise<string> {
  const [ata] = await findAssociatedTokenPda({
    owner: solanaAddress(owner),
    tokenProgram: TOKEN_PROGRAM_ADDRESS,
    mint: solanaAddress(mint),
  });
  return ata;
}

async function resolvePayTo(
  accept: Subly402RouteAccept,
  assetMint: string
): Promise<string> {
  if (accept.payTo) {
    return accept.payTo;
  }
  if (accept.sellerWallet) {
    return await deriveAssociatedTokenAccount(accept.sellerWallet, assetMint);
  }
  throw new Error("Subly402 route requires sellerWallet or payTo");
}

function requestPath(req: Request): string {
  return (req.path || req.originalUrl.split("?")[0] || "/").replace(/\/$/, "");
}

function routePath(routeKey: string): { method: string; path: string } {
  const [method, ...rest] = routeKey.trim().split(/\s+/);
  if (!method || rest.length === 0) {
    throw new Error(`Invalid Subly402 route key: ${routeKey}`);
  }
  return {
    method: method.toUpperCase(),
    path: rest.join(" ").replace(/\/$/, ""),
  };
}

function findRoute(
  routes: Subly402Routes,
  req: Request
): Subly402RouteConfig | null {
  const method = req.method.toUpperCase();
  const path = requestPath(req);

  for (const [routeKey, route] of Object.entries(routes)) {
    const parsed = routePath(routeKey);
    if (parsed.method === method && parsed.path === path) {
      return route;
    }
  }
  return null;
}

function normalizePriceToAtomic(
  price: string | number,
  decimals: number
): string {
  if (typeof price === "number") {
    if (!Number.isFinite(price) || price < 0) {
      throw new Error("Subly402 price must be a non-negative number");
    }
    return Math.trunc(price).toString();
  }

  const trimmed = price.trim();
  if (/^\d+$/.test(trimmed)) {
    return trimmed;
  }

  const decimal = trimmed.startsWith("$") ? trimmed.slice(1) : trimmed;
  if (!/^\d+(\.\d+)?$/.test(decimal)) {
    throw new Error(
      `Unsupported Subly402 price ${price}; use "$0.001" or atomic units`
    );
  }

  const [whole, fraction = ""] = decimal.split(".");
  if (fraction.length > decimals) {
    throw new Error(
      `Subly402 price ${price} has more than ${decimals} decimal places`
    );
  }
  const atomic =
    BigInt(whole) * 10n ** BigInt(decimals) +
    BigInt((fraction + "0".repeat(decimals)).slice(0, decimals) || "0");
  return atomic.toString();
}

function selectAccept(route: Subly402RouteConfig): Subly402RouteAccept {
  const accept = route.accepts.find((candidate) => {
    return (
      candidate.scheme === undefined ||
      candidate.scheme === "exact" ||
      candidate.scheme === "subly402-exact" ||
      candidate.scheme === INTERNAL_WIRE_SCHEME
    );
  });
  if (!accept) {
    throw new Error("Subly402 route has no supported payment scheme");
  }
  return accept;
}

export class Subly402ExactScheme {
  readonly scheme = "exact";
  readonly wireScheme = INTERNAL_WIRE_SCHEME;
}

export class Subly402FacilitatorClient {
  readonly url: string;
  readonly providerApiKey?: string;
  readonly authMode?: Subly402ProviderConfig["authMode"];
  readonly mtls?: Subly402ProviderConfig["mtls"];
  readonly defaultAssetMint?: string;
  readonly defaultAssetDecimals: number;
  readonly defaultAssetSymbol: string;

  private attestation?: AttestationSummary;
  private attestationPromise?: Promise<AttestationSummary>;

  constructor(options: Subly402FacilitatorClientOptions) {
    this.url = normalizeBaseUrl(options.url);
    this.providerApiKey = options.providerApiKey;
    this.authMode = options.authMode;
    this.mtls = options.mtls;
    this.defaultAssetMint = options.assetMint;
    this.defaultAssetDecimals = options.assetDecimals ?? DEFAULT_ASSET_DECIMALS;
    this.defaultAssetSymbol = options.assetSymbol ?? DEFAULT_ASSET_SYMBOL;

    if (
      options.vaultConfig &&
      options.vaultSigner &&
      options.attestationPolicyHash
    ) {
      this.attestation = {
        vaultConfig: options.vaultConfig,
        vaultSigner: options.vaultSigner,
        attestationPolicyHash: options.attestationPolicyHash,
      };
    }
  }

  async getAttestation(): Promise<AttestationSummary> {
    if (this.attestation) {
      return this.attestation;
    }

    if (!this.attestationPromise) {
      const pending = globalThis
        .fetch(`${this.url}/v1/attestation`)
        .then(async (response) => {
          if (!response.ok) {
            throw new Error(
              `Subly402 attestation failed: ${
                response.status
              } ${await response.text()}`
            );
          }
          const body = (await response.json()) as AttestationSummary;
          this.attestation = {
            vaultConfig: body.vaultConfig,
            vaultSigner: body.vaultSigner,
            attestationPolicyHash: body.attestationPolicyHash,
          };
          return this.attestation;
        });
      // Clear the cached Promise once it settles so a transient fetch failure
      // (enclave restart, network blip, 5xx) doesn't brick the seller until a
      // process restart. Successive callers after a rejection will retry.
      pending.finally(() => {
        if (this.attestationPromise === pending) {
          this.attestationPromise = undefined;
        }
      });
      this.attestationPromise = pending;
    }

    return this.attestationPromise;
  }
}

export class Subly402ResourceServer {
  private networks = new Set<string>();

  constructor(readonly facilitatorClient: Subly402FacilitatorClient) {}

  register(network: string, _scheme: Subly402ExactScheme): this {
    this.networks.add(network);
    return this;
  }

  async buildProviderConfig(
    accept: Subly402RouteAccept
  ): Promise<Subly402ProviderConfig> {
    if (
      ![...this.networks].some((network) =>
        networkMatches(network, accept.network)
      )
    ) {
      throw new Error(`Subly402 network is not registered: ${accept.network}`);
    }

    const attestation = await this.facilitatorClient.getAttestation();
    const assetMint =
      accept.asset?.mint ??
      accept.assetMint ??
      this.facilitatorClient.defaultAssetMint;
    if (!assetMint) {
      throw new Error("Subly402 asset mint is required");
    }
    const payTo = await resolvePayTo(accept, assetMint);
    const providerId =
      accept.providerId ?? deriveProviderId(accept.network, assetMint, payTo);

    return {
      facilitatorUrl: this.facilitatorClient.url,
      providerId,
      authMode: this.facilitatorClient.authMode,
      apiKey: this.facilitatorClient.providerApiKey,
      mtls: this.facilitatorClient.mtls,
      payTo,
      network: accept.network,
      assetMint,
      assetDecimals:
        accept.asset?.decimals ??
        accept.assetDecimals ??
        this.facilitatorClient.defaultAssetDecimals,
      assetSymbol:
        accept.asset?.symbol ??
        accept.assetSymbol ??
        this.facilitatorClient.defaultAssetSymbol,
      vaultConfig: attestation.vaultConfig,
      vaultSigner: attestation.vaultSigner,
      attestationPolicyHash: attestation.attestationPolicyHash,
    };
  }
}

export const subly402ResourceServer = Subly402ResourceServer;

export function subly402PaymentMiddleware(
  routes: Subly402Routes,
  resourceServer: Subly402ResourceServer
) {
  return async (req: Request, res: Response, next: NextFunction) => {
    const route = findRoute(routes, req);
    if (!route) {
      return next();
    }

    try {
      const accept = selectAccept(route);
      const config = await resourceServer.buildProviderConfig(accept);
      const amount = normalizePriceToAtomic(accept.price, config.assetDecimals);
      return subly402Middleware({
        config,
        pricing: () => amount,
      })(req as any, res, next);
    } catch (error: any) {
      return res.status(500).json({
        error: "subly402_middleware_error",
        message: error?.message || "Subly402 middleware error",
      });
    }
  };
}
