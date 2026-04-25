import * as http from "http";
import * as https from "https";
import { readFile } from "fs/promises";
import type { Subly402ProviderConfig } from "./types";

const pemFileCache = new Map<string, Promise<Buffer>>();

function getAuthMode(
  config: Subly402ProviderConfig
): "none" | "bearer" | "api-key" | "mtls" {
  if (config.authMode) {
    return config.authMode;
  }
  if (config.mtls) {
    return "mtls";
  }
  if (config.apiKey) {
    return "bearer";
  }
  return "none";
}

function requireApiKey(config: Subly402ProviderConfig): string {
  if (!config.apiKey) {
    throw new Error(
      "config.apiKey is required for bearer/api-key facilitator auth"
    );
  }
  return config.apiKey;
}

function buildAuthHeaders(
  config: Subly402ProviderConfig,
  authMode: "none" | "bearer" | "api-key" | "mtls"
): Record<string, string> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "x-subly402-provider-id": config.providerId,
  };

  if (authMode === "bearer") {
    const apiKey = requireApiKey(config);
    headers.Authorization = `Bearer ${apiKey}`;
    headers["x-subly402-provider-auth"] = apiKey;
  } else if (authMode === "api-key") {
    headers["x-subly402-provider-auth"] = requireApiKey(config);
  }

  return headers;
}

async function readCachedPem(path: string): Promise<Buffer> {
  const pending = pemFileCache.get(path) ?? readFile(path);
  pemFileCache.set(path, pending);
  try {
    return await pending;
  } catch (error) {
    pemFileCache.delete(path);
    throw error;
  }
}

async function buildRequestOptions(
  url: URL,
  payload: string,
  config: Subly402ProviderConfig
): Promise<http.RequestOptions | https.RequestOptions> {
  const authMode = getAuthMode(config);
  const headers = buildAuthHeaders(config, authMode);
  headers["Content-Length"] = Buffer.byteLength(payload).toString();

  const baseOptions: http.RequestOptions = {
    method: "POST",
    hostname: url.hostname,
    port: url.port ? Number(url.port) : undefined,
    path: `${url.pathname}${url.search}`,
    headers,
  };

  if (authMode !== "mtls") {
    return baseOptions;
  }

  if (url.protocol !== "https:") {
    throw new Error("mtls facilitator auth requires an https facilitatorUrl");
  }
  if (!config.mtls?.certPath || !config.mtls?.keyPath) {
    throw new Error(
      "config.mtls.certPath and config.mtls.keyPath are required for mtls auth"
    );
  }

  return {
    ...baseOptions,
    cert: await readCachedPem(config.mtls.certPath),
    key: await readCachedPem(config.mtls.keyPath),
    ca: config.mtls.caPath
      ? await readCachedPem(config.mtls.caPath)
      : undefined,
    servername: config.mtls.serverName,
  };
}

export async function postFacilitatorJson<T>(
  url: string,
  body: unknown,
  config: Subly402ProviderConfig
): Promise<T> {
  const parsedUrl = new URL(url);
  const payload = JSON.stringify(body);
  const options = await buildRequestOptions(parsedUrl, payload, config);
  const transport = parsedUrl.protocol === "https:" ? https : http;

  return new Promise<T>((resolve, reject) => {
    const request = transport.request(options, (response) => {
      const chunks: Buffer[] = [];
      response.on("data", (chunk) => {
        chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
      });
      response.on("end", () => {
        const raw = Buffer.concat(chunks).toString("utf-8");
        if (!raw) {
          resolve({} as T);
          return;
        }
        try {
          resolve(JSON.parse(raw) as T);
        } catch (error: any) {
          reject(
            new Error(
              `Invalid facilitator JSON response (${
                response.statusCode ?? "unknown"
              }): ${error.message}`
            )
          );
        }
      });
    });

    request.on("error", reject);
    request.write(payload);
    request.end();
  });
}
