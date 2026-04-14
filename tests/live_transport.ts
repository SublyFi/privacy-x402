import * as http from "http";
import * as https from "https";
import { execFileSync } from "child_process";
import { createHash, randomUUID } from "crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";

export type RequestTlsOptions = {
  caPath?: string;
  certPath?: string;
  keyPath?: string;
  serverName?: string;
};

export type TestResponse = {
  status: number;
  ok: boolean;
  text: () => Promise<string>;
  json: <T>() => Promise<T>;
};

export type GeneratedTlsFixture = {
  dir: string;
  caCertPath: string;
  caKeyPath: string;
  serverCertPath: string;
  serverKeyPath: string;
  clientCertPath: string;
  clientKeyPath: string;
  clientCertFingerprintHex: string;
  cleanup: () => void;
};

type RequestJsonOptions = {
  method?: "GET" | "POST";
  headers?: Record<string, string>;
  body?: unknown;
  tls?: RequestTlsOptions;
};

function pemToDer(pem: string): Buffer {
  const base64 = pem
    .replace(/-----BEGIN CERTIFICATE-----/g, "")
    .replace(/-----END CERTIFICATE-----/g, "")
    .replace(/\s+/g, "");
  return Buffer.from(base64, "base64");
}

function shasumHex(input: Buffer): string {
  const hash = createHash("sha256");
  hash.update(input);
  return hash.digest("hex");
}

export function generateTlsFixture(prefix: string): GeneratedTlsFixture {
  const dir = mkdtempSync(join(tmpdir(), `${prefix}-`));
  const caKeyPath = join(dir, "ca-key.pem");
  const caCertPath = join(dir, "ca-cert.pem");
  const serverKeyPath = join(dir, "server-key.pem");
  const serverCsrPath = join(dir, "server.csr");
  const serverCertPath = join(dir, "server-cert.pem");
  const serverExtPath = join(dir, "server-ext.cnf");
  const clientKeyPath = join(dir, "client-key.pem");
  const clientCsrPath = join(dir, "client.csr");
  const clientCertPath = join(dir, "client-cert.pem");
  const clientExtPath = join(dir, "client-ext.cnf");

  execFileSync(
    "openssl",
    [
      "req",
      "-x509",
      "-newkey",
      "rsa:2048",
      "-keyout",
      caKeyPath,
      "-out",
      caCertPath,
      "-days",
      "1",
      "-nodes",
      "-subj",
      "/CN=A402 Test CA",
    ],
    { stdio: "ignore" }
  );

  writeFileSync(
    serverExtPath,
    ["subjectAltName=DNS:localhost,IP:127.0.0.1", "extendedKeyUsage=serverAuth", ""].join("\n")
  );
  execFileSync(
    "openssl",
    [
      "req",
      "-newkey",
      "rsa:2048",
      "-keyout",
      serverKeyPath,
      "-out",
      serverCsrPath,
      "-nodes",
      "-subj",
      "/CN=localhost",
    ],
    { stdio: "ignore" }
  );
  execFileSync(
    "openssl",
    [
      "x509",
      "-req",
      "-in",
      serverCsrPath,
      "-CA",
      caCertPath,
      "-CAkey",
      caKeyPath,
      "-CAcreateserial",
      "-out",
      serverCertPath,
      "-days",
      "1",
      "-sha256",
      "-extfile",
      serverExtPath,
    ],
    { stdio: "ignore" }
  );

  writeFileSync(clientExtPath, ["extendedKeyUsage=clientAuth", ""].join("\n"));
  execFileSync(
    "openssl",
    [
      "req",
      "-newkey",
      "rsa:2048",
      "-keyout",
      clientKeyPath,
      "-out",
      clientCsrPath,
      "-nodes",
      "-subj",
      `/CN=a402-provider-${randomUUID()}`,
    ],
    { stdio: "ignore" }
  );
  execFileSync(
    "openssl",
    [
      "x509",
      "-req",
      "-in",
      clientCsrPath,
      "-CA",
      caCertPath,
      "-CAkey",
      caKeyPath,
      "-CAcreateserial",
      "-out",
      clientCertPath,
      "-days",
      "1",
      "-sha256",
      "-extfile",
      clientExtPath,
    ],
    { stdio: "ignore" }
  );

  const clientCertFingerprintHex = shasumHex(
    pemToDer(readFileSync(clientCertPath, "utf8"))
  );

  return {
    dir,
    caCertPath,
    caKeyPath,
    serverCertPath,
    serverKeyPath,
    clientCertPath,
    clientKeyPath,
    clientCertFingerprintHex,
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

export async function requestJson(
  url: string,
  options: RequestJsonOptions = {}
): Promise<TestResponse> {
  const parsedUrl = new URL(url);
  const transport = parsedUrl.protocol === "https:" ? https : http;
  const body =
    options.body === undefined ? undefined : Buffer.from(JSON.stringify(options.body));
  const headers: Record<string, string> = {
    ...(options.headers ?? {}),
  };

  if (body && !headers["Content-Type"]) {
    headers["Content-Type"] = "application/json";
  }
  if (body) {
    headers["Content-Length"] = body.byteLength.toString();
  }

  const requestOptions: http.RequestOptions | https.RequestOptions = {
    method: options.method ?? (body ? "POST" : "GET"),
    hostname: parsedUrl.hostname,
    port: parsedUrl.port ? Number(parsedUrl.port) : undefined,
    path: `${parsedUrl.pathname}${parsedUrl.search}`,
    headers,
  };

  if (parsedUrl.protocol === "https:") {
    const tls = options.tls;
    Object.assign(requestOptions, {
      ca: tls?.caPath ? readFileSync(tls.caPath) : undefined,
      cert: tls?.certPath ? readFileSync(tls.certPath) : undefined,
      key: tls?.keyPath ? readFileSync(tls.keyPath) : undefined,
      servername: tls?.serverName,
    });
  }

  return new Promise<TestResponse>((resolve, reject) => {
    const request = transport.request(requestOptions, (response) => {
      const chunks: Buffer[] = [];
      response.on("data", (chunk) => {
        chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
      });
      response.on("end", () => {
        const raw = Buffer.concat(chunks).toString("utf8");
        resolve({
          status: response.statusCode ?? 0,
          ok:
            (response.statusCode ?? 0) >= 200 &&
            (response.statusCode ?? 0) < 300,
          text: async () => raw,
          json: async <T>() => JSON.parse(raw) as T,
        });
      });
    });

    request.on("error", reject);
    if (body) {
      request.write(body);
    }
    request.end();
  });
}
