import { X509Certificate } from "node:crypto";
import { isIP } from "node:net";
import tls from "node:tls";

import { sha256hex } from "./crypto";

export async function probeTlsPublicKeySha256(
  urlString: string
): Promise<string> {
  const url = new URL(urlString);
  if (url.protocol !== "https:") {
    throw new Error("TLS endpoint binding requires an https:// enclaveUrl");
  }

  return new Promise((resolve, reject) => {
    const socket = tls.connect({
      host: url.hostname,
      port: Number(url.port || 443),
      servername: isIP(url.hostname) === 0 ? url.hostname : undefined,
      rejectUnauthorized: false,
    });

    socket.once("secureConnect", () => {
      try {
        const certificate = socket.getPeerCertificate(true);
        if (!certificate || !certificate.raw) {
          throw new Error("TLS peer certificate is missing");
        }
        const x509 = new X509Certificate(certificate.raw);
        const publicKeyDer = x509.publicKey.export({
          format: "der",
          type: "spki",
        }) as Buffer;
        resolve(sha256hex(publicKeyDer));
      } catch (error) {
        reject(error);
      } finally {
        socket.end();
      }
    });

    socket.once("error", (error) => {
      reject(error);
    });
  });
}
