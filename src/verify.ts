import { Crypto } from "@peculiar/webcrypto";
import { X509Certificate } from "@peculiar/x509";

type Metadata = {
  getX509Certificate: (use: string) => string; // PEM or bare base64
  getSignatureAlgorithm?: () => string | undefined;
};

const certUse = { signing: "signing" } as const;

// Initialize Peculiar WebCrypto once
const crypto = new Crypto();

function toPemOrDer(input: string): string {
  // If it already looks like PEM, return as is; otherwise wrap base64 as PEM.
  if (/-----BEGIN CERTIFICATE-----/.test(input)) return input;
  const b64 = input.replace(/\s+/g, "");
  const wrapped = b64.replace(/(.{64})/g, "$1\n");
  return `-----BEGIN CERTIFICATE-----\n${wrapped}\n-----END CERTIFICATE-----`;
}

/**
 * @desc Normalize signature format for WebCrypto verification
 * @param sig {string | Buffer} signature bytes
 * @param algo {VerifyAlgo} algorithm to use for verification
 * @return {ArrayBuffer} normalized signature
 * 
 * For ECDSA signatures, expects IEEE P1363 format as required by XML Signature spec:
 * IEEE P1363: <r-padded> <s-padded> (concatenated, each component padded to curve field size)
 * 
 * Key size mapping:
 * - P-256 (secp256r1): 64 bytes (32 + 32)
 * - P-384 (secp384r1): 96 bytes (48 + 48)
 * - P-521 (secp521r1): 132 bytes (66 + 66)
 * 
 * For RSA signatures, passes through as-is.
 */
function normalizeSig(sig: string | Buffer, algo: VerifyAlgo): ArrayBuffer {
  let buffer: Buffer;
  
  if (Buffer.isBuffer(sig)) {
    buffer = sig;
  } else {
    buffer = Buffer.from(sig);
  }

  // Return buffer as ArrayBuffer for WebCrypto
  return buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength) as ArrayBuffer;
}

function encodeOctets(s: string): ArrayBuffer {
  // HTTP-Redirect binding signs the ASCII/UTF-8 octet string of the query (exact bytes).
  return new TextEncoder().encode(s).buffer;
}

type VerifyAlgo =
  | { name: "RSASSA-PKCS1-v1_5"; hash: "SHA-1" | "SHA-256" | "SHA-384" | "SHA-512" }
  | { name: "ECDSA"; hash: "SHA-1" | "SHA-256" | "SHA-384" | "SHA-512" };

function resolveVerifyAlgorithm(algo?: string): VerifyAlgo {
  const a = (algo ?? "").toLowerCase();

  // Common XML DSig URIs & aliases
  const map: Record<string, VerifyAlgo> = {
    // RSA
    "http://www.w3.org/2000/09/xmldsig#rsa-sha1":   { name: "RSASSA-PKCS1-v1_5", hash: "SHA-1" },
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256": { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384": { name: "RSASSA-PKCS1-v1_5", hash: "SHA-384" },
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512": { name: "RSASSA-PKCS1-v1_5", hash: "SHA-512" },
    "rsa-sha1":   { name: "RSASSA-PKCS1-v1_5", hash: "SHA-1" },
    "rsa-sha256": { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    "rsa-sha384": { name: "RSASSA-PKCS1-v1_5", hash: "SHA-384" },
    "rsa-sha512": { name: "RSASSA-PKCS1-v1_5", hash: "SHA-512" },
    "sha1withrsa":   { name: "RSASSA-PKCS1-v1_5", hash: "SHA-1" },
    "sha256withrsa": { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    "sha384withrsa": { name: "RSASSA-PKCS1-v1_5", hash: "SHA-384" },
    "sha512withrsa": { name: "RSASSA-PKCS1-v1_5", hash: "SHA-512" },

    // ECDSA
    "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1":   { name: "ECDSA", hash: "SHA-1" },
    "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256": { name: "ECDSA", hash: "SHA-256" },
    "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384": { name: "ECDSA", hash: "SHA-384" },
    "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512": { name: "ECDSA", hash: "SHA-512" },
    "ecdsa-sha1":   { name: "ECDSA", hash: "SHA-1" },
    "ecdsa-sha256": { name: "ECDSA", hash: "SHA-256" },
    "ecdsa-sha384": { name: "ECDSA", hash: "SHA-384" },
    "ecdsa-sha512": { name: "ECDSA", hash: "SHA-512" },
  };

  // Default to RSA SHA-1 if unspecified (backward compatible with master branch)
  return map[a] ?? { name: "RSASSA-PKCS1-v1_5", hash: "SHA-1" };
}

/**
 * @desc Verifies message signature (HTTP-Redirect binding friendly)
 * @param  {Metadata} metadata
 * @param  {string}   octetString
 * @param  {string|Buffer} signature
 * @param  {string}   verifyAlgorithm     (URI or alias, e.g., rsa-sha256)
 * @return {Promise<boolean>}
 */
export async function verifyMessageSignature(
  metadata: Metadata,
  octetString: string,
  signature: string | Buffer,
  verifyAlgorithm?: string
): Promise<boolean> {
  try {
    const signCertRaw = metadata.getX509Certificate(certUse.signing);
    if (!signCertRaw) return false;

    const pem = toPemOrDer(signCertRaw);
    const cert = new X509Certificate(pem);

    const algo = resolveVerifyAlgorithm(
      verifyAlgorithm ?? metadata.getSignatureAlgorithm?.()
    );

    // Export raw key material from certificate
    const peculiarKey = await cert.publicKey.export(crypto);
    const rawKey = await crypto.subtle.exportKey('spki', peculiarKey);

    // Build algorithm for re-import
    // For ECDSA, we need to preserve the namedCurve from the original key
    let importAlgo: any = algo;
    if (algo.name === 'ECDSA' && peculiarKey.algorithm && 'namedCurve' in peculiarKey.algorithm) {
      importAlgo = {
        ...algo,
        namedCurve: (peculiarKey.algorithm as any).namedCurve
      };
    }

    // Re-import with the correct algorithm for verification
    const key = await crypto.subtle.importKey(
      'spki',
      rawKey,
      importAlgo,  // This includes the correct hash algorithm (and namedCurve for ECDSA)
      false,
      ['verify']
    );

    const ok = await crypto.subtle.verify(
      algo,                                // includes { name, hash }
      key,
      normalizeSig(signature, algo),       // signature (IEEE P1363 for ECDSA, raw for RSA)
      encodeOctets(octetString)            // data exactly as signed
    );

    return !!ok;
  } catch (err) {
    return false;
  }
}
