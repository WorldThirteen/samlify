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

function normalizeSig(sig: string | Buffer, algo: VerifyAlgo): ArrayBuffer {
  let buffer: Buffer;
  
  if (Buffer.isBuffer(sig)) {
    buffer = sig;
  } else {
    buffer = Buffer.from(sig);
  }
  
  // For ECDSA, convert DER signature to IEEE P1363 format (raw r|s)
  if (algo.name === 'ECDSA') {
    // DER format: 0x30 <length> 0x02 <r-length> <r> 0x02 <s-length> <s>
    // IEEE P1363: <r> <s> (each padded to key size / 2)
    
    try {
      // Parse DER structure
      if (buffer[0] !== 0x30) {
        throw new Error('Invalid DER signature');
      }
      
      let offset = 2; // Skip 0x30 and total length
      
      // Parse r
      if (buffer[offset] !== 0x02) {
        throw new Error('Invalid DER signature - r marker');
      }
      offset++;
      const rLength = buffer[offset];
      offset++;
      let r = buffer.slice(offset, offset + rLength);
      offset += rLength;
      
      // Parse s
      if (buffer[offset] !== 0x02) {
        throw new Error('Invalid DER signature - s marker');
      }
      offset++;
      const sLength = buffer[offset];
      offset++;
      let s = buffer.slice(offset, offset + sLength);
      
      // Remove leading zeros (DER adds them for positive integers)
      while (r.length > 0 && r[0] === 0) {
        r = r.slice(1);
      }
      while (s.length > 0 && s[0] === 0) {
        s = s.slice(1);
      }
      
      // Determine key size (P-256 = 32 bytes, P-384 = 48 bytes, P-521 = 66 bytes)
      // Based on the total signature length, we can infer the key size
      const keySize = buffer.length <= 75 ? 32 : (buffer.length <= 110 ? 48 : 66);
      
      // Pad r and s to key size
      const rPadded = Buffer.alloc(keySize);
      r.copy(rPadded as any, keySize - r.length);
      
      const sPadded = Buffer.alloc(keySize);
      s.copy(sPadded as any, keySize - s.length);
      
      // Concatenate r and s
      const ieee = Buffer.concat([rPadded as any, sPadded as any]);
      
      return ieee.buffer.slice(ieee.byteOffset, ieee.byteOffset + ieee.byteLength) as ArrayBuffer;
    } catch (e) {
      console.error('Failed to convert DER to IEEE P1363:', e);
      // Fall through to original behavior
    }
  }

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

  // Default to modern RSA SHA-256 if unspecified
  return map[a] ?? { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };
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

    const key = await cert.publicKey.export(crypto);

    const ok = await crypto.subtle.verify(
      algo,                                // includes { name, hash }
      key,
      normalizeSig(signature, algo),       // signature (IEEE P1363 for ECDSA, raw for RSA)
      encodeOctets(octetString)            // data exactly as signed
    );

    return !!ok;
  } catch {
    return false;
  }
}
