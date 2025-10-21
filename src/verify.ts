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
 * @param sig {string | Buffer} signature bytes (may be DER-encoded for ECDSA)
 * @param algo {VerifyAlgo} algorithm to use for verification
 * @return {ArrayBuffer} normalized signature
 * 
 * For ECDSA signatures, converts from DER encoding (used by OpenSSL/Node.js crypto)
 * to IEEE P1363 format (required by WebCrypto API).
 * 
 * DER format: 0x30 <total-length> 0x02 <r-length> <r-value> 0x02 <s-length> <s-value>
 * IEEE P1363: <r-padded> <s-padded> (concatenated, each component padded to curve field size)
 * 
 * Key size mapping (based on component lengths after removing leading zeros):
 * - P-256 (secp256r1): 32 bytes per component (64 total)
 * - P-384 (secp384r1): 48 bytes per component (96 total)
 * - P-521 (secp521r1): 66 bytes per component (132 total)
 */
function normalizeSig(sig: string | Buffer, algo: VerifyAlgo): ArrayBuffer {
  let buffer: Buffer;
  
  if (Buffer.isBuffer(sig)) {
    buffer = sig;
  } else {
    buffer = Buffer.from(sig);
  }
  
  // For ECDSA, convert DER signature to IEEE P1363 format (raw r|s)
  if (algo.name === 'ECDSA') {
    try {
      // Validate DER structure
      if (buffer.length < 8) {
        throw new Error('Signature too short to be valid DER');
      }
      
      if (buffer[0] !== 0x30) {
        throw new Error('Invalid DER signature - missing SEQUENCE marker (0x30)');
      }
      
      // Parse total length (byte 1)
      const totalLength = buffer[1];
      if (totalLength + 2 !== buffer.length) {
        throw new Error(`Invalid DER signature - length mismatch (declared: ${totalLength}, actual: ${buffer.length - 2})`);
      }
      
      let offset = 2; // Skip 0x30 and total length
      
      // Parse r component
      if (offset >= buffer.length || buffer[offset] !== 0x02) {
        throw new Error('Invalid DER signature - missing INTEGER marker for r (0x02)');
      }
      offset++;
      
      if (offset >= buffer.length) {
        throw new Error('Invalid DER signature - missing r length');
      }
      const rLength = buffer[offset];
      offset++;
      
      if (offset + rLength > buffer.length) {
        throw new Error('Invalid DER signature - r value extends beyond buffer');
      }
      let r = buffer.slice(offset, offset + rLength);
      offset += rLength;
      
      // Parse s component
      if (offset >= buffer.length || buffer[offset] !== 0x02) {
        throw new Error('Invalid DER signature - missing INTEGER marker for s (0x02)');
      }
      offset++;
      
      if (offset >= buffer.length) {
        throw new Error('Invalid DER signature - missing s length');
      }
      const sLength = buffer[offset];
      offset++;
      
      if (offset + sLength > buffer.length) {
        throw new Error('Invalid DER signature - s value extends beyond buffer');
      }
      let s = buffer.slice(offset, offset + sLength);
      
      // DER encodes integers with a leading 0x00 byte if the high bit is set
      // (to indicate positive numbers). Remove these padding bytes.
      while (r.length > 1 && r[0] === 0x00 && (r[1] & 0x80) !== 0) {
        r = r.slice(1);
      }
      while (s.length > 1 && s[0] === 0x00 && (s[1] & 0x80) !== 0) {
        s = s.slice(1);
      }
      
      // Also remove any leading zeros that aren't needed for sign bit
      while (r.length > 1 && r[0] === 0x00) {
        r = r.slice(1);
      }
      while (s.length > 1 && s[0] === 0x00) {
        s = s.slice(1);
      }
      
      // Determine curve field size based on component lengths
      // More robust than using total signature length
      const maxComponentLength = Math.max(r.length, s.length);
      let keySize: number;
      
      if (maxComponentLength <= 32) {
        keySize = 32; // P-256
      } else if (maxComponentLength <= 48) {
        keySize = 48; // P-384
      } else if (maxComponentLength <= 66) {
        keySize = 66; // P-521
      } else {
        throw new Error(`Unsupported EC curve - component length ${maxComponentLength} exceeds P-521`);
      }
      
      // Validate that components fit within the determined key size
      if (r.length > keySize || s.length > keySize) {
        throw new Error(`Invalid signature components - lengths (r: ${r.length}, s: ${s.length}) exceed key size ${keySize}`);
      }
      
      // Pad r and s to key size (left-pad with zeros)
      const rPadded = Buffer.alloc(keySize);
      r.copy(rPadded as any, keySize - r.length);
      
      const sPadded = Buffer.alloc(keySize);
      s.copy(sPadded as any, keySize - s.length);
      
      // Concatenate r and s to create IEEE P1363 format
      const ieee = Buffer.concat([rPadded as any, sPadded as any]);
      
      return ieee.buffer.slice(ieee.byteOffset, ieee.byteOffset + ieee.byteLength) as ArrayBuffer;
    } catch (e) {
      // Log error and fall back to returning raw buffer
      // This allows RSA signatures or already-normalized ECDSA signatures to work
      console.error('Failed to convert DER to IEEE P1363 format:', (e as Error).message);
      console.error('Falling back to raw signature buffer');
    }
  }

  // For RSA or if ECDSA conversion failed, return buffer as-is
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
