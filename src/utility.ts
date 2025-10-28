/**
* @file utility.ts
* @author tngan
* @desc  Library for some common functions (e.g. de/inflation, en/decoding)
*/
import { pki, util, asn1 } from 'node-forge';
import * as x509 from '@peculiar/x509';
import { inflate, deflate } from 'pako';
import { AsnParser } from '@peculiar/asn1-schema';
import { PrivateKeyInfo } from '@peculiar/asn1-pkcs8';
import { id_rsaEncryption } from '@peculiar/asn1-rsa';
import { id_ecPublicKey } from '@peculiar/asn1-ecc';
import { algorithms } from './urn';

const BASE64_STR = 'base64';

/**
 * @desc Mimic lodash.zipObject
 * @param arr1 {string[]}
 * @param arr2 {[]}
 */
export function zipObject(arr1: string[], arr2: any[], skipDuplicated = true) {
  return arr1.reduce((res, l, i) => {

    if (skipDuplicated) {
      res[l] = arr2[i];
      return res;
    }
    // if key exists, aggregate with array in order to get rid of duplicate key
    if (res[l] !== undefined) {
      res[l] = Array.isArray(res[l])
        ? res[l].concat(arr2[i])
        : [res[l]].concat(arr2[i]);
      return res;
    }

    res[l] = arr2[i];
    return res;

  }, {});
}
/**
 * @desc Alternative to lodash.flattenDeep
 * @reference https://github.com/you-dont-need/You-Dont-Need-Lodash-Underscore#_flattendeep
 * @param input {[]}
 */
export function flattenDeep(input: any[]) {
  return Array.isArray(input)
    ? input.reduce((a, b) => a.concat(flattenDeep(b)), [])
    : [input];
}
/**
 * @desc Alternative to lodash.last
 * @reference https://github.com/you-dont-need/You-Dont-Need-Lodash-Underscore#_last
 * @param input {[]}
 */
export function last(input: any[]) {
  return input.slice(-1)[0];
}
/**
 * @desc Alternative to lodash.uniq
 * @reference https://github.com/you-dont-need/You-Dont-Need-Lodash-Underscore#_uniq
 * @param input {string[]}
 */
export function uniq(input: string[]) {
  const set = new Set(input);
  return [...set];
}
/**
 * @desc Alternative to lodash.get
 * @reference https://github.com/you-dont-need/You-Dont-Need-Lodash-Underscore#_get
 * @param obj
 * @param path
 * @param defaultValue
 */
export function get(obj, path, defaultValue) {
  return path.split('.')
    .reduce((a, c) => (a && a[c] ? a[c] : (defaultValue || null)), obj);
}
/**
 * @desc Check if the input is string
 * @param {any} input
 */
export function isString(input: any) {
  return typeof input === 'string';
}
/**
* @desc Encode string with base64 format
* @param  {string} message                       plain-text message
* @return {string} base64 encoded string
*/
function base64Encode(message: string | number[]) {
  return Buffer.from(message as string).toString(BASE64_STR);
}
/**
* @desc Decode string from base64 format
* @param  {string} base64Message                 encoded string
* @param  {boolean} isBytes                      determine the return value type (True: bytes False: string)
* @return {bytes/string}  decoded bytes/string depends on isBytes, default is {string}
*/
export function base64Decode(base64Message: string, isBytes?: boolean): string | Buffer {
  const bytes = Buffer.from(base64Message, BASE64_STR);
  return Boolean(isBytes) ? bytes : bytes.toString();
}
/**
* @desc Compress the string
* @param  {string} message
* @return {string} compressed string
*/
function deflateString(message: string): number[] {
  const input = Array.prototype.map.call(message, char => char.charCodeAt(0));
  return Array.from(deflate(input, { raw: true }));
}
/**
* @desc Decompress the compressed string
* @param  {string} compressedString
* @return {string} decompressed string
*/
export function inflateString(compressedString: string): string {
  const inputBuffer = Buffer.from(compressedString, BASE64_STR);
  const input = Array.prototype.map.call(inputBuffer.toString('binary'), char => char.charCodeAt(0));
  return Array.from(inflate(input, { raw: true }))
    .map((byte: number) => String.fromCharCode(byte))
    .join('');
}
/**
* @desc Abstract the normalizeCerString and normalizePemString
* @param {buffer} File stream or string
* @param {string} String for header and tail
* @return {string} A formatted certificate string
*/
function _normalizeCerString(bin: string | Buffer, format: string) {
  return bin.toString().replace(/\n/g, '').replace(/\r/g, '').replace(`-----BEGIN ${format}-----`, '').replace(`-----END ${format}-----`, '').replace(/ /g, '').replace(/\t/g, '');
}
/**
* @desc Parse the .cer to string format without line break, header and footer
* @param  {string} certString     declares the certificate contents
* @return {string} certificiate in string format
*/
function normalizeCerString(certString: string | Buffer) {
  return _normalizeCerString(certString, 'CERTIFICATE');
}
/**
* @desc Normalize the string in .pem format without line break, header and footer
* @param  {string} pemString
* @return {string} private key in string format
*/
function normalizePemString(pemString: string | Buffer) {
  return _normalizeCerString(pemString.toString(), 'RSA PRIVATE KEY');
}
/**
* @desc Return the complete URL
* @param  {object} req                   HTTP request
* @return {string} URL
*/
function getFullURL(req) {
  return `${req.protocol}://${req.get('host')}${req.originalUrl}`;
}
/**
* @desc Parse input string, return default value if it is undefined
* @param  {string/boolean}
* @return {boolean}
*/
function parseString(str, defaultValue = '') {
  return str || defaultValue;
}
/**
* @desc Override the object by another object (rtl)
* @param  {object} default object
* @param  {object} object applied to the default object
* @return {object} result object
*/
function applyDefault(obj1, obj2) {
  return Object.assign({}, obj1, obj2);
}
/**
* @desc Get public key in pem format from the certificate included in the metadata
* @param {string} x509 certificate (base64 string without headers)
* @return {string} public key fetched from the certificate
*/
function getPublicKeyPemFromCertificate(x509Certificate: string) {
  // Try using @peculiar/x509 first which supports both RSA and EC
  try {
    // Wrap the certificate in PEM format
    const pem = `-----BEGIN CERTIFICATE-----\n${x509Certificate.match(/.{1,64}/g)?.join('\n')}\n-----END CERTIFICATE-----`;
    const cert = new x509.X509Certificate(pem);

    // Export public key in PEM format
    const publicKeyDer = cert.publicKey.rawData;
    const publicKeyBase64 = Buffer.from(publicKeyDer).toString('base64');
    const publicKeyPem = `-----BEGIN PUBLIC KEY-----\n${publicKeyBase64.match(/.{1,64}/g)?.join('\n')}\n-----END PUBLIC KEY-----`;

    return publicKeyPem;
  } catch (e) {
    // Fallback to node-forge for RSA certificates (legacy support)
    try {
      const certDerBytes = util.decode64(x509Certificate);
      const obj = asn1.fromDer(certDerBytes);
      const cert = pki.certificateFromAsn1(obj);
      return pki.publicKeyToPem(cert.publicKey);
    } catch (forgeError) {
      throw new Error(`Failed to extract public key from certificate: ${(e as Error).message}`);
    }
  }
}
/**
* @desc Read private key from pem-formatted string
* @param {string | Buffer} keyString pem-formatted string
* @param {string} protected passphrase of the key
* @return {string} string in pem format
* If passphrase is used to protect the .pem content (recommend)
*/
export function readPrivateKey(keyString: string | Buffer, passphrase: string | undefined, isOutputString?: boolean) {
  if (!isString(passphrase)) {
    return keyString;
  }

  const keyStr = String(keyString);

  // For encrypted PKCS#8, use Node.js crypto which supports both RSA and EC
  if (keyStr.includes('BEGIN ENCRYPTED PRIVATE KEY')) {
    // Node.js crypto can decrypt and re-export encrypted PKCS#8 keys
    const nodeCrypto = require('crypto');
    const keyObject = nodeCrypto.createPrivateKey({
      key: keyStr,
      format: 'pem',
      passphrase: passphrase as string
    });
    // Export as unencrypted PKCS#8 PEM
    const decryptedPem = keyObject.export({
      type: 'pkcs8',
      format: 'pem'
    });
    return this.convertToString(decryptedPem, isOutputString);
  }

  // For legacy encrypted formats (e.g., BEGIN RSA PRIVATE KEY with encryption)
  return this.convertToString(pki.privateKeyToPem(pki.decryptRsaPrivateKey(keyStr, passphrase as string)), isOutputString);
}
/**
* @desc Inline syntax sugar
*/
function convertToString(input, isOutputString) {
  return Boolean(isOutputString) ? String(input) : input;
}
/**
 * @desc Check if the input is an array with non-zero size
 */
export function isNonEmptyArray(a) {
  return Array.isArray(a) && a.length > 0;
}

export function castArrayOpt<T>(a?: T | T[]): T[] {
  if (a === undefined) return []
  return Array.isArray(a) ? a : [a]
}

export function notEmpty<TValue>(value: TValue | null | undefined): value is TValue {
  return value !== null && value !== undefined;
}

export function detectCertAlg(cert: string | undefined): 'RSA' | 'EC' | null {
  if (!cert) {
    return null;
  }

  try {
    const parsedCert = new x509.X509Certificate(cert);

    switch (parsedCert.signatureAlgorithm.name.toUpperCase()) {
      case 'RSASSA-PKCS1-V1_5':
      case 'RSA-PSS':
      case 'RSA-OAEP':
        return 'RSA';
      case 'ECDSA':
      case 'ECDH':
        return 'EC';
      default:
        return null;
    }
  } catch (Error) {
    return null;
  }
}

/**
* @desc Detect if a private key or certificate is RSA or EC
* @param keyOrCert {string | Buffer} PEM formatted key or certificate
* @return {'RSA' | 'EC' | null} key type or null if unable to detect
*/
/**
 * @desc Detect if a private key or certificate is RSA or EC using robust ASN.1 parsing
 * @param keyOrCert {string | Buffer} PEM formatted key or certificate
 * @return {'RSA' | 'EC'} key type
 * @throws {Error} If key type cannot be reliably determined
 * 
 * This function uses strict detection strategies without fallbacks:
 * 1. Fast path: Checks PEM headers for explicit key type markers (SEC1, PKCS#1)
 * 2. PKCS#8 path: Uses @peculiar/asn1-pkcs8 library to parse PrivateKeyInfo structure
 * 3. Certificate path: Uses @peculiar/x509 to parse certificate and extract algorithm
 * 
 * For critical security operations, this function will throw an error rather than
 * guess or assume a key type. This prevents silent failures and misconfigurations.
 */
export function detectKeyType(keyOrCert: string | Buffer | undefined): 'RSA' | 'EC' {
  if (!keyOrCert) {
    throw new Error('Key or certificate is required for key type detection');
  }

  // Convert Buffer to string if needed
  const keyString = Buffer.isBuffer(keyOrCert) ? keyOrCert.toString('utf8') : keyOrCert;

  // Strategy 1: Fast path - Check PEM headers for explicit type markers
  // These formats include the key type in the header itself, so detection is certain
  if (keyString.includes('EC PRIVATE KEY') || keyString.includes('EC PUBLIC KEY')) {
    return 'EC'; // SEC1 format (RFC 5915)
  }
  if (keyString.includes('RSA PRIVATE KEY') || keyString.includes('RSA PUBLIC KEY')) {
    return 'RSA'; // PKCS#1 format (RFC 8017)
  }

  // Strategy 2: PKCS#8 format - Use proper ASN.1 parsing library
  // This is the most common format for modern keys
  if (keyString.includes('PRIVATE KEY') && !keyString.includes('ENCRYPTED')) {
    try {
      // Remove PEM headers/footers and whitespace
      const pemContent = keyString
        .replace(/-----BEGIN [^-]+-----/, '')
        .replace(/-----END [^-]+-----/, '')
        .replace(/\s+/g, '');

      const der = Buffer.from(pemContent, 'base64');
      const privateKeyInfo = AsnParser.parse(der, PrivateKeyInfo);
      const algorithm = privateKeyInfo.privateKeyAlgorithm.algorithm;

      // Check against standard OIDs
      if (algorithm === id_ecPublicKey) {
        return 'EC';
      }
      if (algorithm === id_rsaEncryption) {
        return 'RSA';
      }

      // Check OID prefixes for algorithm families
      // EC family: 1.2.840.10045.* (ansi-x962)
      // RSA family: 1.2.840.113549.1.1.* (pkcs-1)
      if (algorithm.startsWith('1.2.840.10045')) {
        return 'EC';
      }
      if (algorithm.startsWith('1.2.840.113549.1.1')) {
        return 'RSA';
      }

      // Unknown algorithm OID
      throw new Error(
        `Unsupported key algorithm OID: ${algorithm}. ` +
        `Expected RSA (1.2.840.113549.1.1.*) or EC (1.2.840.10045.*)`
      );
    } catch (e) {
      if (e instanceof Error && e.message.includes('Unsupported key algorithm')) {
        throw e; // Re-throw our custom errors
      }
      throw new Error(
        `Failed to parse PKCS#8 private key: ${e instanceof Error ? e.message : String(e)}. ` +
        `Ensure the key is valid PEM-encoded PKCS#8 format.`
      );
    }
  }

  // Strategy 3: X.509 Certificate - Use existing @peculiar/x509 dependency
  if (keyString.includes('CERTIFICATE')) {
    try {
      // Remove PEM headers/footers and whitespace
      const pemContent = keyString
        .replace(/-----BEGIN [^-]+-----/, '')
        .replace(/-----END [^-]+-----/, '')
        .replace(/\s+/g, '');

      const der = Buffer.from(pemContent, 'base64');
      // Convert Buffer to Uint8Array for x509 library
      const uint8Array = new Uint8Array(der);
      const cert = new x509.X509Certificate(uint8Array);
      const algorithm = cert.publicKey.algorithm.name;

      // Check for EC algorithms
      if (algorithm === 'ECDSA' || algorithm === 'ECDH') {
        return 'EC';
      }

      // Check for RSA algorithms
      if (algorithm === 'RSA' || algorithm === 'RSASSA-PKCS1-v1_5' ||
        algorithm === 'RSA-PSS' || algorithm === 'RSA-OAEP') {
        return 'RSA';
      }

      // Unknown algorithm
      throw new Error(
        `Unsupported certificate algorithm: ${algorithm}. ` +
        `Expected RSA or EC-based algorithm.`
      );
    } catch (e) {
      if (e instanceof Error && e.message.includes('Unsupported certificate algorithm')) {
        throw e; // Re-throw our custom errors
      }
      throw new Error(
        `Failed to parse X.509 certificate: ${e instanceof Error ? e.message : String(e)}. ` +
        `Ensure the certificate is valid PEM-encoded X.509 format.`
      );
    }
  }

  // Encrypted PKCS#8 - Cannot reliably detect without decrypting
  // The encryption wrapper hides the algorithm identifier
  if (keyString.includes('ENCRYPTED PRIVATE KEY')) {
    throw new Error(
      'Encrypted PKCS#8 private keys cannot be inspected without decryption. ' +
      'The key algorithm is encrypted within the PKCS#8 structure. ' +
      'Please decrypt the key first or use key type detection after decryption.'
    );
  }

  // Unknown key format
  throw new Error(
    'Unable to detect key type: unrecognized key format. ' +
    'Supported formats: SEC1 (EC PRIVATE KEY), PKCS#1 (RSA PRIVATE KEY), ' +
    'PKCS#8 (PRIVATE KEY), X.509 (CERTIFICATE)'
  );
}

/**
 * @desc Normalize signature algorithm based on key type
 * @param algorithm {string | undefined} The signature algorithm (can be RSA or ECDSA URN)
 * @param keyType {'RSA' | 'EC'} The detected key type
 * @return {string | undefined} The normalized signature algorithm matching the key type, or undefined if no algorithm specified
 * 
 * This function handles algorithm conversion when RSA algorithm is specified but key is EC.
 * It converts RSA signature algorithms to their equivalent ECDSA algorithms.
 * 
 * If no algorithm is specified (undefined), it returns undefined without adding a default.
 * This allows calling code to handle its own default algorithm logic.
 * 
 * This ensures that the signature algorithm always matches the key type, preventing signature failures.
 */
export function normalizeSignatureAlgorithm(
  algorithm: string | undefined,
  keyType: 'RSA' | 'EC'
): string | undefined {
  const signatureAlgorithms = algorithms.signature;

  // If no algorithm specified, return undefined (let caller handle default)
  if (!algorithm) {
    return undefined;
  }

  // Convert RSA to ECDSA if key is EC
  if (keyType === 'EC' && algorithm.toLowerCase().includes('rsa')) {
    if (algorithm.toLowerCase().includes('sha512')) {
      return signatureAlgorithms.ECDSA_SHA512;
    } else if (algorithm.toLowerCase().includes('sha384')) {
      return signatureAlgorithms.ECDSA_SHA384;
    } else if (algorithm.toLowerCase().includes('sha1')) {
      return signatureAlgorithms.ECDSA_SHA1;
    } else {
      // Default to SHA256 for any other SHA variant or unrecognized
      return signatureAlgorithms.ECDSA_SHA256;
    }
  }

  // Return algorithm as-is if no conversion needed
  return algorithm;
}

/**
 * @desc Convert PEM-encoded key to DER format (for WebCrypto importKey)
 * @param pem {string} PEM-encoded key (with BEGIN/END headers)
 * @return {Buffer} DER-encoded key as Buffer
 */
export function pemToDer(pem: string): Buffer {
  // Remove PEM headers and decode base64
  const pemContent = pem
    .replace(/-----BEGIN [A-Z ]+-----/, '')
    .replace(/-----END [A-Z ]+-----/, '')
    .replace(/\s+/g, '');

  return Buffer.from(pemContent, 'base64');
}

/**
 * @desc Convert ECDSA signature from DER format to IEEE P1363 format (raw r|s)
 * Node.js crypto.sign() produces DER format, but XML signatures require IEEE P1363
 * @param derSignature {Buffer} DER-encoded signature
 * @return {Buffer} IEEE P1363 encoded signature (raw r||s concatenation)
 */
export function derToP1363(derSignature: Buffer): Buffer {
  // DER format: 0x30 <total-length> 0x02 <r-length> <r-value> 0x02 <s-length> <s-value>

  if (derSignature.length < 8) {
    throw new Error('DER signature too short');
  }

  if (derSignature[0] !== 0x30) {
    throw new Error('Invalid DER signature - missing SEQUENCE marker');
  }

  let offset = 2; // Skip SEQUENCE marker and length

  // Read r value
  if (derSignature[offset] !== 0x02) {
    throw new Error('Invalid DER signature - missing INTEGER marker for r');
  }
  offset++;

  const rLength = derSignature[offset];
  offset++;

  let r = derSignature.subarray(offset, offset + rLength);
  offset += rLength;

  // Remove leading 0x00 byte if present (DER padding for positive integers)
  if (r[0] === 0x00 && r.length > 1) {
    r = r.subarray(1);
  }

  // Read s value
  if (derSignature[offset] !== 0x02) {
    throw new Error('Invalid DER signature - missing INTEGER marker for s');
  }
  offset++;

  const sLength = derSignature[offset];
  offset++;

  let s = derSignature.subarray(offset, offset + sLength);

  // Remove leading 0x00 byte if present
  if (s[0] === 0x00 && s.length > 1) {
    s = s.subarray(1);
  }

  // Determine the field size (r and s should be the same length in P1363)
  const fieldSize = Math.max(r.length, s.length);

  // Pad r and s to field size
  const rPadded = Buffer.alloc(fieldSize);
  r.copy(rPadded, fieldSize - r.length);

  const sPadded = Buffer.alloc(fieldSize);
  s.copy(sPadded, fieldSize - s.length);

  // Concatenate r || s
  return Buffer.concat([rPadded, sPadded]);
}

/**
 * @desc Convert ECDSA signature from IEEE P1363 format to DER format
 * WebCrypto and XML signatures use P1363, but Node.js crypto.verify() expects DER
 * @param p1363Signature {Buffer} IEEE P1363 encoded signature (raw r||s)
 * @return {Buffer} DER-encoded signature
 */
export function p1363ToDer(p1363Signature: Buffer): Buffer {
  // P1363 format is r || s concatenated, each component is the same length
  const componentLength = p1363Signature.length / 2;

  let r = p1363Signature.subarray(0, componentLength);
  let s = p1363Signature.subarray(componentLength);

  // Remove leading zeros from r and s (but keep at least one byte)
  while (r.length > 1 && r[0] === 0x00) {
    r = r.subarray(1);
  }
  while (s.length > 1 && s[0] === 0x00) {
    s = s.subarray(1);
  }

  // Add leading 0x00 if high bit is set (DER requirement for positive integers)
  if (r[0] & 0x80) {
    r = Buffer.concat([Buffer.from([0x00]), r]);
  }
  if (s[0] & 0x80) {
    s = Buffer.concat([Buffer.from([0x00]), s]);
  }

  // Build DER structure: 0x30 <total-length> 0x02 <r-length> <r> 0x02 <s-length> <s>
  const derLength = 2 + r.length + 2 + s.length; // 2 bytes for each INTEGER marker+length
  const der = Buffer.alloc(2 + derLength);

  let offset = 0;
  der[offset++] = 0x30; // SEQUENCE marker
  der[offset++] = derLength; // Total length

  der[offset++] = 0x02; // INTEGER marker for r
  der[offset++] = r.length;
  r.copy(der, offset);
  offset += r.length;

  der[offset++] = 0x02; // INTEGER marker for s
  der[offset++] = s.length;
  s.copy(der, offset);

  return der;
}

const utility = {
  isString,
  base64Encode,
  base64Decode,
  deflateString,
  inflateString,
  normalizeCerString,
  normalizePemString,
  getFullURL,
  parseString,
  applyDefault,
  getPublicKeyPemFromCertificate,
  readPrivateKey,
  convertToString,
  isNonEmptyArray,
  detectKeyType,
  normalizeSignatureAlgorithm,
  pemToDer,
  derToP1363,
  p1363ToDer,
};

export default utility;
