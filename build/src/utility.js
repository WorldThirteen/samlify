"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __read = (this && this.__read) || function (o, n) {
    var m = typeof Symbol === "function" && o[Symbol.iterator];
    if (!m) return o;
    var i = m.call(o), r, ar = [], e;
    try {
        while ((n === void 0 || n-- > 0) && !(r = i.next()).done) ar.push(r.value);
    }
    catch (error) { e = { error: error }; }
    finally {
        try {
            if (r && !r.done && (m = i["return"])) m.call(i);
        }
        finally { if (e) throw e.error; }
    }
    return ar;
};
var __spreadArray = (this && this.__spreadArray) || function (to, from, pack) {
    if (pack || arguments.length === 2) for (var i = 0, l = from.length, ar; i < l; i++) {
        if (ar || !(i in from)) {
            if (!ar) ar = Array.prototype.slice.call(from, 0, i);
            ar[i] = from[i];
        }
    }
    return to.concat(ar || Array.prototype.slice.call(from));
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.p1363ToDer = exports.derToP1363 = exports.pemToDer = exports.normalizeSignatureAlgorithm = exports.detectKeyType = exports.detectCertAlg = exports.notEmpty = exports.castArrayOpt = exports.isNonEmptyArray = exports.readPrivateKey = exports.inflateString = exports.base64Decode = exports.isString = exports.get = exports.uniq = exports.last = exports.flattenDeep = exports.zipObject = void 0;
/**
* @file utility.ts
* @author tngan
* @desc  Library for some common functions (e.g. de/inflation, en/decoding)
*/
var node_forge_1 = require("node-forge");
var x509 = __importStar(require("@peculiar/x509"));
var webcrypto = __importStar(require("@peculiar/webcrypto"));
var pako_1 = require("pako");
var asn1_schema_1 = require("@peculiar/asn1-schema");
var asn1_pkcs8_1 = require("@peculiar/asn1-pkcs8");
var asn1_rsa_1 = require("@peculiar/asn1-rsa");
var asn1_ecc_1 = require("@peculiar/asn1-ecc");
var urn_1 = require("./urn");
var crypto = new webcrypto.Crypto();
var BASE64_STR = 'base64';
/**
 * @desc Mimic lodash.zipObject
 * @param arr1 {string[]}
 * @param arr2 {[]}
 */
function zipObject(arr1, arr2, skipDuplicated) {
    if (skipDuplicated === void 0) { skipDuplicated = true; }
    return arr1.reduce(function (res, l, i) {
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
exports.zipObject = zipObject;
/**
 * @desc Alternative to lodash.flattenDeep
 * @reference https://github.com/you-dont-need/You-Dont-Need-Lodash-Underscore#_flattendeep
 * @param input {[]}
 */
function flattenDeep(input) {
    return Array.isArray(input)
        ? input.reduce(function (a, b) { return a.concat(flattenDeep(b)); }, [])
        : [input];
}
exports.flattenDeep = flattenDeep;
/**
 * @desc Alternative to lodash.last
 * @reference https://github.com/you-dont-need/You-Dont-Need-Lodash-Underscore#_last
 * @param input {[]}
 */
function last(input) {
    return input.slice(-1)[0];
}
exports.last = last;
/**
 * @desc Alternative to lodash.uniq
 * @reference https://github.com/you-dont-need/You-Dont-Need-Lodash-Underscore#_uniq
 * @param input {string[]}
 */
function uniq(input) {
    var set = new Set(input);
    return __spreadArray([], __read(set), false);
}
exports.uniq = uniq;
/**
 * @desc Alternative to lodash.get
 * @reference https://github.com/you-dont-need/You-Dont-Need-Lodash-Underscore#_get
 * @param obj
 * @param path
 * @param defaultValue
 */
function get(obj, path, defaultValue) {
    return path.split('.')
        .reduce(function (a, c) { return (a && a[c] ? a[c] : (defaultValue || null)); }, obj);
}
exports.get = get;
/**
 * @desc Check if the input is string
 * @param {any} input
 */
function isString(input) {
    return typeof input === 'string';
}
exports.isString = isString;
/**
* @desc Encode string with base64 format
* @param  {string} message                       plain-text message
* @return {string} base64 encoded string
*/
function base64Encode(message) {
    return Buffer.from(message).toString(BASE64_STR);
}
/**
* @desc Decode string from base64 format
* @param  {string} base64Message                 encoded string
* @param  {boolean} isBytes                      determine the return value type (True: bytes False: string)
* @return {bytes/string}  decoded bytes/string depends on isBytes, default is {string}
*/
function base64Decode(base64Message, isBytes) {
    var bytes = Buffer.from(base64Message, BASE64_STR);
    return Boolean(isBytes) ? bytes : bytes.toString();
}
exports.base64Decode = base64Decode;
/**
* @desc Compress the string
* @param  {string} message
* @return {string} compressed string
*/
function deflateString(message) {
    var input = Array.prototype.map.call(message, function (char) { return char.charCodeAt(0); });
    return Array.from((0, pako_1.deflate)(input, { raw: true }));
}
/**
* @desc Decompress the compressed string
* @param  {string} compressedString
* @return {string} decompressed string
*/
function inflateString(compressedString) {
    var inputBuffer = Buffer.from(compressedString, BASE64_STR);
    var input = Array.prototype.map.call(inputBuffer.toString('binary'), function (char) { return char.charCodeAt(0); });
    return Array.from((0, pako_1.inflate)(input, { raw: true }))
        .map(function (byte) { return String.fromCharCode(byte); })
        .join('');
}
exports.inflateString = inflateString;
/**
* @desc Abstract the normalizeCerString and normalizePemString
* @param {buffer} File stream or string
* @param {string} String for header and tail
* @return {string} A formatted certificate string
*/
function _normalizeCerString(bin, format) {
    return bin.toString().replace(/\n/g, '').replace(/\r/g, '').replace("-----BEGIN ".concat(format, "-----"), '').replace("-----END ".concat(format, "-----"), '').replace(/ /g, '').replace(/\t/g, '');
}
/**
* @desc Parse the .cer to string format without line break, header and footer
* @param  {string} certString     declares the certificate contents
* @return {string} certificiate in string format
*/
function normalizeCerString(certString) {
    return _normalizeCerString(certString, 'CERTIFICATE');
}
/**
* @desc Normalize the string in .pem format without line break, header and footer
* @param  {string} pemString
* @return {string} private key in string format
*/
function normalizePemString(pemString) {
    return _normalizeCerString(pemString.toString(), 'RSA PRIVATE KEY');
}
/**
* @desc Return the complete URL
* @param  {object} req                   HTTP request
* @return {string} URL
*/
function getFullURL(req) {
    return "".concat(req.protocol, "://").concat(req.get('host')).concat(req.originalUrl);
}
/**
* @desc Parse input string, return default value if it is undefined
* @param  {string/boolean}
* @return {boolean}
*/
function parseString(str, defaultValue) {
    if (defaultValue === void 0) { defaultValue = ''; }
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
function getPublicKeyPemFromCertificate(x509Certificate) {
    var _a, _b;
    // Try using @peculiar/x509 first which supports both RSA and EC
    try {
        // Wrap the certificate in PEM format
        var pem = "-----BEGIN CERTIFICATE-----\n".concat((_a = x509Certificate.match(/.{1,64}/g)) === null || _a === void 0 ? void 0 : _a.join('\n'), "\n-----END CERTIFICATE-----");
        var cert = new x509.X509Certificate(pem);
        // Export public key in PEM format
        var publicKeyDer = cert.publicKey.rawData;
        var publicKeyBase64 = Buffer.from(publicKeyDer).toString('base64');
        var publicKeyPem = "-----BEGIN PUBLIC KEY-----\n".concat((_b = publicKeyBase64.match(/.{1,64}/g)) === null || _b === void 0 ? void 0 : _b.join('\n'), "\n-----END PUBLIC KEY-----");
        return publicKeyPem;
    }
    catch (e) {
        // Fallback to node-forge for RSA certificates (legacy support)
        try {
            var certDerBytes = node_forge_1.util.decode64(x509Certificate);
            var obj = node_forge_1.asn1.fromDer(certDerBytes);
            var cert = node_forge_1.pki.certificateFromAsn1(obj);
            return node_forge_1.pki.publicKeyToPem(cert.publicKey);
        }
        catch (forgeError) {
            throw new Error("Failed to extract public key from certificate: ".concat(e.message));
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
function readPrivateKey(keyString, passphrase, isOutputString) {
    if (!isString(passphrase)) {
        return keyString;
    }
    var keyStr = String(keyString);
    // For encrypted PKCS#8, use Node.js crypto which supports both RSA and EC
    if (keyStr.includes('BEGIN ENCRYPTED PRIVATE KEY')) {
        // Node.js crypto can decrypt and re-export encrypted PKCS#8 keys
        var nodeCrypto = require('crypto');
        var keyObject = nodeCrypto.createPrivateKey({
            key: keyStr,
            format: 'pem',
            passphrase: passphrase
        });
        // Export as unencrypted PKCS#8 PEM
        var decryptedPem = keyObject.export({
            type: 'pkcs8',
            format: 'pem'
        });
        return this.convertToString(decryptedPem, isOutputString);
    }
    // For legacy encrypted formats (e.g., BEGIN RSA PRIVATE KEY with encryption)
    return this.convertToString(node_forge_1.pki.privateKeyToPem(node_forge_1.pki.decryptRsaPrivateKey(keyStr, passphrase)), isOutputString);
}
exports.readPrivateKey = readPrivateKey;
/**
* @desc Inline syntax sugar
*/
function convertToString(input, isOutputString) {
    return Boolean(isOutputString) ? String(input) : input;
}
/**
 * @desc Check if the input is an array with non-zero size
 */
function isNonEmptyArray(a) {
    return Array.isArray(a) && a.length > 0;
}
exports.isNonEmptyArray = isNonEmptyArray;
function castArrayOpt(a) {
    if (a === undefined)
        return [];
    return Array.isArray(a) ? a : [a];
}
exports.castArrayOpt = castArrayOpt;
function notEmpty(value) {
    return value !== null && value !== undefined;
}
exports.notEmpty = notEmpty;
function detectCertAlg(cert) {
    if (!cert) {
        return null;
    }
    try {
        var parsedCert = new x509.X509Certificate(cert);
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
    }
    catch (Error) {
        return null;
    }
}
exports.detectCertAlg = detectCertAlg;
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
function detectKeyType(keyOrCert) {
    if (!keyOrCert) {
        throw new Error('Key or certificate is required for key type detection');
    }
    // Convert Buffer to string if needed
    var keyString = Buffer.isBuffer(keyOrCert) ? keyOrCert.toString('utf8') : keyOrCert;
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
            var pemContent = keyString
                .replace(/-----BEGIN [^-]+-----/, '')
                .replace(/-----END [^-]+-----/, '')
                .replace(/\s+/g, '');
            var der = Buffer.from(pemContent, 'base64');
            var privateKeyInfo = asn1_schema_1.AsnParser.parse(der, asn1_pkcs8_1.PrivateKeyInfo);
            var algorithm = privateKeyInfo.privateKeyAlgorithm.algorithm;
            // Check against standard OIDs
            if (algorithm === asn1_ecc_1.id_ecPublicKey) {
                return 'EC';
            }
            if (algorithm === asn1_rsa_1.id_rsaEncryption) {
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
            throw new Error("Unsupported key algorithm OID: ".concat(algorithm, ". ") +
                "Expected RSA (1.2.840.113549.1.1.*) or EC (1.2.840.10045.*)");
        }
        catch (e) {
            if (e instanceof Error && e.message.includes('Unsupported key algorithm')) {
                throw e; // Re-throw our custom errors
            }
            throw new Error("Failed to parse PKCS#8 private key: ".concat(e instanceof Error ? e.message : String(e), ". ") +
                "Ensure the key is valid PEM-encoded PKCS#8 format.");
        }
    }
    // Strategy 3: X.509 Certificate - Use existing @peculiar/x509 dependency
    if (keyString.includes('CERTIFICATE')) {
        try {
            // Remove PEM headers/footers and whitespace
            var pemContent = keyString
                .replace(/-----BEGIN [^-]+-----/, '')
                .replace(/-----END [^-]+-----/, '')
                .replace(/\s+/g, '');
            var der = Buffer.from(pemContent, 'base64');
            // Convert Buffer to Uint8Array for x509 library
            var uint8Array = new Uint8Array(der);
            var cert = new x509.X509Certificate(uint8Array);
            var algorithm = cert.publicKey.algorithm.name;
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
            throw new Error("Unsupported certificate algorithm: ".concat(algorithm, ". ") +
                "Expected RSA or EC-based algorithm.");
        }
        catch (e) {
            if (e instanceof Error && e.message.includes('Unsupported certificate algorithm')) {
                throw e; // Re-throw our custom errors
            }
            throw new Error("Failed to parse X.509 certificate: ".concat(e instanceof Error ? e.message : String(e), ". ") +
                "Ensure the certificate is valid PEM-encoded X.509 format.");
        }
    }
    // Encrypted PKCS#8 - Cannot reliably detect without decrypting
    // The encryption wrapper hides the algorithm identifier
    if (keyString.includes('ENCRYPTED PRIVATE KEY')) {
        throw new Error('Encrypted PKCS#8 private keys cannot be inspected without decryption. ' +
            'The key algorithm is encrypted within the PKCS#8 structure. ' +
            'Please decrypt the key first or use key type detection after decryption.');
    }
    // Unknown key format
    throw new Error('Unable to detect key type: unrecognized key format. ' +
        'Supported formats: SEC1 (EC PRIVATE KEY), PKCS#1 (RSA PRIVATE KEY), ' +
        'PKCS#8 (PRIVATE KEY), X.509 (CERTIFICATE)');
}
exports.detectKeyType = detectKeyType;
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
function normalizeSignatureAlgorithm(algorithm, keyType) {
    var signatureAlgorithms = urn_1.algorithms.signature;
    // If no algorithm specified, return undefined (let caller handle default)
    if (!algorithm) {
        return undefined;
    }
    // Convert RSA to ECDSA if key is EC
    if (keyType === 'EC' && algorithm.toLowerCase().includes('rsa')) {
        if (algorithm.toLowerCase().includes('sha512')) {
            return signatureAlgorithms.ECDSA_SHA512;
        }
        else if (algorithm.toLowerCase().includes('sha384')) {
            return signatureAlgorithms.ECDSA_SHA384;
        }
        else if (algorithm.toLowerCase().includes('sha1')) {
            return signatureAlgorithms.ECDSA_SHA1;
        }
        else {
            // Default to SHA256 for any other SHA variant or unrecognized
            return signatureAlgorithms.ECDSA_SHA256;
        }
    }
    // Return algorithm as-is if no conversion needed
    return algorithm;
}
exports.normalizeSignatureAlgorithm = normalizeSignatureAlgorithm;
/**
 * @desc Convert PEM-encoded key to DER format (for WebCrypto importKey)
 * @param pem {string} PEM-encoded key (with BEGIN/END headers)
 * @return {Buffer} DER-encoded key as Buffer
 */
function pemToDer(pem) {
    // Remove PEM headers and decode base64
    var pemContent = pem
        .replace(/-----BEGIN [A-Z ]+-----/, '')
        .replace(/-----END [A-Z ]+-----/, '')
        .replace(/\s+/g, '');
    return Buffer.from(pemContent, 'base64');
}
exports.pemToDer = pemToDer;
/**
 * @desc Convert ECDSA signature from DER format to IEEE P1363 format (raw r|s)
 * Node.js crypto.sign() produces DER format, but XML signatures require IEEE P1363
 * @param derSignature {Buffer} DER-encoded signature
 * @return {Buffer} IEEE P1363 encoded signature (raw r||s concatenation)
 */
function derToP1363(derSignature) {
    // DER format: 0x30 <total-length> 0x02 <r-length> <r-value> 0x02 <s-length> <s-value>
    if (derSignature.length < 8) {
        throw new Error('DER signature too short');
    }
    if (derSignature[0] !== 0x30) {
        throw new Error('Invalid DER signature - missing SEQUENCE marker');
    }
    var offset = 2; // Skip SEQUENCE marker and length
    // Read r value
    if (derSignature[offset] !== 0x02) {
        throw new Error('Invalid DER signature - missing INTEGER marker for r');
    }
    offset++;
    var rLength = derSignature[offset];
    offset++;
    var r = derSignature.subarray(offset, offset + rLength);
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
    var sLength = derSignature[offset];
    offset++;
    var s = derSignature.subarray(offset, offset + sLength);
    // Remove leading 0x00 byte if present
    if (s[0] === 0x00 && s.length > 1) {
        s = s.subarray(1);
    }
    // Determine the field size (r and s should be the same length in P1363)
    var fieldSize = Math.max(r.length, s.length);
    // Pad r and s to field size
    var rPadded = Buffer.alloc(fieldSize);
    r.copy(rPadded, fieldSize - r.length);
    var sPadded = Buffer.alloc(fieldSize);
    s.copy(sPadded, fieldSize - s.length);
    // Concatenate r || s
    return Buffer.concat([rPadded, sPadded]);
}
exports.derToP1363 = derToP1363;
/**
 * @desc Convert ECDSA signature from IEEE P1363 format to DER format
 * WebCrypto and XML signatures use P1363, but Node.js crypto.verify() expects DER
 * @param p1363Signature {Buffer} IEEE P1363 encoded signature (raw r||s)
 * @return {Buffer} DER-encoded signature
 */
function p1363ToDer(p1363Signature) {
    // P1363 format is r || s concatenated, each component is the same length
    var componentLength = p1363Signature.length / 2;
    var r = p1363Signature.subarray(0, componentLength);
    var s = p1363Signature.subarray(componentLength);
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
    var derLength = 2 + r.length + 2 + s.length; // 2 bytes for each INTEGER marker+length
    var der = Buffer.alloc(2 + derLength);
    var offset = 0;
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
exports.p1363ToDer = p1363ToDer;
var utility = {
    isString: isString,
    base64Encode: base64Encode,
    base64Decode: base64Decode,
    deflateString: deflateString,
    inflateString: inflateString,
    normalizeCerString: normalizeCerString,
    normalizePemString: normalizePemString,
    getFullURL: getFullURL,
    parseString: parseString,
    applyDefault: applyDefault,
    getPublicKeyPemFromCertificate: getPublicKeyPemFromCertificate,
    readPrivateKey: readPrivateKey,
    convertToString: convertToString,
    isNonEmptyArray: isNonEmptyArray,
    detectKeyType: detectKeyType,
    normalizeSignatureAlgorithm: normalizeSignatureAlgorithm,
    pemToDer: pemToDer,
    derToP1363: derToP1363,
    p1363ToDer: p1363ToDer,
};
exports.default = utility;
//# sourceMappingURL=utility.js.map