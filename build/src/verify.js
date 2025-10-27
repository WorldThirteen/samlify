"use strict";
var __assign = (this && this.__assign) || function () {
    __assign = Object.assign || function(t) {
        for (var s, i = 1, n = arguments.length; i < n; i++) {
            s = arguments[i];
            for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p))
                t[p] = s[p];
        }
        return t;
    };
    return __assign.apply(this, arguments);
};
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (g && (g = 0, op[0] && (_ = 0)), _) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.verifyMessageSignature = void 0;
var webcrypto_1 = require("@peculiar/webcrypto");
var x509_1 = require("@peculiar/x509");
var certUse = { signing: "signing" };
// Initialize Peculiar WebCrypto once
var crypto = new webcrypto_1.Crypto();
function toPemOrDer(input) {
    // If it already looks like PEM, return as is; otherwise wrap base64 as PEM.
    if (/-----BEGIN CERTIFICATE-----/.test(input))
        return input;
    var b64 = input.replace(/\s+/g, "");
    var wrapped = b64.replace(/(.{64})/g, "$1\n");
    return "-----BEGIN CERTIFICATE-----\n".concat(wrapped, "\n-----END CERTIFICATE-----");
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
function normalizeSig(sig, algo) {
    var buffer;
    if (Buffer.isBuffer(sig)) {
        buffer = sig;
    }
    else {
        buffer = Buffer.from(sig);
    }
    // Return buffer as ArrayBuffer for WebCrypto
    return buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength);
}
function encodeOctets(s) {
    // HTTP-Redirect binding signs the ASCII/UTF-8 octet string of the query (exact bytes).
    return new TextEncoder().encode(s).buffer;
}
function resolveVerifyAlgorithm(algo) {
    var _a;
    var a = (algo !== null && algo !== void 0 ? algo : "").toLowerCase();
    // Common XML DSig URIs & aliases
    var map = {
        // RSA
        "http://www.w3.org/2000/09/xmldsig#rsa-sha1": { name: "RSASSA-PKCS1-v1_5", hash: "SHA-1" },
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256": { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384": { name: "RSASSA-PKCS1-v1_5", hash: "SHA-384" },
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512": { name: "RSASSA-PKCS1-v1_5", hash: "SHA-512" },
        "rsa-sha1": { name: "RSASSA-PKCS1-v1_5", hash: "SHA-1" },
        "rsa-sha256": { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
        "rsa-sha384": { name: "RSASSA-PKCS1-v1_5", hash: "SHA-384" },
        "rsa-sha512": { name: "RSASSA-PKCS1-v1_5", hash: "SHA-512" },
        "sha1withrsa": { name: "RSASSA-PKCS1-v1_5", hash: "SHA-1" },
        "sha256withrsa": { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
        "sha384withrsa": { name: "RSASSA-PKCS1-v1_5", hash: "SHA-384" },
        "sha512withrsa": { name: "RSASSA-PKCS1-v1_5", hash: "SHA-512" },
        // ECDSA
        "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1": { name: "ECDSA", hash: "SHA-1" },
        "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256": { name: "ECDSA", hash: "SHA-256" },
        "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384": { name: "ECDSA", hash: "SHA-384" },
        "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512": { name: "ECDSA", hash: "SHA-512" },
        "ecdsa-sha1": { name: "ECDSA", hash: "SHA-1" },
        "ecdsa-sha256": { name: "ECDSA", hash: "SHA-256" },
        "ecdsa-sha384": { name: "ECDSA", hash: "SHA-384" },
        "ecdsa-sha512": { name: "ECDSA", hash: "SHA-512" },
    };
    // Default to RSA SHA-1 if unspecified (backward compatible with master branch)
    return (_a = map[a]) !== null && _a !== void 0 ? _a : { name: "RSASSA-PKCS1-v1_5", hash: "SHA-1" };
}
/**
 * @desc Verifies message signature (HTTP-Redirect binding friendly)
 * @param  {Metadata} metadata
 * @param  {string}   octetString
 * @param  {string|Buffer} signature
 * @param  {string}   verifyAlgorithm     (URI or alias, e.g., rsa-sha256)
 * @return {Promise<boolean>}
 */
function verifyMessageSignature(metadata, octetString, signature, verifyAlgorithm) {
    var _a;
    return __awaiter(this, void 0, void 0, function () {
        var signCertRaw, pem, cert, algo, peculiarKey, rawKey, importAlgo, key, ok, err_1;
        return __generator(this, function (_b) {
            switch (_b.label) {
                case 0:
                    _b.trys.push([0, 5, , 6]);
                    signCertRaw = metadata.getX509Certificate(certUse.signing);
                    if (!signCertRaw)
                        return [2 /*return*/, false];
                    pem = toPemOrDer(signCertRaw);
                    cert = new x509_1.X509Certificate(pem);
                    algo = resolveVerifyAlgorithm(verifyAlgorithm !== null && verifyAlgorithm !== void 0 ? verifyAlgorithm : (_a = metadata.getSignatureAlgorithm) === null || _a === void 0 ? void 0 : _a.call(metadata));
                    return [4 /*yield*/, cert.publicKey.export(crypto)];
                case 1:
                    peculiarKey = _b.sent();
                    return [4 /*yield*/, crypto.subtle.exportKey('spki', peculiarKey)];
                case 2:
                    rawKey = _b.sent();
                    importAlgo = algo;
                    if (algo.name === 'ECDSA' && peculiarKey.algorithm && 'namedCurve' in peculiarKey.algorithm) {
                        importAlgo = __assign(__assign({}, algo), { namedCurve: peculiarKey.algorithm.namedCurve });
                    }
                    return [4 /*yield*/, crypto.subtle.importKey('spki', rawKey, importAlgo, // This includes the correct hash algorithm (and namedCurve for ECDSA)
                        false, ['verify'])];
                case 3:
                    key = _b.sent();
                    return [4 /*yield*/, crypto.subtle.verify(algo, // includes { name, hash }
                        key, normalizeSig(signature, algo), // signature (IEEE P1363 for ECDSA, raw for RSA)
                        encodeOctets(octetString) // data exactly as signed
                        )];
                case 4:
                    ok = _b.sent();
                    return [2 /*return*/, !!ok];
                case 5:
                    err_1 = _b.sent();
                    return [2 /*return*/, false];
                case 6: return [2 /*return*/];
            }
        });
    });
}
exports.verifyMessageSignature = verifyMessageSignature;
//# sourceMappingURL=verify.js.map