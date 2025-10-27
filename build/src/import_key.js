// import { Crypto } from "@peculiar/webcrypto";
// import { AsnParser, AsnSerializer } from "@peculiar/asn1-schema";
// import {
//   EncryptedPrivateKeyInfo,
//   PrivateKeyInfo,
// } from "@peculiar/asn1-pkcs8";
// import {
//   PBES2Params,
//   PBKDF2Params,
// } from "@peculiar/asn1-pbe"; // if your version exports from pbe; otherwise from pkcs8
// import { ECPrivateKey } from "@peculiar/asn1-ecc";
// const crypto = new Crypto();
// (globalThis as any).crypto = crypto;
// // --- utils ---
// const TEXT_ENCODER = new TextEncoder();
// const OID = {
//   idEcPublicKey: "1.2.840.10045.2.1",
//   // Curves
//   P256: "1.2.840.10045.3.1.7",
//   P384: "1.3.132.0.34",
//   P521: "1.3.132.0.35",
//   // PBES2 / PBKDF2
//   PBES2: "1.2.840.113549.1.5.13",
//   PBKDF2: "1.2.840.113549.1.5.12",
//   // AES-CBC
//   AES128_CBC: "2.16.840.1.101.3.4.1.2",
//   AES192_CBC: "2.16.840.1.101.3.4.1.22",
//   AES256_CBC: "2.16.840.1.101.3.4.1.42",
// };
// function pemSection(pem: string, label: string): string | null {
//   const m = new RegExp(`-----BEGIN ${label}-----([\\s\\S]*?)-----END ${label}-----`).exec(pem);
//   return m ? m[1].replace(/\s+/g, "") : null;
// }
// function derFromPem(pem: string, label: string): Uint8Array {
//   const b64 = pemSection(pem, label);
//   if (!b64) throw new Error(`Missing ${label} section`);
//   return Uint8Array.from(Buffer.from(b64, "base64"));
// }
// function curveNameFromOid(oid: string): "P-256"|"P-384"|"P-521"|undefined {
//   switch (oid) {
//     case OID.P256: return "P-256";
//     case OID.P384: return "P-384";
//     case OID.P521: return "P-521";
//     default: return;
//   }
// }
// async function decryptPkcs8Pem(encryptedPem: string, password: string): Promise<ArrayBuffer> {
//   const der = derFromPem(encryptedPem, "ENCRYPTED PRIVATE KEY");
//   const epki = AsnParser.parse(der, EncryptedPrivateKeyInfo);
//   // Parse PBES2 params
//   if (epki.encryptionAlgorithm.algorithm !== OID.PBES2) {
//     throw new Error("Unsupported encryption scheme (expect PBES2)");
//   }
//   const pbes2 = AsnParser.parse(epki.encryptionAlgorithm.parameters!, PBES2Params);
//   // PBKDF2 params
//   if (pbes2.keyDerivationFunc.algorithm !== OID.PBKDF2) {
//     throw new Error("Unsupported KDF (expect PBKDF2)");
//   }
//   const pbkdf2 = AsnParser.parse(pbes2.keyDerivationFunc.parameters!, PBKDF2Params);
//   // Cipher & IV
//   const cipherOid = pbes2.encryptionScheme.algorithm;
//   const iv = new Uint8Array(AsnParser.parse(pbes2.encryptionScheme.parameters!, /* OCTET STRING */ Uint8Array));
//   const keyLen = (
//     cipherOid === OID.AES128_CBC ? 16 :
//     cipherOid === OID.AES192_CBC ? 24 :
//     cipherOid === OID.AES256_CBC ? 32 : 0
//   );
//   if (!keyLen) throw new Error(`Unsupported cipher OID: ${cipherOid}`);
//   const hash = pbkdf2.prf?.algorithm?.endsWith("2.1.5") ? "SHA-512"
//             : pbkdf2.prf?.algorithm?.endsWith("2.1.4") ? "SHA-384"
//             : pbkdf2.prf?.algorithm?.endsWith("2.1.3") ? "SHA-256"
//             : "SHA-1"; // default per RFC if PRF omitted
//   const salt = new Uint8Array(pbkdf2.salt.valueBlock.valueHex ?? pbkdf2.salt as any); // compatible with different asn1 models
//   const iterations = Number(pbkdf2.iterationCount);
//   // Derive key with PBKDF2
//   const baseKey = await crypto.subtle.importKey(
//     "raw",
//     TEXT_ENCODER.encode(password),
//     "PBKDF2",
//     false,
//     ["deriveBits"]
//   );
//   const bits = await crypto.subtle.deriveBits(
//     { name: "PBKDF2", salt, iterations, hash },
//     baseKey,
//     keyLen * 8
//   );
//   const encKey = await crypto.subtle.importKey(
//     "raw",
//     bits,
//     { name: "AES-CBC" },
//     false,
//     ["decrypt"]
//   );
//   // Decrypt to plaintext PKCS#8
//   const plaintext = await crypto.subtle.decrypt(
//     { name: "AES-CBC", iv },
//     encKey,
//     epki.encryptedData
//   );
//   return plaintext; // DER-encoded PrivateKeyInfo
// }
// // Reuse your Option A: wrap SEC1 → PKCS#8 and import.
// // Here: if we already decrypted PKCS#8, just import.
// async function importPkcs8Bytes(derPkcs8: ArrayBuffer): Promise<CryptoKey> {
//   // We still parse to detect EC vs RSA & set params
//   const pki = AsnParser.parse(derPkcs8, PrivateKeyInfo);
//   if (pki.privateKeyAlgorithm.algorithm === "1.2.840.10045.2.1") {
//     // EC
//     // figure out the curve OID from parameters
//     const paramsAny = pki.privateKeyAlgorithm.parameters!;
//     // A minimal way: serialize and parse as an OID
//     const paramsBytes = new Uint8Array(paramsAny.valueBlock ? paramsAny.valueBlock.valueHex : AsnSerializer.serialize(paramsAny));
//     // crude OID decode via known curve matches; in production use a proper OID parser
//     const oidStr = Buffer.from(paramsBytes).toString("hex").includes("2a8648ce3d030107")
//       ? OID.P256
//       : Buffer.from(paramsBytes).toString("hex").includes("2b81040022")
//         ? OID.P384
//         : Buffer.from(paramsBytes).toString("hex").includes("2b81040023")
//           ? OID.P521
//           : "";
//     const namedCurve = curveNameFromOid(oidStr);
//     if (!namedCurve) throw new Error("Unsupported/unknown EC curve");
//     return crypto.subtle.importKey(
//       "pkcs8",
//       derPkcs8,
//       { name: "ECDSA", namedCurve },
//       true,
//       ["sign"]
//     );
//   } else if (pki.privateKeyAlgorithm.algorithm === "1.2.840.113549.1.1.1") {
//     // RSA
//     return crypto.subtle.importKey(
//       "pkcs8",
//       derPkcs8,
//       { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
//       true,
//       ["sign"]
//     );
//   }
//   throw new Error("Unsupported key algorithm in PKCS#8");
// }
// // Convenience: decrypt PEM (if needed) then import
// export async function importEncryptedPkcs8Pem(pem: string, password: string): Promise<CryptoKey> {
//   const hasEncrypted = /-----BEGIN ENCRYPTED PRIVATE KEY-----/.test(pem);
//   const der = hasEncrypted ? await decryptPkcs8Pem(pem, password)
//                            : derFromPem(pem, "PRIVATE KEY").buffer; // already plaintext PKCS#8
//   return importPkcs8Bytes(der);
// }
//# sourceMappingURL=import_key.js.map