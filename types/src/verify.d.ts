/// <reference types="node" />
type Metadata = {
    getX509Certificate: (use: string) => string;
    getSignatureAlgorithm?: () => string | undefined;
};
/**
 * @desc Verifies message signature (HTTP-Redirect binding friendly)
 * @param  {Metadata} metadata
 * @param  {string}   octetString
 * @param  {string|Buffer} signature
 * @param  {string}   verifyAlgorithm     (URI or alias, e.g., rsa-sha256)
 * @return {Promise<boolean>}
 */
export declare function verifyMessageSignature(metadata: Metadata, octetString: string, signature: string | Buffer, verifyAlgorithm?: string): Promise<boolean>;
export {};
