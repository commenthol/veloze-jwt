/**
 * @typedef {object} JwksOptions
 * @property {fetch} [fetcher=fetch]
 * @property {Number} [expiresIn=3e5] expiry in ms
 * @property {Record<string, string>} [jwksByIssuer] jwksUri by issuer
 * @property {Record<string, string|Uint8Array>} [secretsByIssuer] secret or publicKey by issuer
 */
/** @typedef {import('./decodeJwt.js').DecodedJWT} DecodedJWT */
/** @typedef {Uint8Array|jose.CryptoKey} KeyLike */
/** @typedef {(decodedToken: DecodedJWT) => Promise<KeyLike|undefined>} GetKeyLikeFn */
/**
 * @param {string[]} issuers issuer uris
 * @param {JwksOptions} options
 * @returns {Promise<GetKeyLikeFn>}
 */
export function jwks(issuers: string[], options: JwksOptions): Promise<GetKeyLikeFn>;
export type JwksOptions = {
    fetcher?: typeof fetch | undefined;
    /**
     * expiry in ms
     */
    expiresIn?: number | undefined;
    /**
     * jwksUri by issuer
     */
    jwksByIssuer?: Record<string, string> | undefined;
    /**
     * secret or publicKey by issuer
     */
    secretsByIssuer?: Record<string, string | Uint8Array<ArrayBufferLike>> | undefined;
};
export type DecodedJWT = import("./decodeJwt.js").DecodedJWT;
export type KeyLike = Uint8Array | jose.CryptoKey;
export type GetKeyLikeFn = (decodedToken: DecodedJWT) => Promise<KeyLike | undefined>;
import * as jose from 'jose';
