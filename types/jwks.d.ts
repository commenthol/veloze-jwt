/**
 * @typedef {import('./jwtAuth.js').GetKeyLikeFn} GetKeyLikeFn
 */
/**
 * @typedef {object} JwksOptions
 * @property {fetch} [fetcher=fetch]
 * @property {Number} [expiresIn=3e5] expiry in ms
 * @property {Record<string, string>} [jwksByIssuer] jwksUri by issuer
 * @property {Record<string, string|Uint8Array>} [secretsByIssuer] secret or publicKey by issuer
 */
/**
 * @param {string[]} issuers issuer uris
 * @param {JwksOptions} options
 * @returns {Promise<GetKeyLikeFn>}
 */
export function jwks(issuers: string[], options: JwksOptions): Promise<GetKeyLikeFn>;
export type GetKeyLikeFn = import("./jwtAuth.js").GetKeyLikeFn;
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
