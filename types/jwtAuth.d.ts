/** @typedef {import('veloze').Request} Request */
/** @typedef {import('veloze').Response} Response */
/** @typedef {import('veloze').Handler} Handler */
/** @typedef {import('jose').JWTVerifyOptions} JWTVerifyOptions */
/** @typedef {import('./decodeJwt.js').DecodedJWT} DecodedJWT */
/** @typedef {import('./jwks.js').KeyLike} KeyLike */
/** @typedef {import('./jwks.js').GetKeyLikeFn} GetKeyLikeFn */
/**
 * @typedef {object} JwtAuth
 * @property {string|Uint8Array|GetKeyLikeFn} secret
 * @property {string} [requestProperty='auth'] property on the request object to set the decoded JWT payload on
 */
/** @typedef {JwtAuth & JWTVerifyOptions} JwtOptions*/
/**
 * @throws {HttpError} throws validation errors as HttpError(401)
 * @param {JwtOptions} options
 * @returns {Handler}
 */
export function jwtAuth(options: JwtOptions): Handler;
/**
 * does not throw on errors, just passes. If valid token was found, sets
 * req[requestProperty]
 * @param {JwtOptions} options
 * @returns {Handler}
 */
export function jwtAuthPass(options: JwtOptions): Handler;
export type Request = import("veloze").Request;
export type Response = import("veloze").Response;
export type Handler = import("veloze").Handler;
export type JWTVerifyOptions = import("jose").JWTVerifyOptions;
export type DecodedJWT = import("./decodeJwt.js").DecodedJWT;
export type KeyLike = import("./jwks.js").KeyLike;
export type GetKeyLikeFn = import("./jwks.js").GetKeyLikeFn;
export type JwtAuth = {
    secret: string | Uint8Array | GetKeyLikeFn;
    /**
     * property on the request object to set the decoded JWT payload on
     */
    requestProperty?: string | undefined;
};
export type JwtOptions = JwtAuth & JWTVerifyOptions;
