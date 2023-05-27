/**
 * @typedef {import('veloze/types').Request} Request
 * @typedef {import('veloze/types').Response} Response
 * @typedef {import('veloze/types').Handler} Handler
 * @typedef {import('jose').JWTVerifyOptions} JWTVerifyOptions
 * @typedef {import('jose').KeyLike} KeyLike
 * @typedef {import('./decodeJwt.js').DecodedJWT} DecodedJWT
 *
 * @typedef {object & JWTVerifyOptions} JwtOptions
 * @property {string|Buffer|KeyLike|GetKeyLikeFn} secret
 * @property {string} [requestProperty='auth']
 *
 * @typedef {(decodedToken: DecodedJWT, req: Request) => Promise<KeyLike>} GetKeyLikeFn
 */
/**
 * @param {JwtOptions} options
 * @returns {Handler}
 */
export function jwtAuth(options: JwtOptions): Handler;
export type Request = import('veloze/types').Request;
export type Response = import('veloze/types').Response;
export type Handler = import('veloze/types').Handler;
export type JWTVerifyOptions = import('jose').JWTVerifyOptions;
export type KeyLike = import('jose').KeyLike;
export type DecodedJWT = import('./decodeJwt.js').DecodedJWT;
export type JwtOptions = object & JWTVerifyOptions;
export type GetKeyLikeFn = (decodedToken: DecodedJWT, req: Request) => Promise<KeyLike>;
