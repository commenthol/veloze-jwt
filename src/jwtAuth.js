import * as jose from 'jose'
import { HttpError } from 'veloze/src/HttpError.js'
import { decodeJwt } from './decodeJwt.js'

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
export function jwtAuth(options) {
  const { secret, requestProperty = 'auth', ...verifyOptions } = options || {}

  if (!secret) throw new TypeError('need secret')

  const _secret =
    typeof secret === 'string' ? new TextEncoder().encode(secret) : secret

  const getKey = typeof secret === 'function' ? secret : async () => _secret

  return async function _jwtAuth(req, _res) {
    req[requestProperty] = undefined
    const { authorization } = req.headers
    if (!authorization) {
      throw new HttpError(401)
    }
    const [type, token] = String(authorization).split(' ', 2)
    if (type !== 'Bearer') {
      throw new HttpError(401, 'Bearer token authorization expected')
    }
    if (!token) {
      throw new HttpError(401, 'No bearer token found')
    }
    /** @type {DecodedJWT} */
    let decodedToken
    let key

    try {
      decodedToken = decodeJwt(token)
      key = await getKey(decodedToken)
    } catch (/** @type {Error|any} */ err) {
      throw new HttpError(401, 'Invalid Token', err)
    }

    if (!key) {
      throw new HttpError(401)
    }

    try {
      // @ts-expect-error
      const decoded = await jose.jwtVerify(token, key, verifyOptions)
      req[requestProperty] = decoded.payload
    } catch (/** @type {Error|any} */ err) {
      throw new HttpError(401, 'Invalid Token', err)
    }

    await immediate()
  }
}

/**
 * does not throw on errors, just passes. If valid token was found, sets
 * req[requestProperty]
 * @param {JwtOptions} options
 * @returns {Handler}
 */
export function jwtAuthPass(options) {
  const { secret, requestProperty = 'auth', ...verifyOptions } = options || {}

  if (!secret) throw new TypeError('need secret')

  const _secret =
    typeof secret === 'string' ? new TextEncoder().encode(secret) : secret

  const getKey = typeof secret === 'function' ? secret : async () => _secret

  return async function _jwtAuthPass(req, _res) {
    req[requestProperty] = undefined
    const { authorization } = req.headers
    if (!authorization) {
      return
    }
    const [type, token] = String(authorization).split(' ', 2)
    if (type !== 'Bearer' || !token) {
      return
    }
    /** @type {DecodedJWT} */
    let decodedToken
    let key

    try {
      decodedToken = decodeJwt(token)
      key = await getKey(decodedToken)
      if (!key) {
        return
      }
      // @ts-expect-error
      const decoded = await jose.jwtVerify(token, key, verifyOptions)
      req[requestProperty] = decoded.payload
      await immediate()
    } catch (/** @type {Error|any} */ err) {
      return
    }
  }
}

const immediate = () => new Promise((resolve) => setImmediate(() => resolve(0)))
