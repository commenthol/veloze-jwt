import * as jose from 'jose'
import { HttpError } from 'veloze'
import { decodeJwt } from './decodeJwt.js'

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
export function jwtAuth (options) {
  const {
    secret,
    requestProperty = 'auth',
    ...verifyOptions
  } = options || {}

  if (!secret) throw new TypeError('need secret')

  const _secret = typeof secret === 'string'
    ? new TextEncoder().encode(secret)
    : secret

  const getKey = typeof secret === 'function'
    ? secret
    : async () => _secret

  return async function _jwtAuth (req, _res) {
    const { authorization } = req.headers
    if (!authorization) {
      throw new HttpError(401)
    }
    const [type, token] = String(authorization).split(' ', 2)
    if (type.toLowerCase() !== 'bearer') {
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
      key = await getKey(decodedToken, req)
    } catch (/** @type {Error|any} */err) {
      throw new HttpError(401, 'Invalid Token', err)
    }

    if (!key) {
      throw new HttpError(401)
    }

    try {
      await jose.jwtVerify(token, key, verifyOptions)
    } catch (/** @type {Error|any} */err) {
      throw new HttpError(401, 'Invalid Token', err)
    }

    req[requestProperty] = decodedToken.payload

    await immediate()
  }
}

const immediate = () => new Promise(resolve => setImmediate(() => resolve(0)))
