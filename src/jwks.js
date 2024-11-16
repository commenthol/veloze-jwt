import * as jose from 'jose'

/**
 * @typedef {import('./jwtAuth.js').GetKeyLikeFn} GetKeyLikeFn
 */
/**
 * @typedef {object} JwksOptions
 * @property {fetch} [fetcher=fetch]
 * @property {Number} [expiresIn=3e5] expiry in ms
 * @property {Record<string, string>} [jwksByIssuer] jwksUri by issuer
 * @property {Record<string, string|Uint8Array>} [secretsByIssuer] secret by issuer
 */

/**
 * @param {string[]} issuers issuer uris
 * @param {JwksOptions} options
 * @returns {GetKeyLikeFn}
 */
export function jwks(issuers, options) {
  const {
    expiresIn = 3e5, // default is 5 min
    fetcher = fetchIt(options),
    jwksByIssuer = {},
    secretsByIssuer = {}
  } = options || {}

  if (!Array.isArray(issuers) || !issuers?.[0]) {
    throw new Error('need issuers array')
  }

  const kidCache = new Map()
  const jwksCache = new Map()
  const secretsCache = new Map()
  const expiryCache = new Map()

  for (const [iss, jwskUri] of Object.entries(jwksByIssuer)) {
    if (!isHttpUrl(jwskUri)) {
      throw new Error(`Invalid URL: ${jwskUri}`)
    }
    jwksCache.set(iss, jwskUri)
  }
  for (const [iss, secret] of Object.entries(secretsByIssuer)) {
    const _secret =
      typeof secret === 'string' ? new TextEncoder().encode(secret) : secret
    secretsCache.set(iss, _secret)
  }

  return async function getKey({ header, payload }) {
    const { kid, alg } = header
    const { iss } = payload || {}

    if (!issuers.includes(iss)) {
      throw new Error(`unknown issuer: ${iss}`)
    }

    const secret = secretsCache.get(iss)
    if (secret) {
      return secret
    }

    const kidAlg = kid + alg
    const expires = expiryCache.get(kidAlg)
    /* c8 ignore next 4 */
    if (expires && Date.now() > expires) {
      kidCache.delete(kidAlg)
      expiryCache.delete(kidAlg)
    }

    let _kid = kidCache.get(kidAlg)
    if (_kid) {
      return _kid
    }

    let jwskUri = jwksCache.get(iss)
    if (!jwskUri) {
      /* c8 ignore next 3 */
      if (!issuers.includes(iss)) {
        throw new Error(`unknown issuer: ${iss}`)
      }
      const obj = await fetcher(`${iss}/.well-known/openid-configuration`)
      jwskUri = obj.jwks_uri
      if (!jwskUri) {
        throw new Error(`unknown jwksUri: ${iss}`)
      }
      jwksCache.set(iss, jwskUri)
    }

    const obj = await fetcher(jwskUri)
    if (!Array.isArray(obj?.keys)) {
      throw new Error(`No keys found: ${iss}`)
    }
    for (const key of obj.keys) {
      const { kid, alg, ...keyLikeAttr } = key
      const _kidAlg = kid + alg
      const keyLike = await jose.importJWK(keyLikeAttr).catch((_err) => null)
      if (keyLike) {
        kidCache.set(_kidAlg, keyLike)
        expiryCache.set(_kidAlg, Date.now() + expiresIn)
      }
    }

    _kid = kidCache.get(kidAlg)
    return _kid
  }
}

const fetchIt = (options) => {
  const { timeout = 15e3 } = options || {}

  return async (jwskUri) => {
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), timeout)

    const res = await fetch(jwskUri, { signal: controller.signal })
    clearTimeout(timer)

    if (
      res.ok &&
      String(res.headers.get('content-type')).startsWith('application/json')
    ) {
      return await res.json()
    }
  }
}

/**
 * @param {string} urlLike
 * @returns {boolean}
 */
const isHttpUrl = (urlLike) => {
  try {
    const parsed = new URL(urlLike)
    return /^https?:$/.test(parsed.protocol)
  } catch (e) {
    return false
  }
}
