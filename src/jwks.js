import * as jose from 'jose'

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
export async function jwks(issuers, options) {
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

  async function getKey({ header, payload }) {
    const { kid, alg } = header
    const { iss } = payload || {}

    if (!issuers.includes(iss)) {
      throw new Error(`unknown issuer: ${iss}`)
    }

    // serve secret or public key passed with secretsByIssuer
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

    let jwksUri = jwksCache.get(iss)
    if (!jwksUri) {
      /* c8 ignore next 3 */
      if (!issuers.includes(iss)) {
        throw new Error(`unknown issuer: ${iss}`)
      }
      const oidcConf = await fetcher(`${iss}/.well-known/openid-configuration`)
      if (oidcConf?.issuer !== iss) {
        throw new Error(`ambiguous issuer ${iss} !== ${oidcConf?.issuer}`)
      }
      jwksUri = oidcConf?.jwks_uri
      /* c8 ignore next 3 */
      if (!jwksUri) {
        throw new Error(`unknown jwksUri: ${iss}`)
      }
      jwksCache.set(iss, jwksUri)
    }

    const jwksKeys = await fetcher(jwksUri)
    if (!Array.isArray(jwksKeys?.keys)) {
      throw new Error(`no keys found: issue=${iss} url=${jwksUri}`)
    }
    for (const key of jwksKeys.keys) {
      const { kid, alg, ...keyLikeAttr } = key
      const _kidAlg = kid + alg
      const keyLike = await jose
        .importJWK(keyLikeAttr, alg)
        .catch((err) => console.warn(err))
      if (keyLike) {
        kidCache.set(_kidAlg, keyLike)
        expiryCache.set(_kidAlg, Date.now() + expiresIn)
      }
    }

    _kid = kidCache.get(kidAlg)
    return _kid
  }

  // get keys from all issuers (max. timeout is 2x 15s)
  await Promise.all(
    issuers.map((iss) => getKey({ header: {}, payload: { iss } }))
  )

  return getKey
}

const fetchIt = (options) => {
  const { timeout = 15e3 } = options || {}

  return async (jwskUri) => {
    const res = await fetch(jwskUri, {
      signal: AbortSignal.timeout(timeout)
    }).catch((cause) => {
      throw new Error(`fetch failed url=${jwskUri}`, { cause })
    })

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
