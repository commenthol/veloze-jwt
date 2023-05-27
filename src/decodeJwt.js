/**
 * @typedef {object} DecodedJWT
 * @property {{kid: string, alg: string}} header
 * @property {{iat: number, exp: number, [prop: string]: any}} payload
 * @property {string} signature
 */

/**
 * @param {string} input
 * @returns {string}
 */
export const decodeBase64 = (input) => Buffer.from(input, 'base64').toString()

/**
 * @param {string} token
 * @returns {DecodedJWT}
 */
export const decodeJwt = (token) => {
  /* c8 ignore next 3 */
  if (typeof token !== 'string') {
    throw new TypeError('Invalid JWT')
  }
  const parts = token.split('.')
  if (parts.length !== 3) {
    throw new TypeError('Invalid JWT')
  }

  const header = JSON.parse(decodeBase64(parts[0]))
  const payload = JSON.parse(decodeBase64(parts[1]))
  const signature = parts[2]

  return {
    header,
    payload,
    signature
  }
}
