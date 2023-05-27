import { Server, bodyParser, json as sendJson } from 'veloze'
import * as jose from 'jose'
import { httpLogs } from 'debug-level'

/**
 * @note this is a fake oidc server; only use for test purposes.
 * @param {{
 *   issuer: string
 * }} options
 * @returns {Server}
 */
export const createServer = async (options) => {
  const { issuer, pathname = '' } = options

  const { privateKeys, publicKeys } = await generateKeys()
  // console.log(privateKeys, publicKeys)

  const server = new Server({ onlyHTTP1: true, gracefulTimeout: 0 })

  server.use(httpLogs('http'), sendJson)

  server.get(`${pathname}/.well-known/openid-configuration`,
    wellKnown({ issuer }))

  server.get(`${pathname}/:status/.well-known/openid-configuration`,
    (req, res) => {
      const { status } = req.params
      res.json({}, status)
    })

  server.get(`${pathname}/certs`,
    certs({ publicKeys }))

  server.get(`${pathname}/:status/certs`,
    (req, res) => {
      const { status } = req.params
      res.json({}, status)
    })

  server.post(`${pathname}/token`,
    bodyParser.urlEncoded(),
    token({ issuer, privateKeys }))

  return server
}

const generateKeys = async () => {
  const algs = ['PS256', 'RS256', 'ES256', 'HS256']
  const publicKeys = []
  const privateKeys = {}

  let cnt = 0
  for (const alg of algs) {
    const kid = '00000000-0000-0000-0000-00000000000' + (cnt++)
    if (/^HS/.test(alg)) {
      const privateKey = new TextEncoder().encode('secret')
      privateKeys[alg] = { privateKey, kid, alg }
    } else {
      const { publicKey, privateKey } = await jose.generateKeyPair(alg)
      const jwks = await jose.exportJWK(publicKey)
      publicKeys.push({ ...jwks, kid, alg, use: 'sig' })
      privateKeys[alg] = { privateKey, kid, alg }
    }
  }

  return { privateKeys, publicKeys }
}

const wellKnown = ({ issuer }) => (req, res) => {
  res.json({
    issuer,
    token_endpoint: issuer + '/token',
    jwks_uri: issuer + '/certs',
    grant_types_supported: ['password'],
    response_types_supported: ['token'],
    token_endpoint_auth_methods_supported: ['client_secret_post']
  })
}

const certs = ({ publicKeys }) => (req, res) => {
  res.json({ keys: publicKeys })
}

const token = ({ issuer, privateKeys }) => async (req, res) => {
  const { username } = req.body
  const body = {
    iss: issuer,
    username
  }

  const { kid, alg, privateKey } = privateKeys[username] || privateKeys.RS256

  const accessToken = await new jose.SignJWT(body)
    .setProtectedHeader({ kid, alg })
    .setIssuedAt()
    .setExpirationTime('5m')
    .sign(privateKey)

  return res.json({
    access_token: accessToken,
    expires: 300
  })
}

// await createServer({ issuer: 'http://localhost:8080/realms/my' })
// console.log(await generateKeys())
