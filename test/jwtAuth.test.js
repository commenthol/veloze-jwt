import assert from 'node:assert/strict'
import supertest from 'supertest'
import * as jose from 'jose'
import { jwtAuth } from '../src/index.js'
import { connect, json as sendJson } from 'veloze'

export const sign = (
  payload,
  { secret, expiresIn = 5e3, header = { alg: 'HS256' } }
) =>
  new jose.SignJWT({ ...payload, exp: secs(Date.now() + expiresIn) })
    .setProtectedHeader(header)
    .sign(new TextEncoder().encode(secret))

const createApp = (options) => {
  const { requestProperty = 'auth' } = options || {}
  return (req, res) =>
    connect(sendJson, jwtAuth(options), (req, res) =>
      res.json(req[requestProperty])
    )(req, res, (err) => {
      // console.error(err)
      const { status = 500, message } = err
      res.json({ message }, status)
    })
}

describe('jwtAuth', function () {
  let app
  const secret = 's€cr3t'
  before(function () {
    app = createApp({ secret })
  })

  it('shall fail if no secret is provided', function () {
    assert.throws(() => {
      jwtAuth()
    }, /^TypeError: need secret/)
  })

  it('shall fail with missing authorization header', async function () {
    await supertest(app).get('/').expect(401, { message: 'Unauthorized' })
  })

  it('shall fail with missing JWT', async function () {
    await supertest(app)
      .get('/')
      .set({ authorization: 'Bearer ' })
      .expect(401, { message: 'No bearer token found' })
  })

  it('shall fail with bad JWT', async function () {
    await supertest(app)
      .get('/')
      .set({ authorization: 'Bearer foobar' })
      .expect(401, { message: 'Invalid Token' })
  })

  it('shall fail with wrong auth scheme', async function () {
    await supertest(app)
      .get('/')
      .set({ authorization: 'Basic foobar' })
      .expect(401, { message: 'Bearer token authorization expected' })
  })

  it('shall fail with empty secret', async function () {
    const app = createApp({
      secret: () => null,
      algorithms: ['HS512'] // ['HS256']
    })

    const token = await sign({ azp: 'test' }, { secret })

    await supertest(app)
      .get('/')
      .set({ authorization: `Bearer ${token}` })
      .expect(401, { message: 'Unauthorized' })
  })

  it('shall decode H256 JWT', async function () {
    const token = await sign({ azp: 'test' }, { secret })

    await supertest(app)
      .get('/')
      .set({ authorization: `Bearer ${token}` })
      .expect(200)
      .then(({ body }) => {
        const { azp } = body
        assert.equal(azp, 'test')
      })
  })

  it('shall fail with expired H256 JWT', async function () {
    const token = await sign({ azp: 'test' }, { secret, expiresIn: -5e3 })

    await supertest(app)
      .get('/')
      .set({ authorization: `Bearer ${token}` })
      .expect(401)
  })
})

const secs = (ms) => Math.floor(ms / 1000)
