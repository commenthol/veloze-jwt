import assert from 'node:assert/strict'
import supertest from 'supertest'
import { sign } from './jwtAuth.test.js'
import { jwtAuthExpress } from '../src/index.js'
import { connect, json as sendJson } from 'veloze'

const createApp = (options) => {
  const { requestProperty = 'auth' } = options || {}
  return (req, res) => connect(
    sendJson,
    jwtAuthExpress(options),
    (req, res) => res.json(req[requestProperty])
  )(req, res, (err) => {
    const { status = 500, message } = err
    res.json({ message }, status)
  })
}

describe('jwtAuthExpress', function () {
  let app
  const secret = 's€cr3t'
  before(function () {
    app = createApp({ secret, algorithms: ['HS256'] })
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
    const token = await sign({ azp: 'test' }, { secret, expiresIn: -1e3 })

    await supertest(app)
      .get('/')
      .set({ authorization: `Bearer ${token}` })
      .expect(401)
  })
})
