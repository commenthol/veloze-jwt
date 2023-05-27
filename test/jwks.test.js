// https://login.microsoftonline.com/common/.well-known/openid-configuration
// https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration

import assert from 'node:assert'
import { Server, json as sendJson } from 'veloze'
import supertest from 'supertest'
import { jwtAuth, jwks } from '../src/index.js'
import { getAccessToken, encodeJwtBadHeader, encodeJwtBadPayload, encodeJwtBadSig } from './support/auth.js'
import { createServer } from './support/server.js'
import { Log } from 'debug-level'

const log = new Log('test')

const createApp = (issuers, options) => {
  const secret = jwks(issuers, options)
  const app = new Server({ onlyHTTP1: true, gracefulTimeout: 0 })
  app.use(jwtAuth({ secret }), sendJson)
  app.get('/', (req, res) => res.json(req.auth))
  return app
}

describe('jwks', function () {
  describe('setup', function () {
    it('throws on missing issuers', function () {
      assert.throws(() => {
        jwks()
      }, /^Error: need issuers array$/)
    })

    it('throws if issuers are not an array', function () {
      assert.throws(() => {
        jwks('foobar')
      }, /^Error: need issuers array$/)
    })

    it('throws if jwksByIssuer does not use correct url', function () {
      assert.throws(() => {
        jwks(['foobar'], { jwksByIssuer: { foobar: 'not an URL' } })
      }, /^Error: Invalid URL: not an URL$/)
    })
  })

  describe('fake', function () {
    const port = 10001
    const issuer = `http://localhost:${port}/fake`
    let server
    before(async function () {
      server = (await createServer({ issuer, port, pathname: '/fake' })).listen(port)
    })
    after(function () {
      server.close()
    })

    const clientUrl = 'http://localhost:10002'
    let client
    before(function () {
      const app = createApp([issuer])
      client = app.listen(new URL(clientUrl).port)
    })
    after(function () {
      client.close()
    })

    let authorization
    before(async function () {
      const accessToken = await getAccessToken({
        username: 'alice',
        tokenUrl: `${issuer}/token`
      })
      authorization = `Bearer ${accessToken}`
    })

    describe('alice RS256', function () {
      it('shall authorize', async function () {
        const { body } = await supertest(clientUrl)
          .get('/')
          .set({ authorization })
        log.debug(body)
        const { iss, username } = body
        assert.deepEqual({ iss, username }, { iss: issuer, username: 'alice' })
      })
    })

    describe('PS256', function () {
      let authorization
      before(async function () {
        const accessToken = await getAccessToken({
          username: 'PS256',
          tokenUrl: `${issuer}/token`
        })
        authorization = `Bearer ${accessToken}`
      })

      it('shall authorize', async function () {
        const { body } = await supertest(clientUrl)
          .get('/')
          .set({ authorization })
        log.debug(body)
        const { iss, username } = body
        assert.deepEqual({ iss, username }, { iss: issuer, username: 'PS256' })
      })
    })

    describe('ES256', function () {
      let authorization
      before(async function () {
        const accessToken = await getAccessToken({
          username: 'ES256',
          tokenUrl: `${issuer}/token`
        })
        authorization = `Bearer ${accessToken}`
      })

      it('shall authorize', async function () {
        const { body } = await supertest(clientUrl)
          .get('/')
          .set({ authorization })
        log.debug(body)
        const { iss, username } = body
        assert.deepEqual({ iss, username }, { iss: issuer, username: 'ES256' })
      })
    })

    describe('HS256', function () {
      let authorization
      before(async function () {
        const accessToken = await getAccessToken({
          username: 'HS256',
          tokenUrl: `${issuer}/token`
        })
        authorization = `Bearer ${accessToken}`
      })

      it('shall authorize', async function () {
        // declare secrets by issuer to define share shared secret
        const secretsByIssuer = { [issuer]: 'secret' }
        const app = createApp([issuer], { secretsByIssuer })

        const { body } = await supertest(app)
          .get('/')
          .set({ authorization })
        log.debug(body)
        const { iss, username } = body
        assert.deepEqual({ iss, username }, { iss: issuer, username: 'HS256' })
      })
    })

    describe('failing', function () {
      const header = { alg: 'HS256', kid: '00000000-0000-0000-0000-000000000000' }

      let app
      before(function () {
        app = createApp([issuer])
      })

      it('shall fail with wrong issuer', async function () {
        const app = createApp(['http://localhost:6666/no-issuer'])

        const { body } = await supertest(app)
          .get('/')
          .set({ authorization, accept: 'application/json' })
          .expect(401)
        // log.debug(body)
        assert.equal(body.message, 'Invalid Token')
      })

      it('shall fail with bad header token', async function () {
        const header = { alg: 'HS256', kid: '00000000-0000-0000-0000-000000000000' }
        const payload = { iss: issuer, username: 'H256' }
        const authorization = `Bearer ${encodeJwtBadHeader({ header, payload })}`
        const { body } = await supertest(app)
          .get('/')
          .set({ authorization, accept: 'application/json' })
          .expect(401)
        // log.debug(body)
        assert.equal(body.message, 'Invalid Token')
      })

      it('shall fail with bad payload token', async function () {
        const payload = { iss: issuer, username: 'H256' }
        const authorization = `Bearer ${encodeJwtBadPayload({ header, payload })}`
        const { body } = await supertest(app)
          .get('/')
          .set({ authorization, accept: 'application/json' })
          .expect(401)
        // log.debug(body)
        assert.equal(body.message, 'Invalid Token')
      })

      it('shall fail with bad signature token', async function () {
        const payload = { iss: issuer, username: 'H256' }
        const authorization = `Bearer ${encodeJwtBadSig({ header, payload })}`
        const { body } = await supertest(app)
          .get('/')
          .set({ authorization, accept: 'application/json' })
          .expect(401)
        // log.debug(body)
        assert.equal(body.message, 'Unauthorized')
      })

      it('shall fail if jwks uri returns 500', async function () {
        const jwksByIssuer = { [issuer]: `${issuer}/500/certs` }
        const app = createApp([issuer], { jwksByIssuer })
        const { body } = await supertest(app)
          .get('/')
          .set({ authorization, accept: 'application/json' })
          .expect(401)
        // log.debug(body)
        assert.equal(body.message, 'Invalid Token')
      })

      it('shall fail if well known returns 500', async function () {
        const iss = `${issuer}/500`
        const payload = { iss, username: 'bob' }
        const authorization = `Bearer ${encodeJwtBadSig({ header, payload })}`
        const app = createApp([iss])
        const { body } = await supertest(app)
          .get('/')
          .set({ authorization, accept: 'application/json' })
          .expect(401)
        // log.debug(body)
        assert.equal(body.message, 'Invalid Token')
      })

      it('shall fail if well known returns 200', async function () {
        const iss = `${issuer}/200`
        const payload = { iss, username: 'bob' }
        const authorization = `Bearer ${encodeJwtBadSig({ header, payload })}`
        const app = createApp([iss])
        const { body } = await supertest(app)
          .get('/')
          .set({ authorization, accept: 'application/json' })
          .expect(401)
        // log.debug(body)
        assert.equal(body.message, 'Invalid Token')
      })
    })
  })
})
