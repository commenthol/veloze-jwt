// https://login.microsoftonline.com/common/.well-known/openid-configuration
// https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration

import assert from 'node:assert'
import { Server, json as sendJson } from 'veloze'
import supertest from 'supertest'
import { jwtAuth, jwks } from '../src/index.js'
import {
  getAccessToken,
  encodeJwtBadHeader,
  encodeJwtBadPayload,
  encodeJwtBadSig
} from './support/auth.js'
import { createServer } from './support/server.js'
import { Log } from 'debug-level'

const log = new Log('test')

const createApp = async (issuers, options) => {
  const secret = await jwks(issuers, options)
  const app = new Server({ onlyHTTP1: true, gracefulTimeout: 0 })
  app.use(jwtAuth({ secret }), sendJson)
  app.get('/', (req, res) => res.json(req.auth))
  return app
}

describe('jwks', function () {
  describe('setup', function () {
    const port = 10010
    const issuer = `http://localhost:${port}/fake`
    let server
    before(async function () {
      server = (
        await createServer({ issuer: 'http://foo', port, pathname: '/fake' })
      ).listen(port)
    })
    after(function () {
      server.close()
    })

    it('throws on missing issuers', async function () {
      await assert.rejects(async () => {
        await jwks()
      }, new Error('need issuers array'))
    })

    it('throws if issuers are not an array', async function () {
      await assert.rejects(async () => {
        await jwks('foobar')
      }, new Error('need issuers array'))
    })

    it('throws if jwksByIssuer does not use correct url', async function () {
      await assert.rejects(async () => {
        await jwks(['foobar'], { jwksByIssuer: { foobar: 'not an URL' } })
      }, new Error('Invalid URL: not an URL'))
    })

    it('throws on issuer mismatch', async function () {
      await assert.rejects(async () => {
        await jwks([issuer])
      }, new Error('ambiguous issuer http://localhost:10010/fake !== http://foo'))
    })
  })

  describe('fake', function () {
    const port = 10001
    const issuer = `http://localhost:${port}/fake`
    let server
    let forServer
    before(async function () {
      forServer = await createServer({ issuer, port, pathname: '/fake' })
      server = forServer.listen(port)
    })
    after(function () {
      server.close()
    })

    const clientUrl = 'http://localhost:10002'
    let client
    before(async function () {
      const app = await createApp([issuer])
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
        const app = await createApp([issuer], { secretsByIssuer })

        const { body } = await supertest(app).get('/').set({ authorization })
        log.debug(body)
        const { iss, username } = body
        assert.deepEqual({ iss, username }, { iss: issuer, username: 'HS256' })
      })
    })

    describe('failing', function () {
      const header = {
        alg: 'HS256',
        kid: '00000000-0000-0000-0000-000000000000'
      }

      let app
      before(async function () {
        app = await createApp([issuer])
      })

      it('shall fail with unreachable issuer', async function () {
        await assert.rejects(async () => {
          await createApp(['http://localhost:6666/no-issuer'])
        }, new Error('fetch failed url=http://localhost:6666/no-issuer/.well-known/openid-configuration'))
      })

      it('shall fail with bad header token', async function () {
        const header = {
          alg: 'HS256',
          kid: '00000000-0000-0000-0000-000000000000'
        }
        const payload = { iss: issuer, username: 'RS256' }
        const authorization = `Bearer ${encodeJwtBadHeader({
          header,
          payload
        })}`
        const { body } = await supertest(app)
          .get('/')
          .set({ authorization, accept: 'application/json' })
          .expect(401)
        // log.debug(body)
        assert.equal(body.message, 'Invalid Token')
      })

      it('shall fail with bad issuer', async function () {
        const accessToken = await forServer.getAccessToken('HS256', {
          iss: issuer + '/bad',
          username: 'RS256'
        })
        const authorization = `Bearer ${accessToken}`
        const { body } = await supertest(app)
          .get('/')
          .set({ authorization, accept: 'application/json' })
          .expect(401)
        log.debug(body)
        assert.equal(body.message, 'Invalid Token')
      })

      it('shall fail with bad payload token', async function () {
        const payload = { iss: issuer, username: 'H256' }
        const authorization = `Bearer ${encodeJwtBadPayload({
          header,
          payload
        })}`
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
        await assert.rejects(async () => {
          await createApp([issuer], { jwksByIssuer })
        }, new Error('no keys found: issue=http://localhost:10001/fake url=http://localhost:10001/fake/500/certs'))
      })

      it('shall fail if well known returns 500', async function () {
        const iss = `${issuer}/500`
        await assert.rejects(async () => {
          await createApp([iss])
        }, new Error('ambiguous issuer http://localhost:10001/fake/500 !== undefined'))
      })

      it('shall fail if well known returns 200', async function () {
        const iss = `${issuer}/200`
        await assert.rejects(async () => {
          await createApp([iss])
        }, new Error('ambiguous issuer http://localhost:10001/fake/200 !== undefined'))
      })
    })
  })
})
