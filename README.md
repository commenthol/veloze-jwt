[![npm-badge][npm-badge]][npm]
[![actions-badge][actions-badge]][actions]
![types-badge][types-badge]

# @veloze/jwt

Middleware to verify JSON-Web-Tokens (JWT) sent in Bearer Authorization Header.

If public-keys are required to verify JWTs the JWKS URI can be detected by
issuer using `.well-known/openid-configuration` URLs.

Supports multiple issuers with the `jwks()` method.

Works also with [express][] using `jwtAuthExpress()`.

# usage

Installation

```
npm i @veloze/jwt
```

In your code:

```js
import { Server } from 'veloze'
import { jwtAuth } from '@veloze/jwt'

const server = new Server()
const issuer = 'https://my.oau.th'
// for HS256, HS384, HS512 token provide secret
const protect = jwtAuth({ issuer, secret: 's€cr3t' })
server.get('/', protect, (req, res) => res.end())
server.listen(443)

// ----
await fetch('https://server', { 
  headers: {
    authorization: 'Bearer <TOKEN>' // H256 Token with issuer https://my.oau.th
  }
})
```

For OIDC servers with .well-known/openid-configuration 

```js
import { jwtAuth, jwks } from '@veloze/jwt'

const issuer = 'https://my.oau.th'
const issuer2 = 'https://oauth.other'

// supports multiple issuers
const secret = jwks([issuer, issuer2])
const protect = jwtAuth({ secret })
```

# API

## jwtAuth

```ts
import { 
  JWTHeaderParameters,
  JWTPayload,
  JWTVerifyOptions, 
  KeyLike 
} from 'jose'

interface DecodedJWT {
  header: JWTHeaderParameters,
  payload: JWTPayload,
  signature: string
}

type GetKeyLikeFn = (decodedToken: DecodedJWT, req: Request) => Promise<KeyLike>;

interface JwtOptions extends JWTVerifyOptions {
  /**
   * for HS256...HS512 provide secret as Buffer or string
   * for asymmetric JWT provide publicKey as secret
   */
  secret: string|Buffer|KeyLike|GetKeyLikeFn
  /**
   * if verification is successful then payload of decoded token is added to 
   * request using this property e.g. default is `req.auth`
   * @default 'auth'
   */
  requestProperty: string
}

function jwtAuth (options: JwtOptions): 
  Promise<(req: Request, res: Response): void>

function jwtAuthExpress (options: JwtOptions): 
  (req: Request, res: Response, next: Function): void
```

## jwks

```ts
type JwksOptions = {
  /**
   * allows to set custom fetch function
   */
  fetcher?: typeof fetch | undefined;
  /**
   * expiry in ms, JWKS uris are cached until this expiry timeout
   */
  expiresIn?: number | undefined;
  /**
   * jwksUri by issuer (for PS, RS, ES alg JWTs)
   * allows to overwrite the default jwks_uri which usually is looked-up from 
   * .well-known/openid-configuration
   */
  jwksByIssuer?: Record<string, string> | undefined;
  /**
   * secret by issuer (for HS JWTs) 
   */
  secretsByIssuer?: Record<string, string | Uint8Array> | undefined;
};

/**
 * issuers: provide a list of different issuers which shall be supported
 */
function jwks(issuers: string[], options: JwksOptions): GetKeyLikeFn;
```

# license

MIT licensed

[npm-badge]: https://badgen.net/npm/v/@veloze/jwt
[npm]: https://www.npmjs.com/package/@veloze/jwt
[types-badge]:https://badgen.net/npm/types/@veloze/jwt
[actions-badge]: https://github.com/commenthol/veloze-jwt/workflows/CI/badge.svg?branch=main&event=push
[actions]: https://github.com/commenthol/veloze-jwt/actions/workflows/ci.yml?query=branch%3Amain

[express]: https://expressjs.com
