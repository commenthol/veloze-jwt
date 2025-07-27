import { jwtAuth } from './jwtAuth.js'

/**
 * @deprecated express@5 supports async middlewares
 * @param {import('./jwtAuth.js').JwtOptions} options
 * @returns {import('veloze').HandlerCb}
 */
export const jwtAuthExpress = (options) => {
  const _jwtAuth = jwtAuth(options)
  return (req, res, next) =>
    // @ts-expect-error // _jwtAuth is async handler
    _jwtAuth(req, res)
      // @ts-expect-error
      .then(() => next())
      .catch((err) => next(err))
}
