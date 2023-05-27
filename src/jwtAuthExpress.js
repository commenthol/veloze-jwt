import { jwtAuth } from './jwtAuth.js'

/**
 * @param {import('./jwtAuth.js').JwtOptions} options
 * @returns {import('veloze/types/types.js').HandlerCb}
 */
export const jwtAuthExpress = (options) => {
  const _jwtAuth = jwtAuth(options)
  // @ts-expect-error // _jwtAuth is async handler
  return (req, res, next) => _jwtAuth(req, res)
    // @ts-expect-error
    .then(() => next())
    .catch(err => next(err))
}
