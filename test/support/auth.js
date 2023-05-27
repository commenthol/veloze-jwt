export const getAccessToken = async ({ tokenUrl, clientId, clientSecret, username, password }) => {
  const bodyO = JSON.parse(JSON.stringify({
    grant_type: 'password',
    client_id: clientId,
    clientSecret,
    username,
    password
  }))
  const body = new URLSearchParams(bodyO).toString()
  const res = await fetch(tokenUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body
  })
  if (res.ok && String(res.headers.get('content-type')).startsWith('application/json')) {
    const { access_token: accessToken } = await res.json()
    return accessToken
  }
}

const encodeBase64 = (obj) => Buffer.from(JSON.stringify(obj)).toString('base64').replace(/=+$/, '')

export const encodeJwtBadSig = ({ header, payload }) =>
  [encodeBase64(header), encodeBase64(payload), new Array(32).fill('a')].join('.')

export const encodeJwtBadHeader = ({ header, payload }) =>
  [encodeBase64(header).slice(1), encodeBase64(payload), new Array(32).fill('a')].join('.')

export const encodeJwtBadPayload = ({ header, payload }) =>
  [encodeBase64(header), encodeBase64(payload).slice(1), new Array(32).fill('a')].join('.')
