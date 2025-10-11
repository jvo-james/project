const crypto = require('crypto');

const b64url = (buf) => Buffer.from(buf).toString('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
const sign = (payload, secret) => b64url(crypto.createHmac('sha256', secret).update(payload).digest());

exports.handler = async function(event) {
  const state = crypto.randomBytes(16).toString('hex');
  const verifier = b64url(crypto.randomBytes(32));
  const challenge = b64url(crypto.createHash('sha256').update(verifier).digest());

  const payload = JSON.stringify({ state, verifier, iat: Date.now() });
  const secret = process.env.SESSION_SECRET || 'devsecret';
  const cookieVal = b64url(payload) + '.' + sign(payload, secret);

  // Short-lived cookie to store state & verifier for exchange (10 minutes)
  const cookie = \`mush_oauth=\${cookieVal}; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=600\`;

  const params = new URLSearchParams({
    response_type: 'code',
    client_id: process.env.X_CLIENT_ID,
    redirect_uri: process.env.X_REDIRECT_URI,
    scope: 'users.read tweet.read offline.access',
    state,
    code_challenge: challenge,
    code_challenge_method: 'S256'
  });

  return {
    statusCode: 302,
    headers: {
      'Set-Cookie': cookie,
      'Location': `https://twitter.com/i/oauth2/authorize?${params.toString()}`
    },
    body: ''
  };
};
