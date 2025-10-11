const crypto = require('crypto');
const fetch = global.fetch || require('node-fetch');

const b64url = (buf) => Buffer.from(buf).toString('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
const sign = (payload, secret) => b64url(crypto.createHmac('sha256', secret).update(payload).digest());

function parseCookie(header, name){
  if(!header) return null;
  const cookies = header.split(';').map(s=>s.trim());
  const found = cookies.find(c => c.startsWith(name+'='));
  return found ? found.split('=')[1] : null;
}

exports.handler = async function(event) {
  try {
    const qs = event.queryStringParameters || {};
    const code = qs.code;
    const state = qs.state;
    const cookieHeader = event.headers.cookie || '';
    const raw = parseCookie(cookieHeader, 'mush_oauth');
    if(!raw) return { statusCode:400, body:'Missing oauth cookie' };

    const [payloadB64, sig] = raw.split('.');
    const payload = Buffer.from(payloadB64, 'base64').toString();
    const secret = process.env.SESSION_SECRET || 'devsecret';
    if(sign(payload, secret) !== sig) return { statusCode:400, body:'Invalid signature' };

    const saved = JSON.parse(payload);
    if(saved.state !== state) return { statusCode:400, body:'State mismatch' };

    // Exchange code for tokens
    const tokenRes = await fetch('https://api.twitter.com/2/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type':'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: process.env.X_CLIENT_ID,
        code,
        redirect_uri: process.env.X_REDIRECT_URI,
        code_verifier: saved.verifier
      })
    });
    const tokenJson = await tokenRes.json();
    if(!tokenRes.ok) {
      console.error('token error', tokenJson);
      return { statusCode:500, body: 'Token exchange failed' };
    }

    // Fetch user
    const userRes = await fetch('https://api.twitter.com/2/users/me', {
      headers: { Authorization: `Bearer ${tokenJson.access_token}` }
    });
    const userJson = await userRes.json();

    // Session cookie — store small signed payload (do not store secrets in cookie)
    const sessionPayload = JSON.stringify({
      id: userJson.data?.id,
      username: userJson.data?.username,
      name: userJson.data?.name,
      iat: Date.now()
    });
    const sessionSig = sign(sessionPayload, secret);
    const sessionCookie = \`mush_session=\${b64url(sessionPayload)}.\${sessionSig}; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=\${60*60*24*7}\`;

    const html = `<!doctype html><meta charset="utf-8">
      <title>Signing in…</title>
      <script>
        (async function(){
          try {
            if(window.opener){
              window.opener.postMessage({ type:'mushrush.x.auth' }, '*');
            }
          } catch(e){}
          setTimeout(()=> window.close(), 250);
        })();
      </script>
      <div style="font-family:system-ui;padding:20px">Signing you in…</div>`;

    return { statusCode: 200, headers: { 'Set-Cookie': sessionCookie, 'Content-Type':'text/html' }, body: html };

  } catch(err){
    console.error(err);
    return { statusCode:500, body: 'Server error' };
  }
};
