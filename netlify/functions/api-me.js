const crypto = require('crypto');

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
    const raw = parseCookie(event.headers.cookie || '', 'mush_session');
    if(!raw) return { statusCode:200, body: JSON.stringify({ logged:false }) };

    const [payloadB64, sig] = raw.split('.');
    const secret = process.env.SESSION_SECRET || 'devsecret';
    const payload = Buffer.from(payloadB64, 'base64').toString();
    if(sign(payload, secret) !== sig) return { statusCode:200, body: JSON.stringify({ logged:false }) };

    const user = JSON.parse(payload);
    return { statusCode:200, body: JSON.stringify({ logged:true, user }) };

  } catch(e){
    console.error(e);
    return { statusCode:500, body: JSON.stringify({ logged:false }) };
  }
};
