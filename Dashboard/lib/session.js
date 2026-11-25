export const GUILD = '1574075706940457115', DASH_ROLE = '1574932942323454053', OWNER = '1366957389001134182';
export const ADMIN_ROLES = ['1574511979366842389', '1574812686234165440'];
const enc = new TextEncoder(), dec = new TextDecoder();
const b64 = b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64 = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
const key = s => crypto.subtle.importKey('raw', enc.encode(s), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
export async function sign(o, secret) {
  const p = b64(enc.encode(JSON.stringify(o)));
  return p + '.' + b64(await crypto.subtle.sign('HMAC', await key(secret), enc.encode(p)));
}
export async function verify(t, secret) {
  if (!t) return null; const [p, s] = t.split('.'); if (!p || !s) return null;
  if (b64(await crypto.subtle.sign('HMAC', await key(secret), enc.encode(p))) !== s) return null;
  try { const o = JSON.parse(dec.decode(unb64(p))); return o.exp > Date.now() ? o : null; } catch { return null; }
}
export const cookie = (req, n) => (req.headers.get('Cookie') || '').split('; ').find(c => c.startsWith(n + '='))?.slice(n.length + 1);
