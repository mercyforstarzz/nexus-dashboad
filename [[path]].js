import { verify, cookie } from '../../lib/session.js';
const TYPES = ['giveaway', 'giveaway/end', 'announce', 'mod', 'status'];
export async function onRequest({ request, env, params }) {
  const s = await verify(cookie(request, 'sid'), env.SESSION_SECRET);
  if (!s) return Response.json({ error: 'Sign in again' }, { status: 401 });
  const path = [].concat(params.path || []).join('/'), get = k => env.DB.prepare('SELECT v,t FROM kv WHERE k=?').bind(k).first();
  if (path === 'me') return Response.json(s);
  if (path === 'stats') {
    const r = await get('stats');
    if (!r || Date.now() - r.t > 25000) return Response.json({ error: 'Bot is offline' }, { status: 502 });
    return new Response(r.v, { headers: { 'Content-Type': 'application/json' } });
  }
  if (path.startsWith('result/')) {
    const r = await get('res:' + path.slice(7));
    return r ? new Response(r.v, { headers: { 'Content-Type': 'application/json' } }) : Response.json({ pending: true }, { status: 202 });
  }
  if (request.method !== 'POST' || !TYPES.includes(path)) return Response.json({ error: 'Not found' }, { status: 404 });
  if (request.headers.get('Origin') !== new URL(request.url).origin) return Response.json({ error: 'Bad origin' }, { status: 403 });
  if (/^(mod|status)/.test(path) && !s.admin) return Response.json({ error: 'Admins only' }, { status: 403 });
  const id = crypto.randomUUID();
  await env.DB.prepare('INSERT INTO kv (k,v,t) VALUES (?,?,?)').bind('job:' + id, JSON.stringify({ id, type: path, data: await request.json(), user: s.id }), Date.now()).run();
  return Response.json({ id });
}
