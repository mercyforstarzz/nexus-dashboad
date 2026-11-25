import { sign, cookie, GUILD, DASH_ROLE, ADMIN_ROLES, OWNER } from '../../lib/session.js';
const D = 'https://discord.com/api/v10';
export async function onRequest({ request, env, params }) {
  const u = new URL(request.url), a = params.action, redirect = u.origin + '/auth/callback';
  const go = (loc, ...c) => { const h = new Headers({ Location: loc }); c.forEach(x => h.append('Set-Cookie', x)); return new Response(null, { status: 302, headers: h }); };
  if (a === 'login') {
    const st = crypto.randomUUID();
    return go('https://discord.com/oauth2/authorize?' + new URLSearchParams({ client_id: env.DISCORD_CLIENT_ID, redirect_uri: redirect, response_type: 'code', scope: 'identify', state: st }),
      `st=${st}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600`);
  }
  if (a === 'logout') return go('/', 'sid=; Path=/; Max-Age=0');
  if (a === 'callback') {
    const code = u.searchParams.get('code');
    if (!code || u.searchParams.get('state') !== cookie(request, 'st')) return go('/?e=state');
    const t = await (await fetch(D + '/oauth2/token', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ client_id: env.DISCORD_CLIENT_ID, client_secret: env.DISCORD_CLIENT_SECRET, grant_type: 'authorization_code', code, redirect_uri: redirect }) })).json();
    if (!t.access_token) return go('/?e=token');
    const me = await (await fetch(D + '/users/@me', { headers: { Authorization: 'Bearer ' + t.access_token } })).json();
    const mr = await fetch(`${D}/guilds/${GUILD}/members/${me.id}`, { headers: { Authorization: 'Bot ' + env.DISCORD_BOT_TOKEN } });
    const roles = mr.ok ? (await mr.json()).roles : [];
    const admin = me.id === OWNER || roles.some(r => ADMIN_ROLES.includes(r));
    if (!admin && !roles.includes(DASH_ROLE)) return go('/?e=denied', 'st=; Path=/; Max-Age=0');
    const sid = await sign({ id: me.id, name: me.global_name || me.username, avatar: me.avatar, admin, exp: Date.now() + 12 * 3600e3 }, env.SESSION_SECRET);
    return go('/', `sid=${sid}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=43200`, 'st=; Path=/; Max-Age=0');
  }
  return new Response('Not found', { status: 404 });
}
