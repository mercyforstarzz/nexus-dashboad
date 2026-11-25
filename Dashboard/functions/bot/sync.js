export async function onRequestPost({ request, env }) {
  if (request.headers.get('Authorization') !== 'Bearer ' + env.BOT_API_SECRET) return new Response('unauthorized', { status: 401 });
  const b = await request.json(), put = (k, v) => env.DB.prepare('INSERT OR REPLACE INTO kv (k,v,t) VALUES (?,?,?)').bind(k, JSON.stringify(v), Date.now()).run();
  await put('stats', b.stats);
  for (const r of b.results || []) await put('res:' + r.id, r);
  await env.DB.prepare("DELETE FROM kv WHERE k LIKE 'res:%' AND t < ?").bind(Date.now() - 120000).run();
  const { results } = await env.DB.prepare("DELETE FROM kv WHERE k LIKE 'job:%' RETURNING v").all();
  return Response.json({ jobs: results.map(r => JSON.parse(r.v)) });
}
