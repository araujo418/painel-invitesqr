// Upload/delete event cover images only for an active app session that owns
// the event (or an active admin session). The service key stays server-side.
const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, apikey, content-type, x-app-session-token, x-event-id, x-file-name, x-action',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
};

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), {
  status,
  headers: { ...corsHeaders, 'Content-Type': 'application/json' },
});

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: corsHeaders });
  if (req.method !== 'POST') return json({ error: 'Método não permitido.' }, 405);

  const supabaseUrl = Deno.env.get('SUPABASE_URL');
  const serviceKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY');
  if (!supabaseUrl || !serviceKey) return json({ error: 'Configuração interna incompleta.' }, 500);

  const token = req.headers.get('x-app-session-token') || '';
  const eventId = req.headers.get('x-event-id') || '';
  const action = req.headers.get('x-action') || '';
  if (!/^[0-9a-f]{64}$/.test(token) || !eventId || !['upload', 'delete'].includes(action)) {
    return json({ error: 'Sessão ou pedido inválido.' }, 401);
  }

  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(token));
  const tokenHash = [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
  const adminHeaders = { apikey: serviceKey, Authorization: `Bearer ${serviceKey}` };
  const sessionUrl = new URL('/rest/v1/app_sessions', supabaseUrl);
  sessionUrl.search = new URLSearchParams({
    token_hash: `eq.${tokenHash}`,
    revoked_at: 'is.null',
    expires_at: `gt.${new Date().toISOString()}`,
    select: 'user_id',
    limit: '1',
  }).toString();
  const sessionResponse = await fetch(sessionUrl, { headers: adminHeaders });
  if (!sessionResponse.ok) return json({ error: 'Não foi possível validar a sessão.' }, 503);
  const sessions = await sessionResponse.json();
  const session = sessions[0];
  if (!session) return json({ error: 'Sessão expirada. Entre novamente.' }, 401);

  const accountUrl = new URL('/rest/v1/accounts', supabaseUrl);
  accountUrl.search = new URLSearchParams({
    id: `eq.${session.user_id}`,
    status: 'eq.active',
    select: 'id,role',
    limit: '1',
  }).toString();
  const accountResponse = await fetch(accountUrl, { headers: adminHeaders });
  const accounts = accountResponse.ok ? await accountResponse.json() : [];
  const account = accounts[0];
  if (!account) return json({ error: 'Conta inativa.' }, 403);

  const eventUrl = new URL('/rest/v1/events', supabaseUrl);
  eventUrl.search = new URLSearchParams({ id: `eq.${eventId}`, select: 'id,user_id', limit: '1' }).toString();
  const eventResponse = await fetch(eventUrl, { headers: adminHeaders });
  const events = eventResponse.ok ? await eventResponse.json() : [];
  const event = events[0];
  if (!event) return json({ error: 'Evento não encontrado.' }, 404);
  if (account.role !== 'admin' && event.user_id !== account.id) return json({ error: 'Sem permissão para este evento.' }, 403);

  if (action === 'upload') {
    const fileName = req.headers.get('x-file-name') || '';
    const contentType = req.headers.get('content-type') || '';
    const eventPrefix = `event_${eventId.replace(/[^A-Za-z0-9]/g, '')}_`;
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,179}$/.test(fileName) || fileName.includes('..') || !fileName.startsWith(eventPrefix)) {
      return json({ error: 'Nome do ficheiro inválido.' }, 400);
    }
    if (!['image/jpeg', 'image/png', 'image/webp'].includes(contentType)) {
      return json({ error: 'Formato de imagem não permitido.' }, 415);
    }
    const bytes = await req.arrayBuffer();
    if (bytes.byteLength === 0 || bytes.byteLength > 10 * 1024 * 1024) {
      return json({ error: 'A imagem deve ter até 10 MB.' }, 413);
    }
    const uploadUrl = `${supabaseUrl}/storage/v1/object/event-covers/${encodeURIComponent(fileName)}`;
    const uploadResponse = await fetch(uploadUrl, {
      method: 'POST',
      headers: { ...adminHeaders, 'Content-Type': contentType },
      body: bytes,
    });
    if (!uploadResponse.ok) return json({ error: 'Falha ao guardar a imagem.' }, uploadResponse.status);
    return json({ public_url: `${supabaseUrl}/storage/v1/object/public/event-covers/${encodeURIComponent(fileName)}` });
  }

  let fileName = '';
  try { fileName = (await req.json()).file_name || ''; } catch { return json({ error: 'Pedido inválido.' }, 400); }
  const eventPrefix = `event_${eventId.replace(/[^A-Za-z0-9]/g, '')}_`;
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,179}$/.test(fileName) || fileName.includes('..') || !fileName.startsWith(eventPrefix)) {
    return json({ error: 'Nome do ficheiro inválido.' }, 400);
  }
  const deleteResponse = await fetch(`${supabaseUrl}/storage/v1/object/event-covers/${encodeURIComponent(fileName)}`, {
    method: 'DELETE', headers: adminHeaders,
  });
  if (!deleteResponse.ok) return json({ error: 'Falha ao remover a imagem.' }, deleteResponse.status);
  return json({ ok: true });
});
