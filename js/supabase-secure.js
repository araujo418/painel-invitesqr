// ============================================================================
// supabase-secure.js
// Camada de autenticação segura para o InvitesAO / Painel InvitesQR.
//
// Objetivo: nenhuma senha é comparada no browser. Login e registo passam
// sempre por funções RPC no Supabase (rpc_login / rpc_register), que fazem
// a verificação/hash da password dentro do Postgres (SECURITY DEFINER),
// usando pgcrypto (bcrypt).
//
// Depende de duas variáveis globais já definidas ANTES deste script no
// index.html:
//   const SUPABASE_URL = 'https://SEU_PROJETO.supabase.co';
//   const SUPABASE_ANON_KEY = 'eyJ...';
//
// Este ficheiro deve ser carregado assim, DEPOIS dessas variáveis:
//   <script src="js/supabase-secure.js"></script>
// ============================================================================

(function () {
  if (typeof SUPABASE_URL === 'undefined' || typeof SUPABASE_ANON_KEY === 'undefined') {
    console.error('❌ supabase-secure.js: SUPABASE_URL / SUPABASE_ANON_KEY não definidos antes deste script.');
  }

  const SESSION_KEY = 'invitesqr_session';
  const ADMIN_TOKEN_KEY = 'invitesqr_admin_session_token';

  function getAdminToken() {
    try { return sessionStorage.getItem(ADMIN_TOKEN_KEY); } catch (_) { return null; }
  }

  function clearAdminToken() {
    try { sessionStorage.removeItem(ADMIN_TOKEN_KEY); } catch (_) {}
  }

  // Chama uma função RPC do Supabase via REST (PostgREST).
  async function callRpc(fnName, payload) {
    let res;
    try {
      res = await fetch(`${SUPABASE_URL}/rest/v1/rpc/${fnName}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'apikey': SUPABASE_ANON_KEY,
          'Authorization': `Bearer ${SUPABASE_ANON_KEY}`
        },
        body: JSON.stringify(payload)
      });
    } catch (networkErr) {
      throw new Error('Falha de rede ao contactar o servidor.');
    }

    let data = null;
    try {
      data = await res.json();
    } catch (_) {
      data = null;
    }

    if (!res.ok) {
      // PostgREST devolve erros de "RAISE EXCEPTION" no campo "message".
      const msg = (data && (data.message || data.hint || data.error_description)) || 'Erro desconhecido.';
      throw new Error(msg);
    }

    return data;
  }

  async function login(phone, password) {
    if (!phone || !password) {
      throw new Error('Telefone e senha são obrigatórios.');
    }

    clearAdminToken();
    const user = await callRpc('rpc_login', {
      p_phone: String(phone).trim(),
      p_password: String(password)
    });

    if (!user || !user.id) {
      throw new Error('Conta não encontrada.');
    }

    if (user.role === 'admin' && user.admin_session_token) {
      try { sessionStorage.setItem(ADMIN_TOKEN_KEY, user.admin_session_token); }
      catch (_) { throw new Error('Não foi possível guardar a sessão administrativa. Ative o armazenamento de sessão e entre novamente.'); }
    }

    // Guarda apenas dados não sensíveis da sessão (nunca a password).
    try {
      localStorage.setItem(SESSION_KEY, JSON.stringify({
        id: user.id,
        phone: user.phone,
        role: user.role,
        ts: Date.now()
      }));
    } catch (_) { /* localStorage pode falhar em modo privado; não é crítico */ }

    return user;
  }

  async function register(phone, password) {
    if (!phone || !password) {
      throw new Error('Telefone e senha são obrigatórios.');
    }

    const result = await callRpc('rpc_register', {
      p_phone: String(phone).trim(),
      p_password: String(password)
    });

    return result;
  }

  function logout() {
    const token = getAdminToken();
    if (token) callRpc('rpc_admin_logout', { p_session_token: token }).catch(() => {});
    clearAdminToken();
    try { localStorage.removeItem(SESSION_KEY); } catch (_) {}
  }

  function getSession() {
    try {
      const raw = localStorage.getItem(SESSION_KEY);
      return raw ? JSON.parse(raw) : null;
    } catch (_) {
      return null;
    }
  }

  async function adminSetPassword(userId, newPassword) {
    if (!userId || !newPassword) throw new Error('userId e nova senha são obrigatórios.');
    return callRpc('rpc_admin_set_password', {
      p_user_id: userId,
      p_new_password: String(newPassword),
      p_session_token: getAdminToken()
    });
  }

  async function adminCreateAccount(phone, password, role, status, eventLimit) {
    if (!phone || !password) throw new Error('Telefone e senha são obrigatórios.');
    return callRpc('rpc_admin_create_account', {
      p_phone: String(phone).trim(),
      p_password: String(password),
      p_role: role || 'user',
      p_status: status || 'active',
      p_event_limit: eventLimit ?? null,
      p_session_token: getAdminToken()
    });
  }

  async function adminAccountsRequest(endpoint, method = 'GET', body = null) {
    const token = getAdminToken();
    if (!token) throw new Error('Sessão administrativa expirada. Entre novamente.');
    const [resource, query = ''] = String(endpoint).split('?', 2);
    if (resource !== 'accounts') throw new Error('Pedido de conta inválido.');
    const params = new URLSearchParams(query);

    if (method === 'GET') {
      const idFilter = params.get('id');
      let userId = null;
      if (idFilter) {
        const match = idFilter.match(/^eq\.([0-9a-f-]{36})$/i);
        if (!match) throw new Error('Filtro de conta inválido.');
        userId = match[1];
      }
      const roleFilter = params.get('role');
      if (roleFilter && !/^eq\.[a-z_]{1,32}$/i.test(roleFilter)) {
        throw new Error('Filtro de conta inválido.');
      }
      const rawLimit = params.get('limit');
      const limit = rawLimit ? Math.min(500, Math.max(1, Number.parseInt(rawLimit, 10) || 500)) : 500;
      return callRpc('rpc_admin_accounts', {
        p_session_token: token,
        p_action: params.get('select') === 'count' ? 'count' : 'list',
        p_user_id: userId,
        p_role_filter: roleFilter ? roleFilter.slice(3) : null,
        p_limit: limit
      });
    }

    if (method === 'PATCH') {
      const idFilter = params.get('id');
      const match = idFilter && idFilter.match(/^eq\.([0-9a-f-]{36})$/i);
      if (!match || !body || typeof body !== 'object' || Array.isArray(body)) {
        throw new Error('Atualização de conta inválida.');
      }
      return callRpc('rpc_admin_accounts', {
        p_session_token: token,
        p_action: 'update',
        p_user_id: match[1],
        p_patch: body
      });
    }

    throw new Error('Esta operação direta em contas está desativada.');
  }

  async function adminChangeAccountId() {
    throw new Error('Alterar o ID está desativado para preservar a conta e os eventos associados.');
  }

  window.SecureAuth = {
    login, register, logout, getSession,
    adminSetPassword, adminCreateAccount, adminChangeAccountId,
    getAdminSessionToken: getAdminToken, adminAccountsRequest
  };
})();
