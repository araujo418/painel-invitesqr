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

    const user = await callRpc('rpc_login', {
      p_phone: String(phone).trim(),
      p_password: String(password)
    });

    if (!user || !user.id) {
      throw new Error('Conta não encontrada.');
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

  // ── Funções administrativas (usadas apenas pelo painel admin) ───────────
  // Todas fazem o hash/gestão da password dentro do Postgres via RPC
  // (SECURITY DEFINER); nenhuma password circula em texto simples nem é
  // gravada diretamente pelo browser.

  async function adminSetPassword(userId, newPassword) {
    if (!userId || !newPassword) {
      throw new Error('userId e nova senha são obrigatórios.');
    }
    return callRpc('rpc_admin_set_password', {
      p_user_id: userId,
      p_new_password: String(newPassword)
    });
  }

  async function adminCreateAccount(phone, password, role, status, eventLimit) {
    if (!phone || !password) {
      throw new Error('Telefone e senha são obrigatórios.');
    }
    return callRpc('rpc_admin_create_account', {
      p_phone: String(phone).trim(),
      p_password: String(password),
      p_role: role || 'user',
      p_status: status || 'active',
      p_event_limit: eventLimit ?? null
    });
  }

  async function adminChangeAccountId(oldId, newId) {
    if (!oldId || !newId) {
      throw new Error('ID antigo e novo ID são obrigatórios.');
    }
    return callRpc('rpc_admin_change_account_id', {
      p_old_id: oldId,
      p_new_id: newId
    });
  }

  window.SecureAuth = {
    login,
    register,
    logout,
    getSession,
    adminSetPassword,
    adminCreateAccount,
    adminChangeAccountId
  };
})();
