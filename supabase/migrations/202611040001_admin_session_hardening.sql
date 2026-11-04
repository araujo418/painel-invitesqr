-- Harden the legacy custom account login without changing client/guest flows.
-- Admin session tokens are random, short-lived bearer secrets. Only a SHA-256
-- digest is stored. No account, event, RSVP, or gift rows are deleted.
BEGIN;

CREATE TABLE IF NOT EXISTS public.admin_sessions (
  token_hash text PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES public.accounts(id) ON DELETE RESTRICT,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz
);

CREATE INDEX IF NOT EXISTS admin_sessions_user_expiry_idx
  ON public.admin_sessions (user_id, expires_at);

ALTER TABLE public.admin_sessions ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.admin_sessions FROM PUBLIC, anon, authenticated;
DROP POLICY IF EXISTS accounts_public_access ON public.accounts;

CREATE OR REPLACE FUNCTION public._require_admin_session(p_session_token text)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'public', 'extensions'
AS $function$
DECLARE
  v_user_id uuid;
BEGIN
  IF p_session_token IS NULL OR length(p_session_token) <> 64 THEN
    RAISE EXCEPTION 'Sessão administrativa inválida ou expirada.' USING ERRCODE = '42501';
  END IF;

  SELECT s.user_id INTO v_user_id
  FROM public.admin_sessions s
  JOIN public.accounts a ON a.id = s.user_id
  WHERE s.token_hash = encode(extensions.digest(p_session_token, 'sha256'), 'hex')
    AND s.revoked_at IS NULL
    AND s.expires_at > now()
    AND a.role = 'admin'
    AND a.status = 'active'
  LIMIT 1;

  IF v_user_id IS NULL THEN
    RAISE EXCEPTION 'Sessão administrativa inválida ou expirada.' USING ERRCODE = '42501';
  END IF;

  RETURN v_user_id;
END;
$function$;
REVOKE ALL ON FUNCTION public._require_admin_session(text) FROM PUBLIC, anon, authenticated;

-- Never grant direct access to accounts. Admin reads/updates use the RPC below.

-- Preserve the existing login contract and add a token only for admins.
-- User/guest registration and login continue using the same RPCs and passwords.
CREATE OR REPLACE FUNCTION public.rpc_login(p_phone text, p_password text)
RETURNS json
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'public', 'extensions'
AS $function$
DECLARE
  acc record;
  senha_ok boolean;
  admin_session_token text;
BEGIN
  SELECT id, phone, password, role, status, event_limit
  INTO acc
  FROM public.accounts
  WHERE phone = p_phone
  LIMIT 1;

  IF acc.id IS NULL THEN RAISE EXCEPTION 'Conta não encontrada.'; END IF;
  IF acc.status = 'deleted' THEN RAISE EXCEPTION 'DELETED';
  ELSIF acc.status = 'blocked' THEN RAISE EXCEPTION 'BLOCKED';
  ELSIF acc.status = 'pending' THEN RAISE EXCEPTION 'PENDING';
  END IF;

  IF acc.password LIKE '$2%' THEN
    senha_ok := (extensions.crypt(p_password, acc.password) = acc.password);
  ELSE
    senha_ok := (acc.password = p_password);
    IF senha_ok THEN
      UPDATE public.accounts
      SET password = extensions.crypt(p_password, extensions.gen_salt('bf', 12))
      WHERE id = acc.id;
    END IF;
  END IF;

  IF NOT senha_ok THEN RAISE EXCEPTION 'Senha incorreta'; END IF;

  IF acc.role = 'admin' THEN
    admin_session_token := encode(extensions.gen_random_bytes(32), 'hex');
    INSERT INTO public.admin_sessions (token_hash, user_id, expires_at)
    VALUES (
      encode(extensions.digest(admin_session_token, 'sha256'), 'hex'),
      acc.id,
      now() + interval '8 hours'
    );
  END IF;

  RETURN json_build_object(
    'id', acc.id,
    'phone', acc.phone,
    'role', acc.role,
    'status', acc.status,
    'event_limit', acc.event_limit,
    'admin_session_token', admin_session_token
  );
END;
$function$;

CREATE OR REPLACE FUNCTION public.rpc_admin_logout(p_session_token text)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'public', 'extensions'
AS $function$
DECLARE
  v_user_id uuid;
BEGIN
  v_user_id := public._require_admin_session(p_session_token);
  UPDATE public.admin_sessions
  SET revoked_at = now()
  WHERE token_hash = encode(extensions.digest(p_session_token, 'sha256'), 'hex')
    AND user_id = v_user_id
    AND revoked_at IS NULL;
END;
$function$;

CREATE OR REPLACE FUNCTION public.rpc_admin_set_password(
  p_user_id uuid,
  p_new_password text,
  p_session_token text
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'public', 'extensions'
AS $function$
BEGIN
  PERFORM public._require_admin_session(p_session_token);
  IF p_new_password IS NULL OR length(p_new_password) < 4 THEN
    RAISE EXCEPTION 'A senha deve ter pelo menos 4 caracteres.';
  END IF;
  IF octet_length(p_new_password) > 72 THEN
    RAISE EXCEPTION 'A senha não pode exceder 72 bytes.';
  END IF;

  UPDATE public.accounts
  SET password = extensions.crypt(p_new_password, extensions.gen_salt('bf', 12))
  WHERE id = p_user_id;

  IF NOT FOUND THEN RAISE EXCEPTION 'Conta não encontrada.'; END IF;

  UPDATE public.admin_sessions
  SET revoked_at = now()
  WHERE user_id = p_user_id AND revoked_at IS NULL;
END;
$function$;

-- Never return the accounts row: it contains the password hash.
CREATE OR REPLACE FUNCTION public.rpc_admin_create_account(
  p_phone text,
  p_password text,
  p_role text,
  p_status text,
  p_event_limit integer,
  p_session_token text
)
RETURNS json
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'public', 'extensions'
AS $function$
DECLARE
  new_row public.accounts%ROWTYPE;
BEGIN
  PERFORM public._require_admin_session(p_session_token);
  IF p_phone IS NULL OR btrim(p_phone) = '' THEN RAISE EXCEPTION 'Telefone/username obrigatório.'; END IF;
  IF p_password IS NULL OR length(p_password) < 4 THEN RAISE EXCEPTION 'A senha deve ter pelo menos 4 caracteres.'; END IF;
  IF octet_length(p_password) > 72 THEN RAISE EXCEPTION 'A senha não pode exceder 72 bytes.'; END IF;
  IF coalesce(p_role, 'user') <> 'user' THEN RAISE EXCEPTION 'Só é permitido criar contas de utilizador.'; END IF;
  IF coalesce(p_status, 'active') NOT IN ('active', 'pending') THEN RAISE EXCEPTION 'Estado de conta inválido.'; END IF;
  IF p_event_limit IS NOT NULL AND p_event_limit < 1 THEN RAISE EXCEPTION 'Limite de eventos inválido.'; END IF;

  INSERT INTO public.accounts (phone, password, role, status, event_limit)
  VALUES (
    btrim(p_phone),
    extensions.crypt(p_password, extensions.gen_salt('bf', 12)),
    'user',
    coalesce(p_status, 'active'),
    p_event_limit
  )
  RETURNING * INTO new_row;

  RETURN json_build_object(
    'id', new_row.id,
    'phone', new_row.phone,
    'role', new_row.role,
    'status', new_row.status,
    'event_limit', new_row.event_limit,
    'created_at', new_row.created_at
  );
END;
$function$;

CREATE OR REPLACE FUNCTION public.rpc_admin_accounts(
  p_session_token text,
  p_action text,
  p_user_id uuid DEFAULT NULL,
  p_role_filter text DEFAULT NULL,
  p_limit integer DEFAULT NULL,
  p_patch jsonb DEFAULT NULL
)
RETURNS json
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'public', 'extensions'
AS $function$
DECLARE
  v_result json;
  v_count bigint;
  v_unknown_keys text[];
BEGIN
  PERFORM public._require_admin_session(p_session_token);

  IF p_action = 'count' THEN
    SELECT count(*) INTO v_count FROM public.accounts;
    RETURN json_build_array(json_build_object('count', v_count));
  ELSIF p_action = 'list' THEN
    SELECT coalesce(json_agg(json_build_object(
      'id', a.id,
      'phone', a.phone,
      'role', a.role,
      'status', a.status,
      'event_limit', a.event_limit,
      'admin_label', a.admin_label,
      'created_at', a.created_at
    ) ORDER BY a.created_at DESC), '[]'::json)
    INTO v_result
    FROM (
      SELECT * FROM public.accounts
      WHERE (p_user_id IS NULL OR id = p_user_id)
        AND (p_role_filter IS NULL OR role = p_role_filter)
      ORDER BY created_at DESC
      LIMIT least(coalesce(p_limit, 500), 500)
    ) a;
    RETURN v_result;
  ELSIF p_action = 'update' THEN
    IF p_user_id IS NULL OR p_patch IS NULL OR jsonb_typeof(p_patch) <> 'object' THEN
      RAISE EXCEPTION 'Pedido administrativo inválido.';
    END IF;

    SELECT array_agg(patch_key.key) INTO v_unknown_keys
    FROM jsonb_object_keys(p_patch) AS patch_key(key)
    WHERE patch_key.key NOT IN ('phone', 'role', 'status', 'event_limit', 'admin_label');
    IF v_unknown_keys IS NOT NULL THEN RAISE EXCEPTION 'Campo de conta não permitido.'; END IF;
    IF p_patch ? 'role' AND p_patch->>'role' NOT IN ('user', 'moderator') THEN
      RAISE EXCEPTION 'A operação não pode atribuir privilégios de administrador.';
    END IF;

    UPDATE public.accounts a SET
      phone = CASE WHEN p_patch ? 'phone' THEN p_patch->>'phone' ELSE a.phone END,
      role = CASE WHEN p_patch ? 'role' THEN p_patch->>'role' ELSE a.role END,
      status = CASE WHEN p_patch ? 'status' THEN p_patch->>'status' ELSE a.status END,
      event_limit = CASE WHEN p_patch ? 'event_limit' THEN (p_patch->>'event_limit')::integer ELSE a.event_limit END,
      admin_label = CASE WHEN p_patch ? 'admin_label' THEN p_patch->>'admin_label' ELSE a.admin_label END
    WHERE a.id = p_user_id;

    IF NOT FOUND THEN RAISE EXCEPTION 'Conta não encontrada.'; END IF;

    SELECT json_build_array(json_build_object(
      'id', a.id,
      'phone', a.phone,
      'role', a.role,
      'status', a.status,
      'event_limit', a.event_limit,
      'admin_label', a.admin_label,
      'created_at', a.created_at
    )) INTO v_result
    FROM public.accounts a WHERE a.id = p_user_id;
    RETURN v_result;
  ELSE
    RAISE EXCEPTION 'Ação administrativa inválida.';
  END IF;
END;
$function$;

-- Retire the legacy account-ID operation. Its former implementation copied
-- and deleted an account row, which violates the no-account-deletion rule.
REVOKE ALL ON FUNCTION public.rpc_admin_change_account_id(uuid, uuid) FROM PUBLIC, anon, authenticated;

-- Remove public execution of the unsafe legacy overloads. The secure overloads
-- below have different signatures and validate the admin session token.
REVOKE ALL ON FUNCTION public.rpc_admin_set_password(uuid, text) FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.rpc_admin_create_account(text, text, text, text, integer) FROM PUBLIC, anon, authenticated;

REVOKE ALL ON FUNCTION public.rpc_admin_logout(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.rpc_admin_set_password(uuid, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.rpc_admin_create_account(text, text, text, text, integer, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.rpc_admin_accounts(text, text, uuid, text, integer, jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.rpc_login(text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.rpc_register(text, text) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION public.rpc_login(text, text) TO anon, authenticated;
GRANT EXECUTE ON FUNCTION public.rpc_register(text, text) TO anon, authenticated;
GRANT EXECUTE ON FUNCTION public.rpc_admin_logout(text) TO anon, authenticated;
GRANT EXECUTE ON FUNCTION public.rpc_admin_set_password(uuid, text, text) TO anon, authenticated;
GRANT EXECUTE ON FUNCTION public.rpc_admin_create_account(text, text, text, text, integer, text) TO anon, authenticated;
GRANT EXECUTE ON FUNCTION public.rpc_admin_accounts(text, text, uuid, text, integer, jsonb) TO anon, authenticated;

COMMIT;

