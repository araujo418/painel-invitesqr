-- Preparation phase for the legacy custom-auth InvitesQR app.
-- Creates short-lived sessions and narrow public RPCs without changing the
-- existing table/storage policies. Apply and deploy the matching frontend
-- before running migration 202611040003_cutover_scoped_access.sql.
BEGIN;

CREATE TABLE IF NOT EXISTS public.app_sessions (
  token_hash text PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES public.accounts(id) ON DELETE RESTRICT,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz
);
CREATE TABLE IF NOT EXISTS public.admin_sessions (
  token_hash text PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES public.accounts(id) ON DELETE RESTRICT,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz
);
CREATE INDEX IF NOT EXISTS app_sessions_user_expiry_idx
  ON public.app_sessions (user_id, expires_at);
ALTER TABLE public.app_sessions ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.app_sessions FROM PUBLIC, anon, authenticated;

CREATE OR REPLACE FUNCTION public._current_app_user_id()
RETURNS uuid
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path TO 'public', 'extensions'
AS $function$
DECLARE
  v_header text;
  v_token text;
  v_user_id uuid;
BEGIN
  BEGIN
    v_header := current_setting('request.headers', true)::jsonb ->> 'x-client-info';
  EXCEPTION WHEN OTHERS THEN
    RETURN NULL;
  END;
  IF v_header IS NULL OR position('invitesqr/' IN v_header) = 0 THEN RETURN NULL; END IF;
  v_token := split_part(v_header, 'invitesqr/', 2);
  v_token := split_part(v_token, ' ', 1);
  IF length(v_token) <> 64 OR v_token !~ '^[0-9a-f]{64}$' THEN RETURN NULL; END IF;

  SELECT s.user_id INTO v_user_id
  FROM public.app_sessions s
  JOIN public.accounts a ON a.id = s.user_id
  WHERE s.token_hash = encode(extensions.digest(v_token, 'sha256'), 'hex')
    AND s.revoked_at IS NULL AND s.expires_at > now()
    AND a.status = 'active'
  LIMIT 1;
  RETURN v_user_id;
END;
$function$;
REVOKE ALL ON FUNCTION public._current_app_user_id() FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public._current_app_user_id() TO anon, authenticated;

CREATE OR REPLACE FUNCTION public._current_app_is_admin()
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path TO 'public'
AS $function$
  SELECT EXISTS (
    SELECT 1 FROM public.accounts a
    WHERE a.id = public._current_app_user_id()
      AND a.role = 'admin' AND a.status = 'active'
  );
$function$;
REVOKE ALL ON FUNCTION public._current_app_is_admin() FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public._current_app_is_admin() TO anon, authenticated;

-- Issue a short-lived opaque token on the existing phone/password login.
-- Admins receive the same token in the legacy admin session table so existing
-- secure admin RPCs keep working. Passwords and business rows are untouched.
CREATE OR REPLACE FUNCTION public.rpc_login(p_phone text, p_password text)
RETURNS json
LANGUAGE plpgsql SECURITY DEFINER
SET search_path TO 'public', 'extensions'
AS $function$
DECLARE
  acc record;
  senha_ok boolean;
  v_token text;
BEGIN
  SELECT id, phone, password, role, status, event_limit
  INTO acc FROM public.accounts WHERE phone = p_phone LIMIT 1;
  IF acc.id IS NULL THEN RAISE EXCEPTION 'Conta não encontrada.'; END IF;
  IF acc.status = 'deleted' THEN RAISE EXCEPTION 'DELETED';
  ELSIF acc.status = 'blocked' THEN RAISE EXCEPTION 'BLOCKED';
  ELSIF acc.status = 'pending' THEN RAISE EXCEPTION 'PENDING'; END IF;

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

  v_token := encode(extensions.gen_random_bytes(32), 'hex');
  INSERT INTO public.app_sessions(token_hash, user_id, expires_at)
  VALUES (encode(extensions.digest(v_token, 'sha256'), 'hex'), acc.id, now() + interval '8 hours');
  IF acc.role = 'admin' THEN
    INSERT INTO public.admin_sessions(token_hash, user_id, expires_at)
    VALUES (encode(extensions.digest(v_token, 'sha256'), 'hex'), acc.id, now() + interval '8 hours');
  END IF;
  RETURN json_build_object(
    'id', acc.id, 'phone', acc.phone, 'role', acc.role, 'status', acc.status,
    'event_limit', acc.event_limit, 'app_session_token', v_token,
    'admin_session_token', CASE WHEN acc.role = 'admin' THEN v_token ELSE NULL END
  );
END;
$function$;

CREATE OR REPLACE FUNCTION public.rpc_app_logout(p_session_token text)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path TO 'public', 'extensions'
AS $function$
BEGIN
  IF p_session_token IS NULL OR p_session_token !~ '^[0-9a-f]{64}$' THEN RETURN; END IF;
  UPDATE public.app_sessions SET revoked_at = now()
  WHERE token_hash = encode(extensions.digest(p_session_token, 'sha256'), 'hex')
    AND revoked_at IS NULL;
  UPDATE public.admin_sessions SET revoked_at = now()
  WHERE token_hash = encode(extensions.digest(p_session_token, 'sha256'), 'hex')
    AND revoked_at IS NULL;
END;
$function$;

-- A password reset revokes both administrative and normal app sessions for
-- that account immediately, rather than waiting for the 8-hour expiry.
CREATE OR REPLACE FUNCTION public.rpc_admin_set_password(
  p_user_id uuid, p_new_password text, p_session_token text
)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
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
  UPDATE public.admin_sessions SET revoked_at = now()
  WHERE user_id = p_user_id AND revoked_at IS NULL;
  UPDATE public.app_sessions SET revoked_at = now()
  WHERE user_id = p_user_id AND revoked_at IS NULL;
END;
$function$;

-- Event links remain the public capability. Reads are limited to one event;
-- the page's existing guest flow still receives its event, gifts and RSVP list.
CREATE OR REPLACE FUNCTION public.rpc_public_get_event(p_event_code text)
RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path TO 'public'
AS $function$
DECLARE
  e public.events%ROWTYPE;
  v_result jsonb;
BEGIN
  SELECT * INTO e FROM public.events
  WHERE event_code = p_event_code OR id = p_event_code
  ORDER BY CASE WHEN event_code = p_event_code THEN 0 ELSE 1 END
  LIMIT 1;
  IF e.id IS NULL THEN RETURN '[]'::jsonb; END IF;

  SELECT jsonb_build_array(
    jsonb_build_object(
      'id', e.id, 'title', e.title, 'date', e.date, 'time', e.time,
      'confirm_by_date', e.confirm_by_date, 'cover_image', e.cover_image,
      'allow_companions', e.allow_companions, 'max_companions', e.max_companions,
      'allow_gifts', e.allow_gifts, 'allow_kids', e.allow_kids, 'max_kids', e.max_kids,
      'allow_sides', e.allow_sides, 'side1_name', e.side1_name, 'side2_name', e.side2_name,
      'show_time', e.show_time, 'allow_messages', e.allow_messages,
      'show_guest_messages', e.show_guest_messages, 'extra_fields', e.extra_fields,
      'rsvp_links', e.rsvp_links, 'event_code', e.event_code,
      'rsvps', coalesce((
        SELECT jsonb_agg(jsonb_build_object(
          'guest_name', r.guest_name, 'attending', r.attending, 'side', r.side,
          'companions', r.companions, 'kids', r.kids, 'wants_gift', r.wants_gift,
          'message', r.message, 'extra_data', r.extra_data, 'link_key', r.link_key,
          'created_at', r.created_at, 'updated_at', r.updated_at
        ) ORDER BY r.created_at)
        FROM public.rsvps r WHERE r.event_id = e.id
      ), '[]'::jsonb),
      'gifts', coalesce((
        SELECT jsonb_agg(jsonb_build_object(
          'id', g.id, 'name', g.name, 'category', g.category,
          'reserved', g.reserved, 'reserved_by', g.reserved_by
        ) ORDER BY g.created_at)
        FROM public.gifts g WHERE g.event_id = e.id
      ), '[]'::jsonb)
    )
  ) INTO v_result;
  RETURN v_result;
END;
$function$;

-- Preserve current RSVP form semantics: the event link permits an RSVP for
-- this event. A matching name can update the existing row, as before.
CREATE OR REPLACE FUNCTION public.rpc_public_upsert_rsvp(
  p_event_code text, p_payload jsonb, p_original_name text DEFAULT NULL
)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER
SET search_path TO 'public'
AS $function$
DECLARE
  e public.events%ROWTYPE;
  v_name text;
  v_original text;
  v_existing_id uuid;
  v_row public.rsvps%ROWTYPE;
BEGIN
  IF jsonb_typeof(p_payload) <> 'object' THEN RAISE EXCEPTION 'Dados do RSVP inválidos.'; END IF;
  IF octet_length(p_payload::text) > 16000 THEN RAISE EXCEPTION 'Dados do RSVP excedem o limite.'; END IF;
  SELECT * INTO e FROM public.events
  WHERE event_code = p_event_code OR id = p_event_code
  ORDER BY CASE WHEN event_code = p_event_code THEN 0 ELSE 1 END LIMIT 1;
  IF e.id IS NULL THEN RAISE EXCEPTION 'Evento não encontrado.'; END IF;
  IF e.allow_rsvp IS FALSE THEN RAISE EXCEPTION 'Este evento não está a aceitar confirmações.'; END IF;
  v_name := left(btrim(coalesce(p_payload->>'guest_name','')), 200);
  IF v_name = '' THEN RAISE EXCEPTION 'O nome é obrigatório.'; END IF;
  v_original := left(btrim(coalesce(nullif(p_original_name,''), v_name)), 200);

  PERFORM pg_advisory_xact_lock(hashtextextended(e.id || ':' || lower(v_original), 0));
  SELECT id INTO v_existing_id FROM public.rsvps
  WHERE event_id = e.id AND lower(btrim(guest_name)) = lower(v_original)
  ORDER BY created_at LIMIT 1;

  IF v_existing_id IS NOT NULL THEN
    UPDATE public.rsvps SET
      guest_name = v_name,
      attending = coalesce((p_payload->>'attending')::boolean, false),
      side = left(coalesce(p_payload->>'side',''), 80),
      companions = left(coalesce(p_payload->>'companions',''), 2000),
      kids = left(coalesce(p_payload->>'kids',''), 2000),
      wants_gift = coalesce((p_payload->>'wants_gift')::boolean, false),
      gift_ids = left(coalesce(p_payload->>'gift_ids',''), 2000),
      message = left(coalesce(p_payload->>'message',''), 2000),
      extra_data = CASE WHEN p_payload ? 'extra_data' THEN p_payload->'extra_data' ELSE extra_data END,
      link_key = left(coalesce(p_payload->>'link_key', link_key, ''), 200),
      updated_at = now()
    WHERE id = v_existing_id RETURNING * INTO v_row;
  ELSE
    INSERT INTO public.rsvps(event_id, guest_name, attending, side, companions, kids,
      wants_gift, gift_ids, message, extra_data, link_key)
    VALUES (e.id, v_name, coalesce((p_payload->>'attending')::boolean, false),
      left(coalesce(p_payload->>'side',''),80), left(coalesce(p_payload->>'companions',''),2000),
      left(coalesce(p_payload->>'kids',''),2000), coalesce((p_payload->>'wants_gift')::boolean,false),
      left(coalesce(p_payload->>'gift_ids',''),2000), left(coalesce(p_payload->>'message',''),2000),
      CASE WHEN p_payload ? 'extra_data' THEN p_payload->'extra_data' ELSE '{}'::jsonb END,
      left(coalesce(p_payload->>'link_key',''),200))
    RETURNING * INTO v_row;
  END IF;
  RETURN jsonb_build_object('id',v_row.id,'event_id',v_row.event_id,'guest_name',v_row.guest_name,
    'attending',v_row.attending,'side',v_row.side,'companions',v_row.companions,'kids',v_row.kids,
    'wants_gift',v_row.wants_gift,'gift_ids',v_row.gift_ids,'message',v_row.message,
    'extra_data',v_row.extra_data,'link_key',v_row.link_key,'created_at',v_row.created_at,
    'updated_at',v_row.updated_at);
END;
$function$;

-- The public gift operation can reserve/release only a gift belonging to the
-- event whose existing public link was opened. It cannot create/delete gifts.
CREATE OR REPLACE FUNCTION public.rpc_public_reserve_gift(
  p_event_code text, p_gift_id uuid, p_reserved boolean, p_reserved_by text
)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER
SET search_path TO 'public'
AS $function$
DECLARE
  e public.events%ROWTYPE;
  v_gift public.gifts%ROWTYPE;
  v_name text := left(btrim(coalesce(p_reserved_by,'')),200);
BEGIN
  SELECT * INTO e FROM public.events
  WHERE event_code = p_event_code OR id = p_event_code
  ORDER BY CASE WHEN event_code = p_event_code THEN 0 ELSE 1 END LIMIT 1;
  IF e.id IS NULL THEN RAISE EXCEPTION 'Evento não encontrado.'; END IF;
  IF lower(coalesce(e.allow_gifts,'')) NOT IN ('yes','true') THEN RAISE EXCEPTION 'Presentes desativados neste evento.'; END IF;
  IF p_reserved AND v_name = '' THEN RAISE EXCEPTION 'O nome é obrigatório para reservar.'; END IF;

  UPDATE public.gifts SET reserved = p_reserved,
    reserved_by = CASE WHEN p_reserved THEN v_name ELSE NULL END
  WHERE id = p_gift_id AND event_id = e.id
    AND (coalesce(reserved,false) = false
      OR lower(btrim(coalesce(reserved_by,''))) = lower(v_name))
  RETURNING * INTO v_gift;
  IF v_gift.id IS NULL THEN RAISE EXCEPTION 'Presente indisponível ou não pertence a este evento.'; END IF;
  RETURN jsonb_build_object('id',v_gift.id,'event_id',v_gift.event_id,'name',v_gift.name,
    'category',v_gift.category,'reserved',v_gift.reserved,'reserved_by',v_gift.reserved_by);
END;
$function$;

REVOKE ALL ON FUNCTION public.rpc_login(text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.rpc_app_logout(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.rpc_public_get_event(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.rpc_public_upsert_rsvp(text,jsonb,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.rpc_public_reserve_gift(text,uuid,boolean,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.rpc_login(text,text) TO anon, authenticated;
GRANT EXECUTE ON FUNCTION public.rpc_app_logout(text) TO anon, authenticated;
GRANT EXECUTE ON FUNCTION public.rpc_public_get_event(text) TO anon, authenticated;
GRANT EXECUTE ON FUNCTION public.rpc_public_upsert_rsvp(text,jsonb,text) TO anon, authenticated;
GRANT EXECUTE ON FUNCTION public.rpc_public_reserve_gift(text,uuid,boolean,text) TO anon, authenticated;

COMMIT;
