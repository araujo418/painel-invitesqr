-- Final security cutover. Run only after migration 002, the Edge Function,
-- and the matching GitHub Pages frontend are all deployed and available.
-- This changes permissions/policies only; it does not delete or rewrite data.
BEGIN;

DO $policy_reset$
DECLARE p record;
BEGIN
  FOR p IN SELECT schemaname, tablename, policyname FROM pg_policies
    WHERE schemaname='public' AND tablename IN ('accounts','events','gifts','rsvps')
  LOOP
    EXECUTE format('DROP POLICY IF EXISTS %I ON %I.%I', p.policyname, p.schemaname, p.tablename);
  END LOOP;
END;
$policy_reset$;

ALTER TABLE public.accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.gifts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.rsvps ENABLE ROW LEVEL SECURITY;

-- No direct account-table access, including password hashes. Admins retain
-- the session-checked rpc_admin_accounts RPC.
REVOKE ALL ON TABLE public.accounts FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE public.events, public.gifts, public.rsvps FROM PUBLIC, anon, authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.events, public.gifts, public.rsvps TO anon, authenticated;

CREATE POLICY events_session_read ON public.events FOR SELECT TO anon, authenticated
  USING (user_id = public._current_app_user_id() OR public._current_app_is_admin());
CREATE POLICY events_session_insert ON public.events FOR INSERT TO anon, authenticated
  WITH CHECK (user_id = public._current_app_user_id() OR public._current_app_is_admin());
CREATE POLICY events_session_update ON public.events FOR UPDATE TO anon, authenticated
  USING (user_id = public._current_app_user_id() OR public._current_app_is_admin())
  WITH CHECK (user_id = public._current_app_user_id() OR public._current_app_is_admin());
CREATE POLICY events_session_delete ON public.events FOR DELETE TO anon, authenticated
  USING (user_id = public._current_app_user_id() OR public._current_app_is_admin());

CREATE POLICY gifts_owner_access ON public.gifts FOR ALL TO anon, authenticated
  USING (public._current_app_is_admin() OR EXISTS (
    SELECT 1 FROM public.events e WHERE e.id = gifts.event_id AND e.user_id = public._current_app_user_id()
  ))
  WITH CHECK (public._current_app_is_admin() OR EXISTS (
    SELECT 1 FROM public.events e WHERE e.id = gifts.event_id AND e.user_id = public._current_app_user_id()
  ));
CREATE POLICY rsvps_owner_access ON public.rsvps FOR ALL TO anon, authenticated
  USING (public._current_app_is_admin() OR EXISTS (
    SELECT 1 FROM public.events e WHERE e.id = rsvps.event_id AND e.user_id = public._current_app_user_id()
  ))
  WITH CHECK (public._current_app_is_admin() OR EXISTS (
    SELECT 1 FROM public.events e WHERE e.id = rsvps.event_id AND e.user_id = public._current_app_user_id()
  ));

-- event-covers is already a public bucket, so public image URLs keep working.
-- Remove object listing and anonymous uploads. Authenticated uploads/deletes
-- are handled by the session-checking manage-event-cover Edge Function.
DROP POLICY IF EXISTS "Permitir upload público" ON storage.objects;
DROP POLICY IF EXISTS "Permitir leitura pública" ON storage.objects;

COMMIT;
