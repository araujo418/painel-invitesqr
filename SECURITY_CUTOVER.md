# Segurança do Supabase — sequência de publicação

## Estado actual

No projecto de produção, as migrações `202611040001_admin_session_hardening.sql` e `202611040002_scope_public_access.sql` já foram aplicadas. A migração `202611040003_cutover_scoped_access.sql` ainda não foi aplicada.

A Edge Function `manage-event-cover` ainda tem de ser publicada. Depois deve ser publicada a versão correspondente do site. Só então se aplica a migração 003, que fecha o acesso REST anónimo às tabelas e remove permissões anónimas de upload/listagem no Storage.

## Ordem obrigatória

1. Publicar `supabase/functions/manage-event-cover/index.ts` como a função `manage-event-cover` no projecto `sjjezhvfdblilqqthxtl`.
2. Publicar `index.html` e `js/supabase-secure.js` no branch usado pelo GitHub Pages. O painel e os clientes poderão ter de iniciar sessão novamente para receber uma sessão nova.
3. Confirmar que o site abre, que RSVP e capas estão operacionais e que clientes conseguem entrar.
4. Executar `supabase/migrations/202611040003_cutover_scoped_access.sql` no SQL Editor do Supabase.

**Não executar novamente as migrações 001/002. Não executar a migração 003 antes de os passos 1–3 estarem concluídos.**

As migrações não apagam nem reescrevem contas, eventos, convidados, RSVPs, presentes ou imagens. O link público de cada evento continua a permitir carregar o evento, enviar/editar RSVP e reservar presentes nesse evento. Não foi adicionado código individual nem confirmação por telefone.
