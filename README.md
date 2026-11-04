# Painel InvitesQR

## Publicação da versão segura

Esta versão usa sessões de aplicação com validade de 8 horas e operações limitadas no Supabase. A recuperação do acesso administrativo continua a usar o painel existente; contas, eventos, convidados, RSVPs, presentes e imagens não são apagados nem reescritos.

O RSVP continua acessível pelo link público do evento. Não foi acrescentado código individual de convite nem confirmação por telefone.

### Estado da preparação

- `202611040001_admin_session_hardening.sql`: já aplicado no projeto de produção.
- `202611040002_scope_public_access.sql`: já aplicado no projeto de produção.
- Edge Function `manage-event-cover`: ainda precisa de ser publicada no Supabase.
- `202611040003_cutover_scoped_access.sql`: ainda não aplicar. Executar só depois de a função e o novo site estarem publicados e acessíveis.

### Ordem de publicação

1. Publicar a Edge Function `manage-event-cover` no projecto Supabase `sjjezhvfdblilqqthxtl`.
2. Publicar o conteúdo desta pasta no repositório que serve o GitHub Pages. `index.html` fica na raiz e o ficheiro `js/supabase-secure.js` mantém-se dentro de `js/`.
3. Confirmar que o site publicado abre e que as operações de RSVP e as capas funcionam. Os utilizadores podem ter de iniciar sessão novamente para receber a nova sessão.
4. Só então executar `supabase/migrations/202611040003_cutover_scoped_access.sql` no SQL Editor do Supabase.

Não execute novamente as migrações 001 e 002. Não aplique a 003 antes dos passos 1 e 2.
