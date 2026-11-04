# Painel InvitesQR

## Segurança do painel e do Supabase

O painel usa uma sessão administrativa aleatória, com validade de 8 horas. O token fica apenas no `sessionStorage` do navegador e o banco guarda somente o hash SHA-256. As RPCs administrativas de criar conta e redefinir senha validam a sessão; a listagem e atualização de contas passam por uma RPC que nunca devolve o hash da senha. O login e o registo de clientes continuam usando as mesmas RPCs.

### Publicação coordenada

Para reativar as operações administrativas bloqueadas no projeto de produção, publique a migração SQL e os ficheiros do site na mesma janela de manutenção:

1. No SQL Editor do projeto Supabase, execute `supabase/migrations/202611040001_admin_session_hardening.sql`.
2. Publique `index.html` e `js/supabase-secure.js` juntos. O ficheiro da raiz `supabase-secure.js` é uma cópia de compatibilidade.
3. O administrador precisa entrar novamente para receber a nova sessão.

Não publique apenas um dos lados: a migração exige o novo token no painel, e o painel novo precisa das RPCs da migração. A migração não apaga nem altera linhas de clientes, contas, eventos, RSVPs ou presentes. A antiga operação de alterar ID permanece desativada porque copiava e apagava a conta anterior.

## Recuperação da senha admin

Abra `RECUPERAR-ADMIN.html` localmente no seu computador. A página não contacta nem altera o Supabase; ela prepara uma instrução SQL para executar manualmente no SQL Editor do projeto.

Não publique `RECUPERAR-ADMIN.html` no site. A nova senha é incluída na instrução SQL gerada. Execute a instrução apenas no seu projeto Supabase, não guarde a consulta e apague-a do histórico do SQL Editor, se disponível.

O SQL valida username e `role = 'admin'` e falha se não alterar exatamente uma conta. A conta pré-preenchida é `adkira@admin.com`; confirme o username antes de executar.
