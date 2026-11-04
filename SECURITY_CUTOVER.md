# Segurança do Supabase — sequência de publicação

As duas migrações de segurança estão separadas para evitar uma janela em que
os convidados ou organizadores percam acesso.

## O que foi preparado

- O login existente continua a usar telefone/username e senha. Passa a emitir
  um token aleatório de sessão válido por 8 horas; apenas o hash fica no banco.
- Organizadores e administradores só consultam ou alteram eventos, RSVPs e
  presentes da sua conta, com as operações administrativas verificadas no
  banco.
- O link público continua a carregar o evento, confirmar/editar RSVP e reservar
  presentes dentro daquele evento. Não foi adicionado código por convidado nem
  confirmação por telefone.
- Upload e remoção de capas passam por `manage-event-cover`, que verifica a
  sessão e a propriedade do evento. O bucket continua público para exibir as
  imagens já existentes.
- As migrações não apagam nem reescrevem contas, eventos, convidados, RSVPs,
  presentes ou imagens.

## Ordem obrigatória

1. Aplicar `202611040001_admin_session_hardening.sql` (se ainda não estiver
   aplicado) e depois `202611040002_scope_public_access.sql`. Esta fase apenas
   prepara sessões e RPCs; as regras públicas atuais continuam temporariamente
   ativas.
2. Publicar a Edge Function:

   ```sh
   supabase functions deploy manage-event-cover --project-ref sjjezhvfdblilqqthxtl
   ```

3. Publicar os arquivos do site deste pacote no branch usado pelo GitHub Pages.
   O usuário precisa entrar novamente após a publicação para receber uma sessão.
4. Confirmar que o site publicado carrega links de evento, RSVP e capas. Só
   então aplicar `202611040003_cutover_scoped_access.sql` no SQL Editor.
5. Verificar: login do administrador, login de um cliente, painel do cliente,
   link público de convite, envio/edição de RSVP, reserva de presente e exibição
   de capa pública. A última migração fecha o acesso REST anónimo às tabelas e
   remove upload/listagem anónimos do Storage.

**Não aplicar a migração 003 antes de os passos 1–3 estarem publicados.** Se o
site ainda estiver na versão antiga, os convidados e organizadores deixam de
conseguir usar as chamadas diretas que ela faz hoje.

Não foi feita qualquer alteração no projeto de produção durante esta
preparação; as permissões atuais só mudam quando a migração 003 for aplicada.
