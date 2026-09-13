# BM Business ↔ Bissau Market

A integração é server-to-server. O BM Business deve enviar somente a projeção pública de um produto depois de o vendedor o validar e publicar.

## Nunca enviar

- palavra-passe ou tokens de utilizadores;
- dados privados de clientes;
- custo de aquisição;
- margem/lucro;
- relatórios internos;
- configurações privadas da loja;
- logs de auditoria.

## Segurança

O destino deve autenticar a chamada por chave/API credential, validar o JSON e confirmar o `storeId` autorizado. A publicação no BM Business só deve ser marcada como concluída depois de resposta HTTP 2xx do destino.
