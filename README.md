# ROTINA GERAL · v3.1

Sistema de gestão e controle de rotinas residenciais (PWA instalável).
Gisele Oliveira · Personal Organizer de Alto Padrão.

Todos os arquivos ficam na raiz, sem pastas.

| Arquivo | Função |
|---|---|
| `index.html` | O aplicativo (telas, instruções, verificação; logos embutidas) |
| `manifest.webmanifest`, `sw.js`, `*.png` | Instalação na tela inicial e uso sem internet |
| `api.mjs` | Base compartilhada (Netlify Functions + Netlify Blobs): contas com PIN, permissões, registros com autoria, fotos, avisos, envio de dados antigos e planilha CSV |
| `package.json` | Dependência da API (`@netlify/blobs`) |
| `netlify.toml` | O build copia o app para `public` e posiciona a API; não é preciso configurar o painel |

Variáveis opcionais no Netlify: `ROTINA_CHAVE` (código de ativação para criar residências) e `ROTINA_SEGREDO`.

Para atualizar: "Add file › Upload files", selecionar os arquivos novos e "Commit changes".
