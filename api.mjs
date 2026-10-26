// ROTINA GERAL · API da residência conectada (Netlify Functions + Netlify Blobs)
//
// Perfis: "admin" (responsável pela residência) e "colaboradora".
// Toda permissão é conferida aqui no servidor; o app só esconde botões por conveniência.
//
// Chaves no armazenamento (store "rotina-geral"):
//   _cfg/segredo                 segredo de assinatura das sessões (criado no primeiro uso)
//   h/{casa}/meta                residência, usuários (PIN com hash), convites
//   h/{casa}/rotina              rotina completa (dias, tarefas, instruções, frases) + revisão
//   h/{casa}/dia/{data}          execução do dia: estado de cada tarefa e histórico de eventos
//   h/{casa}/foto/{data}/{id}    fotografias (evidências)
//   h/{casa}/hash/{sha256}       índice para identificar a reutilização de uma mesma foto
//   h/{casa}/notif/{usuario}     notificações internas
//   h/{casa}/audit               histórico de alterações de rotina e de usuários
import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";

const STORE = "rotina-geral";
const ALPHA = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const DIA = 86400000;
const SESSAO_DIAS = 180;
const LABEL = {pendente:"pendente", andamento:"em andamento", pausada:"pausada", aguardando:"aguardando verificação",
  concluida:"concluída", aprovada:"aprovada", correcao:"em correção", impossivel:"não realizada"};
const FEITOS = ["aguardando", "concluida", "aprovada", "impossivel"];

class HttpError extends Error { constructor(status, msg, extra){ super(msg); this.status = status; this.extra = extra; } }
const fail = (status, msg, extra) => { throw new HttpError(status, msg, extra); };
const json = (data, status = 200) => new Response(JSON.stringify(data), {status,
  headers: {"Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store"}});

const rid = (n = 12) => { let s = ""; for (const x of crypto.randomBytes(n)) s += ALPHA[x % 32]; return s; };
const b64u = buf => Buffer.from(buf).toString("base64url");
const sha256 = data => crypto.createHash("sha256").update(data).digest("hex");
const str = (v, max = 1000) => String(v ?? "").trim().slice(0, max);

/* ---------- datas (a residência tem fuso horário próprio) ---------- */
const WEEK = ["seg", "ter", "qua", "qui", "sex", "sab", "dom"];
const isDate = s => typeof s === "string" && /^\d{4}-\d{2}-\d{2}$/.test(s) && new Date(s + "T12:00:00Z").toISOString().slice(0, 10) === s;
const todayIn = tz => new Intl.DateTimeFormat("en-CA", {timeZone: tz, year: "numeric", month: "2-digit", day: "2-digit"}).format(new Date());
const horaIn = (tz, ms) => new Intl.DateTimeFormat("pt-BR", {timeZone: tz, hour: "2-digit", minute: "2-digit"}).format(new Date(ms));
const dataHoraIn = (tz, ms) => ms ? new Intl.DateTimeFormat("pt-BR", {timeZone: tz, day: "2-digit", month: "2-digit", year: "numeric", hour: "2-digit", minute: "2-digit"}).format(new Date(ms)).replace(",", "") : "";
const minutesIn = tz => { const [h, m] = new Intl.DateTimeFormat("en-GB", {timeZone: tz, hour: "2-digit", minute: "2-digit", hourCycle: "h23"}).format(new Date()).split(":").map(Number); return h * 60 + m; };
const weekdayOf = d => WEEK[(new Date(d + "T12:00:00Z").getUTCDay() + 6) % 7];
const addDaysISO = (d, n) => { const x = new Date(d + "T12:00:00Z"); x.setUTCDate(x.getUTCDate() + n); return x.toISOString().slice(0, 10); };
const validTz = tz => { try { new Intl.DateTimeFormat("en", {timeZone: tz}); return true; } catch { return false; } };

/* ---------- armazenamento com escrita condicional (evita que um aparelho apague o registro de outro) ---------- */
const getJSON = (store, key) => store.get(key, {type: "json"});
async function update(store, key, fn){
  for (let i = 0; i < 8; i++) {
    const cur = await store.getWithMetadata(key, {type: "json"});
    const data = cur ? cur.data : null;
    const next = await fn(data === null ? null : structuredClone(data));
    if (next === undefined) return data;
    const res = cur ? await store.setJSON(key, next, {onlyIfMatch: cur.etag}) : await store.setJSON(key, next, {onlyIfNew: true});
    if (res.modified) return next;
  }
  fail(409, "Muitas alterações ao mesmo tempo. Tente novamente em instantes.");
}

/* ---------- sessões assinadas e PIN ---------- */
async function segredo(store){
  const env = (globalThis.Netlify?.env?.get?.("ROTINA_SEGREDO")) || process.env.ROTINA_SEGREDO;
  if (env) return env;
  let s = await store.get("_cfg/segredo", {type: "text"});
  if (!s) {
    const novo = b64u(crypto.randomBytes(32));
    const r = await store.set("_cfg/segredo", novo, {onlyIfNew: true});
    s = r.modified ? novo : await store.get("_cfg/segredo", {type: "text"});
  }
  return s;
}
const assinar = (sec, payload) => { const p = b64u(JSON.stringify(payload)); return p + "." + b64u(crypto.createHmac("sha256", sec).update(p).digest()); };
function conferir(sec, token){
  const [p, s] = String(token || "").split(".");
  if (!p || !s) return null;
  const esperado = b64u(crypto.createHmac("sha256", sec).update(p).digest());
  if (s.length !== esperado.length || !crypto.timingSafeEqual(Buffer.from(s), Buffer.from(esperado))) return null;
  try { const o = JSON.parse(Buffer.from(p, "base64url").toString()); return o.exp > Date.now() ? o : null; } catch { return null; }
}
const pinValido = p => /^\d{6}$/.test(String(p || ""));
const hashPin = (pin, salt) => crypto.pbkdf2Sync(String(pin), salt, 120000, 32, "sha256").toString("base64url");
const novoPin = pin => { const salt = b64u(crypto.randomBytes(16)); return {salt, hash: hashPin(pin, salt)}; };
const pinConfere = (pin, reg) => { if (!reg) return false; const a = Buffer.from(hashPin(pin, reg.salt)), b = Buffer.from(reg.hash); return a.length === b.length && crypto.timingSafeEqual(a, b); };
const emitir = async (store, casa, u) => assinar(await segredo(store), {h: casa, u: u.id, tv: u.tv, exp: Date.now() + SESSAO_DIAS * DIA});

async function autenticar(req, store){
  const token = (req.headers.get("authorization") || "").replace(/^Bearer\s+/i, "");
  const p = conferir(await segredo(store), token);
  if (!p) fail(401, "Sessão expirada. Entre novamente com o seu PIN.");
  const meta = await getJSON(store, `h/${p.h}/meta`);
  const user = meta && meta.usuarios[p.u];
  if (!user || !user.ativo || user.tv !== p.tv) fail(401, "Acesso encerrado neste aparelho. Entre novamente com o seu PIN.");
  return {casa: p.h, U: p.u, user, meta, admin: user.papel === "admin"};
}
const exigirAdmin = c => { if (!c.admin) fail(403, "Somente a administradora da residência pode fazer isso."); };
const usuariosPublicos = meta => Object.values(meta.usuarios).map(u => ({id: u.id, nome: u.nome, papel: u.papel, ativo: u.ativo, pendente: !u.pin}));
const admins = meta => Object.values(meta.usuarios).filter(u => u.ativo && u.papel === "admin").map(u => u.id);

/* ---------- rotina: tarefas de uma data ---------- */
function tarefasDoDia(rot, data){
  const wd = weekdayOf(data), dia = (rot.days || []).find(d => d.id === wd), out = [];
  if (dia && dia.active) {
    for (const b of dia.blocks || []) for (const t of b.tasks || []) if (str(t.t)) out.push({...t, bloco: {name: b.name, time: b.time || ""}});
    for (const c of rot.closing || []) if (str(c.t)) out.push({...c, id: `${wd}-${c.id}`, nivel: 1, bloco: {name: "Conferência final", time: ""}});
  }
  for (const x of rot.extras || []) if (x.data === data && str(x.t)) out.push({...x, bloco: {name: "Atividades extraordinárias", time: x.hora || ""}});
  return out;
}
// prazo em minutos do dia: fim do horário do bloco ("08:00 – 08:40") ou início + 60 min
function prazo(t){
  const hs = String(t.bloco.time || "").match(/\d{1,2}[:h]\d{2}/g);
  if (!hs) return null;
  const m = hs.map(x => { const [h, mm] = x.split(/[:h]/).map(Number); return h * 60 + mm; });
  return m.length > 1 ? m[m.length - 1] : m[0] + 60;
}
const novoRegistro = id => ({id, status: "pendente", ciclo: 1, v: 0, checklist: {}, fotos: [], eventos: []});

/* ---------- notificações e auditoria ---------- */
async function notificar(store, c, para, n){
  const ids = [...new Set(para)].filter(id => id && c.meta.usuarios[id] && c.meta.usuarios[id].ativo);
  for (const id of ids) {
    const off = (c.meta.usuarios[id].prefs || {}).off || [];
    if (off.includes(n.tipo)) continue;
    await update(store, `h/${c.casa}/notif/${id}`, cur => {
      cur = cur || {itens: []};
      cur.itens.unshift({id: rid(8), em: Date.now(), lida: false, ...n});
      cur.itens = cur.itens.slice(0, 100);
      return cur;
    });
  }
}
async function auditar(store, casa, item){
  await update(store, `h/${casa}/audit`, cur => {
    cur = cur || {itens: []};
    cur.itens.unshift({em: Date.now(), ...item});
    cur.itens = cur.itens.slice(0, 500);
    return cur;
  });
}

/* ---------- regras do fluxo de verificação ---------- */
function aplicar(rec, task, a, c, avisos){
  const agora = Date.now(), st = rec.status, nivel = Math.min(4, Math.max(1, +task.nivel || 1));
  const txt = str(a.txt);
  const ev = {id: a.id, tipo: a.tipo, por: c.U, nome: c.user.nome, em: agora};
  // quando outra pessoa mexeu na atividade antes, o aviso diz quem foi e quando
  const quem = () => rec.alteradoPor && rec.alteradoPor !== c.U && c.meta.usuarios[rec.alteradoPor]
    ? ` Última alteração feita por ${c.meta.usuarios[rec.alteradoPor].nome} às ${horaIn(c.meta.tz, rec.alteradoEm)}.` : "";
  const exigir = (ok, msg) => { if (!ok) fail(409, msg + quem()); };
  const checklist = task.checklist || [];
  switch (a.tipo) {
    case "iniciar":
      exigir(["pendente", "correcao"].includes(st), `Esta atividade não pode ser iniciada agora (${LABEL[st]}).`);
      if (task.procObrig) exigir(a.leu === true, "Abra e confirme a leitura das instruções antes de iniciar.");
      rec.status = "andamento"; rec.iniciadoEm = agora; rec.iniciadoPor = c.U; if (a.leu) ev.leu = true;
      break;
    case "pausar":
      exigir(st === "andamento", "Só é possível pausar uma atividade em andamento.");
      rec.status = "pausada"; if (txt) ev.txt = txt;
      break;
    case "retomar":
      exigir(st === "pausada", "Esta atividade não está pausada.");
      rec.status = "andamento";
      break;
    case "check": {
      exigir(["andamento", "pausada"].includes(st), "Inicie a atividade para marcar o checklist.");
      const i = Number(a.item);
      exigir(Number.isInteger(i) && i >= 0 && i < checklist.length, "Item de checklist inválido.");
      rec.checklist[i] = !!a.valor; rec.v++; carimbar(rec, c, agora);
      return; // marcação de item não gera evento: o estado final vai junto com o envio
    }
    case "obs": {
      // não sobrescreve em silêncio a observação de outra pessoa feita depois da versão que esta pessoa viu
      const atual = rec.obs || "";
      const deOutra = atual && rec.obsPor && rec.obsPor !== c.U && atual !== txt;
      if (deOutra && !a.forcar && (rec.obsEm || 0) > (Number(a.base) || 0))
        fail(409, `${rec.obsNome || "Outra pessoa"} alterou esta observação às ${horaIn(c.meta.tz, rec.obsEm)}. Confira antes de salvar.`, {conflito: {txt: atual, nome: rec.obsNome || "", em: rec.obsEm}});
      if (deOutra && a.forcar) avisos.push({para: rec.obsPor, tipo: "alteracao", texto: `${c.user.nome} substituiu a sua observação em "${task.t}".`});
      rec.obs = txt; rec.obsPor = c.U; rec.obsNome = c.user.nome; rec.obsEm = agora; ev.txt = txt;
      break;
    }
    case "registrar": {
      const permitido = nivel === 1 ? ["pendente", "andamento", "pausada", "correcao"] : ["andamento", "pausada"];
      exigir(permitido.includes(st), nivel === 1 ? `Esta atividade não pode ser registrada agora (${LABEL[st]}).` : "Inicie a atividade antes de enviar.");
      if (task.procObrig && ["pendente", "correcao"].includes(st)) exigir(a.leu === true, "Abra e confirme a leitura das instruções antes de registrar.");
      if (nivel === 2 || nivel === 4) exigir(checklist.every((_, i) => rec.checklist[i]), "Confirme todos os itens do checklist antes de enviar.");
      if (nivel >= 3) {
        const f = rec.fotos.filter(x => x.ciclo === rec.ciclo);
        exigir(f.some(x => x.tipo === "depois"), "Envie a foto DEPOIS antes de enviar para verificação.");
        if (task.fotoAntes) exigir(f.some(x => x.tipo === "antes"), "Envie a foto ANTES antes de enviar para verificação.");
      }
      if (["pendente", "correcao"].includes(st)) { rec.iniciadoEm = agora; rec.iniciadoPor = c.U; }
      if (a.leu) ev.leu = true;
      rec.status = nivel >= 3 ? "aguardando" : "concluida";
      rec.enviadoEm = agora; rec.enviadoPor = c.U;
      if (checklist.length) ev.checklist = checklist.map((_, i) => !!rec.checklist[i]);
      if (rec.status === "aguardando") avisos.push({para: "admins", tipo: "verificacao", texto: `${c.user.nome} enviou para verificação: ${task.t}`});
      break;
    }
    case "aprovar":
      exigir(["aguardando", "concluida"].includes(st), "Esta atividade não está aguardando verificação.");
      if (rec.enviadoPor === c.U) fail(403, "Quem executou a atividade não pode aprová-la.");
      rec.status = "aprovada"; rec.aprovadoEm = agora; rec.aprovadoPor = c.U;
      avisos.push({para: rec.enviadoPor, tipo: "aprovada", texto: `Atividade aprovada: ${task.t}`});
      break;
    case "devolver":
      exigir(["aguardando", "concluida", "aprovada"].includes(st), "Esta atividade ainda não foi registrada.");
      exigir(txt.length >= 5, "Descreva objetivamente o que precisa ser corrigido.");
      rec.status = "correcao"; rec.motivo = txt; ev.txt = txt;
      rec.ciclo++; rec.checklist = {}; rec.correcoes = (rec.correcoes || 0) + 1;
      delete rec.aprovadoEm; delete rec.aprovadoPor;
      avisos.push({para: rec.enviadoPor, tipo: "correcao", texto: `Correção solicitada em "${task.t}": ${txt}`});
      break;
    case "reabrir": {
      const proprio = rec.enviadoPor === c.U && st === "concluida";
      exigir(c.admin ? ["concluida", "aprovada", "impossivel", "aguardando"].includes(st) : proprio,
        c.admin ? "Esta atividade não pode ser reaberta." : "Só é possível desfazer um registro próprio que ainda não foi verificado.");
      rec.status = "pendente"; delete rec.enviadoEm; delete rec.aprovadoEm; delete rec.aprovadoPor;
      if (txt) ev.txt = txt;
      break;
    }
    case "impossivel":
      exigir(!["aprovada", "concluida", "aguardando"].includes(st), "Esta atividade já foi registrada.");
      exigir(txt.length >= 3, "Explique por que não foi possível realizar a atividade.");
      rec.status = "impossivel"; rec.motivoImp = txt; ev.txt = txt;
      avisos.push({para: "admins", tipo: "impossivel", texto: `${c.user.nome} não conseguiu realizar "${task.t}": ${txt}`});
      break;
    case "duvida":
      exigir(txt.length >= 3, "Escreva a sua dúvida.");
      ev.txt = txt;
      avisos.push({para: "admins", tipo: "orientacao", texto: `${c.user.nome} pediu orientação sobre "${task.t}": ${txt}`});
      break;
    default:
      fail(400, "Ação desconhecida.");
  }
  rec.v++; carimbar(rec, c, agora);
  rec.eventos.push(ev);
  if (rec.eventos.length > 200) rec.eventos = rec.eventos.slice(-200);
}
// quem criou o registro e quando; quem fez a última alteração e quando (horário do servidor)
function carimbar(rec, c, agora){
  if (!rec.criadoEm) { rec.criadoEm = agora; rec.criadoPor = c.U; }
  rec.alteradoEm = agora; rec.alteradoPor = c.U;
}

// a colaboradora registra apenas hoje e os últimos 7 dias, e só tarefas dela (ou sem responsável)
function conferirAcesso(c, rot, data, tarefaId){
  if (!isDate(data)) fail(400, "Data inválida.");
  const task = tarefasDoDia(rot, data).find(t => t.id === tarefaId);
  if (!task) fail(404, "Atividade não encontrada na rotina deste dia.");
  if (!c.admin) {
    const hoje = todayIn(c.meta.tz);
    if (data > hoje || data < addDaysISO(hoje, -7)) fail(403, "Registros só podem ser feitos para hoje ou para os últimos 7 dias.");
    if (task.resp && task.resp !== c.U) fail(403, "Esta atividade foi atribuída a outra pessoa.");
  }
  return task;
}

async function avisar(store, c, avisos){
  for (const n of avisos) {
    const para = n.para === "admins" ? admins(c.meta) : [n.para];
    await notificar(store, c, para, {tipo: n.tipo, texto: n.texto, data: n.data, tarefa: n.tarefa});
  }
}

// quando tudo do dia foi registrado, avisa a administradora (uma única vez)
async function conferirDiaCompleto(store, c, rot, data, doc){
  if (doc.avisoTodas) return;
  const ts = tarefasDoDia(rot, data);
  if (!ts.length || !ts.every(t => FEITOS.includes((doc.tarefas[t.id] || {}).status))) return;
  let marcou = false;
  await update(store, `h/${c.casa}/dia/${data}`, cur => { if (!cur || cur.avisoTodas) return undefined; cur.avisoTodas = true; marcou = true; return cur; });
  if (marcou) await notificar(store, c, admins(c.meta), {tipo: "dia", texto: `Todas as atividades de ${data.split("-").reverse().join("/")} foram registradas.`, data});
}

// atrasos: verificados quando alguém consulta o dia de hoje (no máximo a cada 5 minutos)
async function conferirAtrasos(store, c, rot, data){
  const chave = `h/${c.casa}/dia/${data}`;
  const agoraMin = minutesIn(c.meta.tz), novos = [];
  await update(store, chave, cur => {
    cur = cur || {rev: 0, data, tarefas: {}};
    if (cur.verif && Date.now() - cur.verif < 300000) return undefined;
    cur.verif = Date.now(); cur.atraso = cur.atraso || {};
    for (const t of tarefasDoDia(rot, data)) {
      const p = prazo(t), st = (cur.tarefas[t.id] || {}).status || "pendente";
      if (p !== null && agoraMin > p && ["pendente", "andamento", "pausada"].includes(st) && !cur.atraso[t.id]) { cur.atraso[t.id] = true; novos.push(t); }
    }
    return cur;
  });
  if (novos.length) {
    const texto = novos.length === 1 ? `Atividade atrasada: ${novos[0].t}` : `${novos.length} atividades atrasadas: ${novos.slice(0, 3).map(t => t.t).join("; ")}${novos.length > 3 ? "…" : ""}`;
    await notificar(store, c, admins(c.meta), {tipo: "atraso", texto, data});
  }
}

// retenção das fotografias (LGPD): apaga as pastas de datas mais antigas que o prazo, uma vez por dia
async function limparFotos(store, c){
  const dias = c.meta.retencaoDias || 180;
  let rodar = false;
  await update(store, `h/${c.casa}/meta`, cur => { if (!cur || (cur.limpeza && Date.now() - cur.limpeza < DIA)) return undefined; cur.limpeza = Date.now(); rodar = true; return cur; });
  if (!rodar) return;
  const limite = addDaysISO(todayIn(c.meta.tz), -dias);
  const {blobs} = await store.list({prefix: `h/${c.casa}/foto/`});
  for (const b of blobs) { const d = b.key.split("/")[3]; if (d && d < limite) await store.delete(b.key); }
}

/* ---------- rotas ---------- */
export function criarApi(abrirStore){
  return async function api(req){
    const store = abrirStore();
    try {
      const url = new URL(req.url);
      const rota = url.pathname.replace(/^\/api\/?/, "").replace(/\/$/, "");
      const q = k => url.searchParams.get(k) || "";
      const corpo = async () => { try { return await req.json(); } catch { fail(400, "Dados inválidos."); } };
      const M = req.method;

      /* criar residência (a primeira pessoa vira administradora) */
      if (rota === "residencia" && M === "POST") {
        const b = await corpo();
        const chave = (globalThis.Netlify?.env?.get?.("ROTINA_CHAVE")) || process.env.ROTINA_CHAVE || "";
        if (chave && str(b.chave) !== chave) fail(403, "Código de ativação inválido. Peça o código à Gisele Oliveira.");
        const nome = str(b.nome, 80), adminNome = str(b.adminNome, 40), tz = validTz(b.tz) ? b.tz : "America/Sao_Paulo";
        if (nome.length < 2 || adminNome.length < 2) fail(400, "Informe o nome da residência e o seu nome.");
        if (!pinValido(b.pin)) fail(400, "O PIN deve ter 6 números.");
        if (!b.rotina || !Array.isArray(b.rotina.days)) fail(400, "Rotina inválida.");
        const casa = rid(12), U = rid(8), agora = Date.now();
        const user = {id: U, nome: adminNome, papel: "admin", ativo: true, pin: novoPin(b.pin), convite: null, tv: 1, falhas: 0};
        const meta = {id: casa, nome, tz, criado: agora, retencaoDias: 180, usuarios: {[U]: user}};
        await store.setJSON(`h/${casa}/meta`, meta, {onlyIfNew: true});
        await store.setJSON(`h/${casa}/rotina`, {rev: 1, atualizado: agora, por: U, rotina: limparRotina(b.rotina)});
        // migração: marcações feitas antes da conexão viram registros "concluída" com evento de migração
        let migrados = 0;
        for (const [k, v] of Object.entries(b.legado || {})) {
          const [data] = k.split("|");
          if (!isDate(data) || !v || !v.done) continue;
          const tarefas = {};
          for (const id of Object.keys(v.done)) { const r = novoRegistro(id); r.status = "concluida"; r.enviadoPor = U; r.enviadoEm = v.updated || agora; r.origem = "migracao"; r.criadoPor = U; r.criadoEm = v.updated || agora; r.alteradoPor = U; r.alteradoEm = agora; r.eventos.push({id: rid(8), tipo: "migracao", por: U, nome: adminNome, em: agora}); tarefas[id] = r; migrados++; }
          await update(store, `h/${casa}/dia/${data}`, cur => { cur = cur || {rev: 0, data, tarefas: {}}; Object.assign(cur.tarefas, tarefas); if (str(v.obs)) cur.obs = {txt: str(v.obs), por: U, nome: adminNome, em: agora, criadoPor: U, criadoEm: v.updated || agora, origem: "migracao"}; cur.rev++; return cur; });
        }
        await auditar(store, casa, {por: U, nome: adminNome, acao: "residencia", resumo: `Residência criada${migrados ? ` · ${migrados} marcações anteriores migradas` : ""}`});
        return json({token: await emitir(store, casa, user), casa, eu: {id: U, nome: adminNome, papel: "admin"}});
      }

      /* login: lista de nomes (sem dados sensíveis) e entrada com PIN */
      if (rota === "usuarios" && M === "GET") {
        const meta = await getJSON(store, `h/${q("casa")}/meta`);
        if (!meta) fail(404, "Residência não encontrada. Confira o código.");
        return json({residencia: meta.nome, usuarios: Object.values(meta.usuarios).filter(u => u.ativo && u.pin).map(u => ({id: u.id, nome: u.nome}))});
      }
      if (rota === "entrar" && M === "POST") {
        const b = await corpo(), casa = str(b.casa, 20);
        let resultado = null, user = null;
        const meta = await update(store, `h/${casa}/meta`, cur => {
          if (!cur) fail(404, "Residência não encontrada.");
          const u = cur.usuarios[str(b.usuario, 20)];
          if (!u || !u.ativo || !u.pin) fail(404, "Usuário não encontrado nesta residência.");
          if (u.bloqueio && u.bloqueio > Date.now()) { resultado = "bloqueado"; user = u; return undefined; }
          if (pinConfere(b.pin, u.pin)) { resultado = "ok"; if (!u.falhas) { user = u; return undefined; } u.falhas = 0; user = u; return cur; }
          u.falhas = (u.falhas || 0) + 1; resultado = "erro";
          if (u.falhas >= 5) { u.bloqueio = Date.now() + 15 * 60000; u.falhas = 0; resultado = "bloqueou"; }
          user = u; return cur;
        });
        if (resultado === "bloqueado") fail(429, `Muitas tentativas. Tente novamente em ${Math.ceil((user.bloqueio - Date.now()) / 60000)} minutos.`);
        if (resultado === "bloqueou") fail(429, "PIN incorreto. Por segurança, o acesso ficou bloqueado por 15 minutos.");
        if (resultado !== "ok") fail(401, "PIN incorreto.");
        return json({token: await emitir(store, casa, user), casa, eu: {id: user.id, nome: user.nome, papel: user.papel}, residencia: meta.nome});
      }

      /* convite: a pessoa convidada cria o próprio PIN */
      if (rota === "convite" && M === "GET") {
        const meta = await getJSON(store, `h/${q("casa")}/meta`);
        const u = meta && Object.values(meta.usuarios).find(x => x.convite && x.convite.h === sha256(q("codigo")) && x.convite.exp > Date.now());
        if (!u) fail(404, "Convite inválido ou expirado. Peça um novo convite à responsável pela casa.");
        return json({residencia: meta.nome, nome: u.nome, papel: u.papel});
      }
      if (rota === "convite" && M === "POST") {
        const b = await corpo(), casa = str(b.casa, 20);
        if (!pinValido(b.pin)) fail(400, "O PIN deve ter 6 números.");
        let user = null;
        const meta = await update(store, `h/${casa}/meta`, cur => {
          const u = cur && Object.values(cur.usuarios).find(x => x.convite && x.convite.h === sha256(str(b.codigo, 40)) && x.convite.exp > Date.now());
          if (!u) fail(404, "Convite inválido ou expirado. Peça um novo convite à responsável pela casa.");
          u.pin = novoPin(b.pin); u.convite = null; u.tv = (u.tv || 0) + 1; u.falhas = 0; delete u.bloqueio; user = u;
          return cur;
        });
        await auditar(store, casa, {por: user.id, nome: user.nome, acao: "usuario", resumo: `${user.nome} aceitou o convite e criou o PIN`});
        return json({token: await emitir(store, casa, user), casa, eu: {id: user.id, nome: user.nome, papel: user.papel}, residencia: meta.nome});
      }

      /* daqui em diante, somente com sessão válida */
      const c = await autenticar(req, store);

      if (rota === "estado" && M === "GET") {
        const data = q("data") || todayIn(c.meta.tz);
        if (!isDate(data)) fail(400, "Data inválida.");
        const rotDoc = await getJSON(store, `h/${c.casa}/rotina`);
        if (data === todayIn(c.meta.tz)) await conferirAtrasos(store, c, rotDoc.rotina, data);
        if (c.admin) await limparFotos(store, c);
        const dia = (await getJSON(store, `h/${c.casa}/dia/${data}`)) || {rev: 0, tarefas: {}};
        const notif = (await getJSON(store, `h/${c.casa}/notif/${c.U}`)) || {itens: []};
        const out = {
          eu: {id: c.U, nome: c.user.nome, papel: c.user.papel, prefs: c.user.prefs || {}},
          residencia: {id: c.casa, nome: c.meta.nome, tz: c.meta.tz, retencaoDias: c.meta.retencaoDias || 180, usuarios: usuariosPublicos(c.meta)},
          rotinaRev: rotDoc.rev, diaRev: dia.rev, data, agora: Date.now(), hoje: todayIn(c.meta.tz),
          notif: {naoLidas: notif.itens.filter(n => !n.lida).length, itens: notif.itens.slice(0, 40)},
        };
        if (String(rotDoc.rev) !== q("rr")) out.rotina = rotDoc.rotina;
        if (String(dia.rev) !== q("dr")) out.dia = {tarefas: dia.tarefas, obs: dia.obs || null};
        return json(out);
      }

      if (rota === "acao" && M === "POST") {
        const a = await corpo();
        if (!/^[\w-]{8,40}$/.test(str(a.id, 60))) fail(400, "Identificador da ação inválido.");
        const rot = (await getJSON(store, `h/${c.casa}/rotina`)).rotina;
        const chave = `h/${c.casa}/dia/${a.data}`;
        // observação geral do dia
        if (a.tarefa === "_dia") {
          if (!isDate(a.data)) fail(400, "Data inválida.");
          if (!c.admin) { const hoje = todayIn(c.meta.tz); if (a.data > hoje || a.data < addDaysISO(hoje, -7)) fail(403, "Registros só podem ser feitos para hoje ou para os últimos 7 dias."); }
          let substituida = null;
          const doc = await update(store, chave, cur => {
            substituida = null;
            cur = cur || {rev: 0, data: a.data, tarefas: {}};
            const txt = str(a.txt, 3000), o = cur.obs, agora = Date.now();
            const deOutra = o && o.txt && o.por !== c.U && o.txt !== txt;
            if (deOutra && !a.forcar && (o.em || 0) > (Number(a.base) || 0))
              fail(409, `${o.nome || "Outra pessoa"} alterou a observação do dia às ${horaIn(c.meta.tz, o.em)}. Confira antes de salvar.`, {conflito: {txt: o.txt, nome: o.nome || "", em: o.em}});
            if (deOutra && a.forcar) substituida = o.por;
            cur.obs = {txt, por: c.U, nome: c.user.nome, em: agora, criadoPor: (o && o.criadoPor) || c.U, criadoEm: (o && (o.criadoEm || o.em)) || agora};
            cur.rev++; return cur;
          });
          if (substituida) await notificar(store, c, [substituida], {tipo: "alteracao", texto: `${c.user.nome} substituiu a sua observação do dia ${a.data.split("-").reverse().join("/")}.`, data: a.data});
          return json({obs: doc.obs, diaRev: doc.rev});
        }
        const task = conferirAcesso(c, rot, a.data, str(a.tarefa, 80));
        if (["aprovar", "devolver"].includes(a.tipo)) exigirAdmin(c);
        let avisos = [];
        const doc = await update(store, chave, cur => {
          avisos = [];
          cur = cur || {rev: 0, data: a.data, tarefas: {}};
          const rec = cur.tarefas[task.id] || novoRegistro(task.id);
          if (rec.eventos.some(e => e.id === a.id)) return undefined; // ação já aplicada (reenvio)
          aplicar(rec, task, a, c, avisos);
          cur.tarefas[task.id] = rec; cur.rev++;
          return cur;
        });
        await avisar(store, c, avisos.map(n => ({...n, data: a.data, tarefa: task.id})));
        if (a.tipo === "registrar" || a.tipo === "impossivel") await conferirDiaCompleto(store, c, rot, a.data, doc);
        return json({tarefa: doc.tarefas[task.id], diaRev: doc.rev});
      }

      if (rota === "foto" && M === "POST") {
        const data = req.headers.get("x-data"), tarefa = req.headers.get("x-tarefa"), tipo = req.headers.get("x-tipo"), acao = req.headers.get("x-acao") || "";
        const origem = req.headers.get("x-origem") === "galeria" ? "galeria" : "camera";
        if (!["antes", "depois"].includes(tipo)) fail(400, "Tipo de foto inválido.");
        if (!/^[\w-]{8,40}$/.test(acao)) fail(400, "Identificador da ação inválido.");
        if (!/^image\/(jpeg|png|webp)$/.test(req.headers.get("content-type") || "")) fail(415, "Envie uma imagem JPEG, PNG ou WebP.");
        const rot = (await getJSON(store, `h/${c.casa}/rotina`)).rotina;
        const task = conferirAcesso(c, rot, data, tarefa);
        const bytes = Buffer.from(await req.arrayBuffer());
        if (!bytes.length) fail(400, "Foto vazia.");
        if (bytes.length > 4 * 1024 * 1024) fail(413, "Foto grande demais.");
        const chaveDia = `h/${c.casa}/dia/${data}`;
        const atual = (await getJSON(store, chaveDia)) || {tarefas: {}};
        const recAtual = atual.tarefas[task.id] || novoRegistro(task.id);
        if (recAtual.fotos.some(f => f.acao === acao)) return json({tarefa: recAtual, diaRev: atual.rev || 0});
        const permitidos = tipo === "antes" ? ["pendente", "andamento", "pausada", "correcao"] : ["andamento", "pausada"];
        if (!permitidos.includes(recAtual.status)) fail(409, tipo === "antes" ? "A foto ANTES deve ser feita antes de concluir a atividade." : "Inicie a atividade antes de enviar a foto DEPOIS.");
        const hash = sha256(bytes), id = rid(16), agora = Date.now();
        // proteção contra reutilização: a mesma imagem já usada em outra atividade fica sinalizada
        const anterior = await getJSON(store, `h/${c.casa}/hash/${hash}`);
        const reuso = anterior && (anterior.tarefa !== task.id || anterior.data !== data) ? {tarefa: anterior.tarefa, data: anterior.data, nome: anterior.nome || ""} : null;
        await store.set(`h/${c.casa}/foto/${data}/${id}`, bytes, {metadata: {tarefa: task.id, tipo, por: c.U, em: agora, origem, hash, tipoMime: req.headers.get("content-type")}});
        let doc;
        try {
          doc = await update(store, chaveDia, cur => {
            cur = cur || {rev: 0, data, tarefas: {}};
            const rec = cur.tarefas[task.id] || novoRegistro(task.id);
            if (rec.fotos.some(f => f.acao === acao)) return undefined;
            if (!permitidos.includes(rec.status)) fail(409, "O estado da atividade mudou. Atualize e tente novamente.");
            rec.fotos.push({id, acao, tipo, ciclo: rec.ciclo, em: agora, por: c.U, nome: c.user.nome, origem, data, reuso});
            carimbar(rec, c, agora);
            rec.eventos.push({id: acao, tipo: "foto", fotoTipo: tipo, por: c.U, nome: c.user.nome, em: agora, origem});
            rec.v++; cur.tarefas[task.id] = rec; cur.rev++;
            return cur;
          });
        } catch (e) { await store.delete(`h/${c.casa}/foto/${data}/${id}`); throw e; }
        if (!anterior) await store.setJSON(`h/${c.casa}/hash/${hash}`, {foto: id, tarefa: task.id, data, nome: task.t}, {onlyIfNew: true});
        return json({tarefa: doc.tarefas[task.id], diaRev: doc.rev});
      }
      if (rota === "foto" && M === "GET") {
        const id = q("id"), data = q("data");
        if (!/^[A-Z2-9]{16}$/.test(id) || !isDate(data)) fail(400, "Foto inválida.");
        const r = await store.getWithMetadata(`h/${c.casa}/foto/${data}/${id}`, {type: "arrayBuffer"});
        if (!r) fail(404, "Foto não encontrada (pode ter sido apagada pelo prazo de retenção).");
        return new Response(r.data, {headers: {"Content-Type": (r.metadata && r.metadata.tipoMime) || "image/jpeg", "Cache-Control": "private, max-age=604800"}});
      }

      if (rota === "rotina" && M === "POST") {
        exigirAdmin(c);
        const b = await corpo();
        if (!b.rotina || !Array.isArray(b.rotina.days)) fail(400, "Rotina inválida.");
        if (JSON.stringify(b.rotina).length > 4_500_000) fail(413, "A rotina ficou grande demais (reduza as imagens das instruções).");
        let antiga = null;
        const doc = await update(store, `h/${c.casa}/rotina`, cur => {
          if (cur.rev !== Number(b.base)) fail(409, "A rotina foi alterada em outro aparelho e foi recarregada. Refaça a última alteração.");
          antiga = cur.rotina;
          return {rev: cur.rev + 1, atualizado: Date.now(), por: c.U, rotina: limparRotina(b.rotina)};
        });
        await auditar(store, c.casa, {por: c.U, nome: c.user.nome, acao: "rotina", resumo: `Rotina atualizada (revisão ${doc.rev})`});
        // novas atribuições e aviso de alteração para as colaboradoras
        const resp = r => { const m = {}; for (const d of r.days || []) for (const bl of d.blocks || []) for (const t of bl.tasks || []) if (t.resp) m[t.id] = {resp: t.resp, t: t.t}; for (const x of r.extras || []) if (x.resp) m[x.id] = {resp: x.resp, t: x.t}; return m; };
        const antes = resp(antiga || {}), depois = resp(doc.rotina), novas = {};
        for (const [id, v] of Object.entries(depois)) if (!antes[id] || antes[id].resp !== v.resp) (novas[v.resp] ||= []).push(v.t);
        for (const [U, lista] of Object.entries(novas)) await notificar(store, c, [U], {tipo: "atribuida", texto: lista.length === 1 ? `Nova tarefa atribuída a você: ${lista[0]}` : `${lista.length} tarefas novas atribuídas a você.`});
        const colab = Object.values(c.meta.usuarios).filter(u => u.ativo && u.papel !== "admin" && !novas[u.id]).map(u => u.id);
        for (const U of colab) {
          const n = (await getJSON(store, `h/${c.casa}/notif/${U}`)) || {itens: []};
          const ultimo = n.itens.find(x => x.tipo === "rotina");
          if (!ultimo || Date.now() - ultimo.em > 30 * 60000) await notificar(store, c, [U], {tipo: "rotina", texto: "A rotina da casa foi atualizada."});
        }
        return json({rev: doc.rev});
      }

      if (rota === "usuarios" && M === "POST") {
        exigirAdmin(c);
        const b = await corpo();
        let codigo = null, alvo = null, resumo = "";
        await update(store, `h/${c.casa}/meta`, cur => {
          codigo = null;
          const papel = b.papel === "admin" ? "admin" : "colaboradora";
          if (b.op === "criar") {
            const nome = str(b.nome, 40); if (nome.length < 2) fail(400, "Informe o nome da pessoa.");
            const U = rid(8); codigo = rid(10);
            alvo = cur.usuarios[U] = {id: U, nome, papel, ativo: true, pin: null, convite: {h: sha256(codigo), exp: Date.now() + 7 * DIA}, tv: 1, falhas: 0};
            resumo = `${nome} cadastrada como ${papel}`; return cur;
          }
          const u = cur.usuarios[str(b.id, 20)]; if (!u) fail(404, "Usuário não encontrado.");
          alvo = u;
          const outrosAdmins = Object.values(cur.usuarios).filter(x => x.ativo && x.papel === "admin" && x.id !== u.id).length;
          if (b.op === "convite") { codigo = rid(10); u.convite = {h: sha256(codigo), exp: Date.now() + 7 * DIA}; u.pin = null; u.tv++; resumo = `Novo convite (redefinição de PIN) para ${u.nome}`; }
          else if (b.op === "desativar") { if (u.id === c.U) fail(400, "Você não pode desativar a sua própria conta."); if (u.papel === "admin" && !outrosAdmins) fail(400, "A residência precisa de ao menos uma administradora ativa."); u.ativo = false; u.tv++; resumo = `${u.nome} desativada`; }
          else if (b.op === "ativar") { u.ativo = true; resumo = `${u.nome} reativada`; }
          else if (b.op === "papel") { if (u.papel === "admin" && papel !== "admin" && !outrosAdmins) fail(400, "A residência precisa de ao menos uma administradora ativa."); u.papel = papel; u.tv++; resumo = `${u.nome} agora é ${papel}`; }
          else if (b.op === "renomear") { const nome = str(b.nome, 40); if (nome.length < 2) fail(400, "Informe o nome."); u.nome = nome; resumo = `Nome alterado para ${nome}`; }
          else fail(400, "Operação desconhecida.");
          return cur;
        });
        await auditar(store, c.casa, {por: c.U, nome: c.user.nome, acao: "usuario", resumo});
        const meta = await getJSON(store, `h/${c.casa}/meta`);
        return json({usuarios: usuariosPublicos(meta), usuario: {id: alvo.id, nome: alvo.nome, papel: alvo.papel}, convite: codigo});
      }

      if (rota === "residencia" && M === "PUT") {
        exigirAdmin(c);
        const b = await corpo();
        await update(store, `h/${c.casa}/meta`, cur => {
          if (b.nome !== undefined) { const n = str(b.nome, 80); if (n.length >= 2) cur.nome = n; }
          if (b.tz !== undefined) { if (!validTz(b.tz)) fail(400, "Fuso horário inválido."); cur.tz = b.tz; }
          if (b.retencaoDias !== undefined) { const d = Number(b.retencaoDias); if (![30, 90, 180, 365].includes(d)) fail(400, "Prazo de retenção inválido."); cur.retencaoDias = d; }
          return cur;
        });
        await auditar(store, c.casa, {por: c.U, nome: c.user.nome, acao: "residencia", resumo: "Configurações da residência alteradas"});
        return json({ok: true});
      }

      if (rota === "notificacoes" && M === "POST") {
        const b = await corpo();
        if (b.op === "lidas") await update(store, `h/${c.casa}/notif/${c.U}`, cur => { if (!cur) return undefined; cur.itens.forEach(n => n.lida = true); return cur; });
        else if (b.op === "prefs") {
          const off = (Array.isArray(b.off) ? b.off : []).filter(x => typeof x === "string").slice(0, 20);
          await update(store, `h/${c.casa}/meta`, cur => { cur.usuarios[c.U].prefs = {off}; return cur; });
        } else fail(400, "Operação desconhecida.");
        return json({ok: true});
      }

      /* "Enviar meus dados para a base compartilhada": marcações antigas guardadas no navegador.
         Só acrescenta o que ainda não existe (nunca substitui), então reenviar não duplica. */
      if (rota === "migrar" && M === "POST") {
        const b = await corpo();
        const legado = b.legado && typeof b.legado === "object" ? b.legado : {};
        const chaves = Object.keys(legado).slice(0, 400);
        const rot = (await getJSON(store, `h/${c.casa}/rotina`)).rotina;
        const origem = str(b.origem, 80) || "aparelho";
        const agora = Date.now(), res = {enviadas: 0, jaExistiam: 0, foraDaRotina: 0, observacoes: 0};
        for (const k of chaves) {
          const [data] = k.split("|"), v = legado[k];
          if (!isDate(data) || !v || typeof v !== "object") continue;
          const ids = new Set(tarefasDoDia(rot, data).map(t => t.id));
          const feitos = Object.keys(v.done || {}).filter(id => v.done[id]);
          let parcial = null;
          await update(store, `h/${c.casa}/dia/${data}`, cur => {
            parcial = {enviadas: 0, jaExistiam: 0, foraDaRotina: 0, observacoes: 0};
            cur = cur || {rev: 0, data, tarefas: {}};
            let mudou = false;
            for (const id of feitos) {
              if (!ids.has(id)) { parcial.foraDaRotina++; continue; }
              if (cur.tarefas[id]) { parcial.jaExistiam++; continue; }
              const r = novoRegistro(id), quando = Number(v.updated) || agora;
              Object.assign(r, {status: "concluida", enviadoPor: c.U, enviadoEm: quando, origem: "migracao", criadoPor: c.U, criadoEm: quando, alteradoPor: c.U, alteradoEm: agora});
              r.eventos.push({id: rid(8), tipo: "migracao", por: c.U, nome: c.user.nome, em: agora, txt: `Marcação guardada em "${origem}"`});
              cur.tarefas[id] = r; parcial.enviadas++; mudou = true;
            }
            if (str(v.obs) && !(cur.obs && cur.obs.txt)) { cur.obs = {txt: str(v.obs, 3000), por: c.U, nome: c.user.nome, em: agora, criadoPor: c.U, criadoEm: Number(v.updated) || agora, origem: "migracao"}; parcial.observacoes++; mudou = true; }
            if (!mudou) return undefined;
            cur.rev++; return cur;
          });
          for (const x of Object.keys(res)) res[x] += parcial[x];
        }
        if (res.enviadas || res.observacoes) {
          await auditar(store, c.casa, {por: c.U, nome: c.user.nome, acao: "migracao", resumo: `${c.user.nome} enviou dados antigos de "${origem}": ${res.enviadas} marcação(ões) e ${res.observacoes} observação(ões)`});
          await notificar(store, c, admins(c.meta).filter(id => id !== c.U), {tipo: "alteracao", texto: `${c.user.nome} enviou ${res.enviadas} marcação(ões) antigas do aparelho para a base compartilhada.`});
        }
        return json(res);
      }

      /* planilha (CSV para Excel) com todos os registros do período, datas e responsáveis */
      if (rota === "exportar" && M === "GET") {
        exigirAdmin(c);
        const de = q("de"), ate = q("ate");
        if (!isDate(de) || !isDate(ate) || de > ate) fail(400, "Período inválido.");
        const datas = []; for (let d = de; d <= ate && datas.length < 366; d = addDaysISO(d, 1)) datas.push(d);
        const rot = (await getJSON(store, `h/${c.casa}/rotina`)).rotina, tz = c.meta.tz;
        const docs = [];
        for (let i = 0; i < datas.length; i += 40) docs.push(...await Promise.all(datas.slice(i, i + 40).map(d => getJSON(store, `h/${c.casa}/dia/${d}`))));
        const nome = id => (c.meta.usuarios[id] || {}).nome || "";
        const DIAS = {seg: "Segunda", ter: "Terça", qua: "Quarta", qui: "Quinta", sex: "Sexta", sab: "Sábado", dom: "Domingo"};
        const cel = v => { const t = String(v ?? ""); return /[";\n\r]/.test(t) ? '"' + t.replace(/"/g, '""') + '"' : t; };
        const linhas = [["Data", "Dia", "Bloco", "Atividade", "Ambiente", "Nível de verificação", "Situação", "Criado por", "Criado em", "Iniciado por", "Iniciado em", "Registrado por", "Registrado em", "Aprovado por", "Aprovado em", "Correções", "Última alteração por", "Última alteração em", "Fotos", "Observação", "Origem"]];
        datas.forEach((d, i) => {
          const doc = docs[i] || {tarefas: {}}, dd = d.split("-").reverse().join("/"), dia = DIAS[weekdayOf(d)];
          for (const t of tarefasDoDia(rot, d)) {
            const r = doc.tarefas[t.id];
            if (!r) { linhas.push([dd, dia, t.bloco.name, t.t, t.amb || "", +t.nivel || 1, LABEL.pendente, "", "", "", "", "", "", "", "", "", "", "", "", "", ""]); continue; }
            const ult = r.eventos[r.eventos.length - 1] || {}, pri = r.eventos[0] || {};
            linhas.push([dd, dia, t.bloco.name, t.t, t.amb || "", +t.nivel || 1, LABEL[r.status] || r.status,
              nome(r.criadoPor || pri.por), dataHoraIn(tz, r.criadoEm || pri.em), nome(r.iniciadoPor), dataHoraIn(tz, r.iniciadoEm),
              nome(r.enviadoPor), dataHoraIn(tz, r.enviadoEm), nome(r.aprovadoPor), dataHoraIn(tz, r.aprovadoEm), r.correcoes || 0,
              nome(r.alteradoPor || ult.por), dataHoraIn(tz, r.alteradoEm || ult.em), (r.fotos || []).length, r.obs || "",
              r.origem === "migracao" ? "dados antigos do aparelho" : "app"]);
          }
          if (doc.obs && doc.obs.txt) linhas.push([dd, dia, "", "(Observação do dia)", "", "", "", nome(doc.obs.criadoPor) || doc.obs.nome || "", dataHoraIn(tz, doc.obs.criadoEm || doc.obs.em),
            "", "", "", "", "", "", "", doc.obs.nome || nome(doc.obs.por), dataHoraIn(tz, doc.obs.em), "", doc.obs.txt, doc.obs.origem === "migracao" ? "dados antigos do aparelho" : "app"]);
        });
        // separador ";" e BOM: o Excel em português abre com acentos e colunas certas
        const csv = "\ufeff" + linhas.map(l => l.map(cel).join(";")).join("\r\n") + "\r\n";
        await auditar(store, c.casa, {por: c.U, nome: c.user.nome, acao: "exportacao", resumo: `Planilha exportada (${de.split("-").reverse().join("/")} a ${ate.split("-").reverse().join("/")})`});
        return new Response(csv, {headers: {"Content-Type": "text/csv; charset=utf-8", "Cache-Control": "no-store", "Content-Disposition": `attachment; filename="rotina_${de}_${ate}.csv"`}});
      }

      if (rota === "historico" && M === "GET") {
        const de = q("de"), ate = q("ate");
        if (!isDate(de) || !isDate(ate) || de > ate) fail(400, "Período inválido.");
        const datas = []; for (let d = de; d <= ate && datas.length < 62; d = addDaysISO(d, 1)) datas.push(d);
        const rot = (await getJSON(store, `h/${c.casa}/rotina`)).rotina;
        const docs = await Promise.all(datas.map(d => getJSON(store, `h/${c.casa}/dia/${d}`)));
        const dias = datas.map((d, i) => {
          const ts = tarefasDoDia(rot, d), doc = docs[i] || {tarefas: {}}, cont = {total: ts.length};
          for (const s of Object.keys(LABEL)) cont[s] = 0;
          for (const t of ts) cont[(doc.tarefas[t.id] || {}).status || "pendente"]++;
          const eventos = [];
          for (const [id, r] of Object.entries(doc.tarefas)) for (const e of r.eventos) if (["aprovar", "devolver"].includes(e.tipo)) eventos.push({tarefa: id, t: (ts.find(x => x.id === id) || {}).t || id, tipo: e.tipo, nome: e.nome, em: e.em, txt: e.txt || ""});
          return {data: d, ...cont, obs: doc.obs ? doc.obs.txt : "", eventos};
        }).filter(x => x.total || x.eventos.length);
        const audit = c.admin ? ((await getJSON(store, `h/${c.casa}/audit`)) || {itens: []}).itens.slice(0, 50) : [];
        return json({dias, audit});
      }

      fail(404, "Endereço da API não encontrado.");
    } catch (e) {
      if (e instanceof HttpError) return json({erro: e.message, ...(e.extra || {})}, e.status);
      console.error(e);
      return json({erro: "Erro interno no servidor. Tente novamente."}, 500);
    }
  };
}

// remove campos locais do aparelho antes de guardar a rotina
function limparRotina(r){
  const {id, remote, sync, updated, ...resto} = r;
  return resto;
}

export default criarApi(() => getStore({name: STORE, consistency: "strong"}));
export const config = {path: "/api/*"};
