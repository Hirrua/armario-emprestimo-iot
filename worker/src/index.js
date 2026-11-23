import PAINEL_HTML from './painel.html';
import { mensagemComando, hmacHex, envelopar, abrirEnvelope } from './assinatura.js';

const KV_AUTORIZADOS = 'armario:autorizados';
const KV_CONFIG = 'armario:config';
const KV_ALERTAS = 'armario:alertas';
const KV_ULTIMO_CONTATO = 'armario:ultimo_contato';
const KV_COOLDOWN = 'armario:cd:';

const CONFIG_PADRAO = {
  janela_abertura_s: 10,
  porta_aberta_max_s: 30,
  max_tentativas: 3,
  bloqueio_s: 30,
  cooldown_alerta_s: 120,
};

const ACOES_VALIDAS = ['liberar', 'travar'];
const TIPOS_EVENTO = ['acesso', 'retirada', 'devolucao', 'alerta', 'comando', 'boot'];

export default {
  async fetch(request, env, ctx) {
    try {
      return await rotear(request, env, ctx);
    } catch (err) {
      console.error('erro na rota', err && err.stack ? err.stack : err);
      return json({ erro: 'erro interno' }, 500);
    }
  },

  async scheduled(event, env, ctx) {
    ctx.waitUntil(rotinaAgendada(env));
    ctx.waitUntil(publicarConfig(env).catch((e) => console.error('publicar config', e)));
  },
};

async function rotear(request, env, ctx) {
  const url = new URL(request.url);
  const { pathname } = url;
  const metodo = request.method;

  if (metodo === 'GET' && (pathname === '/' || pathname === '/painel')) {
    return new Response(PAINEL_HTML, {
      headers: {
        'content-type': 'text/html; charset=utf-8',
        'cache-control': 'no-store',
        'x-frame-options': 'DENY',
      },
    });
  }

  if (pathname === '/api/eventos' && metodo === 'POST') {
    if (!(await autorizado(request, env.DEVICE_TOKEN))) return negado();
    return receberEventos(request, env, ctx);
  }

  if (pathname.startsWith('/api/')) {
    if (!(await autorizado(request, env.PAINEL_SENHA))) return negado();

    if (pathname === '/api/config' && metodo === 'GET') {
      return json({
        mqtt: {
          url: `wss://${env.MQTT_HOST}:${env.MQTT_WSS_PORT}/mqtt`,
          usuario: env.MQTT_PAINEL_USER,
          senha: env.MQTT_PAINEL_PASS,
        },
        topico_base: env.TOPICO_BASE,
        device: env.DEVICE_ID,
        limites: await lerConfig(env),
      });
    }

    if (pathname === '/api/limites' && metodo === 'PUT') return salvarLimites(request, env);
    if (pathname === '/api/publicar-config' && metodo === 'POST') {
      const r = await publicarConfig(env);
      return json({ ok: true, usuarios: r.usuarios });
    }
    if (pathname === '/api/comando' && metodo === 'POST') return assinarComando(request, env);
    if (pathname === '/api/resumo' && metodo === 'GET') return resumo(env);
    if (pathname === '/api/usuarios' && metodo === 'GET') return listarUsuarios(env);
    if (pathname === '/api/usuarios' && metodo === 'POST') return criarUsuario(request, env);

    const m = pathname.match(/^\/api\/usuarios\/(\d+)\/(ativar|desativar)$/);
    if (m && metodo === 'POST') return alterarUsuario(env, Number(m[1]), m[2] === 'ativar' ? 1 : 0);
  }

  return json({ erro: 'rota não encontrada' }, 404);
}

async function autorizado(request, segredo) {
  if (!segredo) return false;
  const cab = request.headers.get('authorization') || '';
  if (!cab.startsWith('Bearer ')) return false;
  return iguaisTempoConstante(cab.slice(7), segredo);
}

async function iguaisTempoConstante(a, b) {
  const enc = new TextEncoder();
  const [ha, hb] = await Promise.all([
    crypto.subtle.digest('SHA-256', enc.encode(a)),
    crypto.subtle.digest('SHA-256', enc.encode(b)),
  ]);
  return crypto.subtle.timingSafeEqual(ha, hb);
}

function negado() {
  return json({ erro: 'não autorizado' }, 401);
}

async function receberEventos(request, env, ctx) {
  const corpo = await abrirEnvelope(env.HMAC_KEY, await request.text());
  if (!corpo) return json({ erro: 'assinatura inválida' }, 403);

  const device = String(corpo.device || '');
  if (device !== env.DEVICE_ID) return json({ erro: 'device desconhecido' }, 403);

  const eventos = Array.isArray(corpo.eventos) ? corpo.eventos.slice(0, 20) : [];
  const aceitos = [];

  for (const ev of eventos) {
    const id = String(ev.id || '');
    const tipo = String(ev.tipo || '');
    if (!/^[a-z0-9-]{3,64}$/.test(id) || !TIPOS_EVENTO.includes(tipo)) continue;

    const tsNum = Number(ev.ts) || 0;
    const horaAproximada = tsNum < 1700000000 ? 1 : 0;
    const ts = horaAproximada ? agoraIso() : epochParaIso(tsNum);
    const usuarioId = Number.isInteger(ev.usuario_id) && ev.usuario_id > 0 ? ev.usuario_id : null;
    const slot = Number.isInteger(ev.slot) && ev.slot > 0 ? ev.slot : null;
    const resultado = ev.resultado != null ? String(ev.resultado).slice(0, 32) : null;
    const detalhe = ev.detalhe != null ? String(ev.detalhe).slice(0, 120) : null;

    const ins = await env.DB.prepare(
      `INSERT OR IGNORE INTO arm_eventos (id, device, tipo, ts, hora_aproximada, usuario_id, slot, resultado, detalhe)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
      .bind(id, device, tipo, ts, horaAproximada, usuarioId, slot, resultado, detalhe)
      .run();

    if (ins.meta.changes === 1) {
      if (tipo === 'retirada' && slot) {
        await env.DB.prepare(
          `INSERT OR IGNORE INTO arm_emprestimos (slot, usuario_id, retirada_em, evento_retirada) VALUES (?, ?, ?, ?)`
        )
          .bind(slot, usuarioId, ts, id)
          .run();
      } else if (tipo === 'devolucao' && slot) {
        await env.DB.prepare(
          `UPDATE arm_emprestimos SET devolvido_em = ?, devolvido_por = ?, evento_devolucao = ?
           WHERE id = (SELECT id FROM arm_emprestimos WHERE slot = ? AND devolvido_em IS NULL
                       ORDER BY retirada_em DESC LIMIT 1)`
        )
          .bind(ts, usuarioId, id, slot)
          .run();
      }
    }
    aceitos.push(id);
  }

  await env.KV.put(KV_ULTIMO_CONTATO, agoraIso());
  await publicarMqtt(env, `${env.TOPICO_BASE}/eventos/ack`, await envelopar(env.HMAC_KEY, { aceitos }), false);
  return json({ ok: true, aceitos });
}

async function publicarMqtt(env, topico, payload, retain) {
  const r = await fetch(`${env.EMQX_API_URL}/publish`, {
    method: 'POST',
    headers: {
      authorization: 'Basic ' + btoa(`${env.EMQX_API_KEY}:${env.EMQX_API_SECRET}`),
      'content-type': 'application/json',
    },
    body: JSON.stringify({ topic: topico, payload, qos: 1, retain }),
  });
  if (!r.ok) throw new Error(`EMQX publish ${r.status}: ${(await r.text()).slice(0, 200)}`);
}

async function publicarConfig(env) {
  const usuarios = await listaAutorizados(env);
  const config = await lerConfig(env);
  await publicarMqtt(env, `${env.TOPICO_BASE}/config`, await envelopar(env.HMAC_KEY, { usuarios, config }), true);
  return { usuarios: usuarios.length };
}

async function listaAutorizados(env) {
  const cache = await env.KV.get(KV_AUTORIZADOS, 'json');
  if (cache) return cache;
  return reconstruirAutorizados(env);
}

async function reconstruirAutorizados(env) {
  const { results } = await env.DB.prepare(
    'SELECT id, pin_hash AS h FROM arm_usuarios WHERE ativo = 1 ORDER BY id'
  ).all();
  await env.KV.put(KV_AUTORIZADOS, JSON.stringify(results));
  return results;
}

async function lerConfig(env) {
  const salvo = await env.KV.get(KV_CONFIG, 'json');
  return { ...CONFIG_PADRAO, ...(salvo || {}) };
}

async function salvarLimites(request, env) {
  const corpo = await request.json().catch(() => ({}));
  const atual = await lerConfig(env);
  const faixas = {
    janela_abertura_s: [5, 60],
    porta_aberta_max_s: [10, 600],
    max_tentativas: [1, 10],
    bloqueio_s: [10, 600],
    cooldown_alerta_s: [30, 3600],
  };
  for (const [chave, [min, max]] of Object.entries(faixas)) {
    if (corpo[chave] === undefined) continue;
    const v = Number(corpo[chave]);
    if (!Number.isInteger(v) || v < min || v > max) {
      return json({ erro: `${chave} deve ser inteiro entre ${min} e ${max}` }, 400);
    }
    atual[chave] = v;
  }
  await env.KV.put(KV_CONFIG, JSON.stringify(atual));
  await publicarConfig(env);
  return json({ ok: true, limites: atual });
}

async function assinarComando(request, env) {
  const corpo = await request.json().catch(() => ({}));
  const acao = String(corpo.acao || '');
  if (!ACOES_VALIDAS.includes(acao)) return json({ erro: 'ação inválida' }, 400);

  const agora = Date.now();
  const comando = {
    device: env.DEVICE_ID,
    acao,
    seq: agora,
    ts: Math.floor(agora / 1000),
  };
  comando.sig = await hmacHex(env.HMAC_KEY, mensagemComando(comando));
  return json(comando);
}

async function resumo(env) {
  const atrasoHoras = Number(env.ATRASO_HORAS || 24);

  const [abertos, porEquipamento, porDia, negados, ultimos, equipamentos] = await env.DB.batch([
    env.DB.prepare(
      `SELECT e.slot, q.nome AS equipamento, COALESCE(u.nome, '(desconhecido)') AS usuario, e.retirada_em,
              ROUND((julianday('now') - julianday(e.retirada_em)) * 24, 2) AS horas_fora
         FROM arm_emprestimos e
         JOIN arm_equipamentos q ON q.slot = e.slot
         LEFT JOIN arm_usuarios u ON u.id = e.usuario_id
        WHERE e.devolvido_em IS NULL
        ORDER BY e.retirada_em`
    ),
    env.DB.prepare(
      `SELECT q.nome AS equipamento, COUNT(e.id) AS emprestimos,
              ROUND(AVG(CASE WHEN e.devolvido_em IS NOT NULL
                             THEN (julianday(e.devolvido_em) - julianday(e.retirada_em)) * 24 END), 2) AS horas_medias
         FROM arm_equipamentos q
         LEFT JOIN arm_emprestimos e ON e.slot = q.slot AND e.retirada_em >= datetime('now', '-7 days')
        GROUP BY q.slot
        ORDER BY q.slot`
    ),
    env.DB.prepare(
      `SELECT date(retirada_em) AS dia, COUNT(*) AS retiradas
         FROM arm_emprestimos
        WHERE retirada_em >= datetime('now', '-7 days')
        GROUP BY date(retirada_em)
        ORDER BY dia`
    ),
    env.DB.prepare(
      `SELECT COUNT(*) AS total FROM arm_eventos
        WHERE tipo = 'acesso' AND resultado IN ('negado', 'bloqueado') AND ts >= datetime('now', '-1 day')`
    ),
    env.DB.prepare(
      `SELECT v.ts, v.tipo, v.resultado, v.detalhe, v.slot, v.hora_aproximada, u.nome AS usuario
         FROM arm_eventos v LEFT JOIN arm_usuarios u ON u.id = v.usuario_id
        ORDER BY v.ts DESC, v.recebido_em DESC LIMIT 15`
    ),
    env.DB.prepare('SELECT slot, nome FROM arm_equipamentos ORDER BY slot'),
  ]);

  return json({
    atraso_horas: atrasoHoras,
    emprestados: abertos.results.map((r) => ({ ...r, atrasado: r.horas_fora >= atrasoHoras })),
    por_equipamento_7d: porEquipamento.results,
    retiradas_por_dia: porDia.results,
    acessos_negados_24h: negados.results[0]?.total ?? 0,
    ultimos_eventos: ultimos.results,
    equipamentos: equipamentos.results,
    alertas_nuvem: (await env.KV.get(KV_ALERTAS, 'json')) || [],
    ultimo_contato: await env.KV.get(KV_ULTIMO_CONTATO),
  });
}

async function listarUsuarios(env) {
  const { results } = await env.DB.prepare(
    'SELECT id, nome, ativo, criado_em FROM arm_usuarios ORDER BY id'
  ).all();
  return json(results);
}

async function criarUsuario(request, env) {
  const corpo = await request.json().catch(() => ({}));
  const nome = String(corpo.nome || '').trim().slice(0, 60);
  const pin = String(corpo.pin || '');
  if (!nome) return json({ erro: 'nome obrigatório' }, 400);
  if (!/^\d{4,8}$/.test(pin)) return json({ erro: 'PIN deve ter de 4 a 8 dígitos' }, 400);

  const { results: ativos } = await env.DB.prepare(
    'SELECT id, pin_hash FROM arm_usuarios WHERE ativo = 1'
  ).all();
  for (const u of ativos) {
    if ((await sha256Hex(`${u.id}:${pin}`)) === u.pin_hash) {
      return json({ erro: 'PIN já usado por outro usuário, escolha outro' }, 409);
    }
  }

  const r = await env.DB.prepare("INSERT INTO arm_usuarios (nome, pin_hash) VALUES (?, '') RETURNING id")
    .bind(nome)
    .first();
  const hash = await sha256Hex(`${r.id}:${pin}`);
  await env.DB.prepare('UPDATE arm_usuarios SET pin_hash = ? WHERE id = ?').bind(hash, r.id).run();
  await reconstruirAutorizados(env);
  await publicarConfig(env);
  return json({ ok: true, id: r.id }, 201);
}

async function alterarUsuario(env, id, ativo) {
  await env.DB.prepare('UPDATE arm_usuarios SET ativo = ? WHERE id = ?').bind(ativo, id).run();
  await reconstruirAutorizados(env);
  await publicarConfig(env);
  return json({ ok: true });
}

async function rotinaAgendada(env) {
  const atrasoHoras = Number(env.ATRASO_HORAS || 24);
  const retEmp = Number(env.RETENCAO_DIAS_EMPRESTIMOS || 90);
  const retAcessos = Number(env.RETENCAO_DIAS_ACESSOS || 30);
  const cooldownS = Number(env.COOLDOWN_ATRASO_S || 21600);

  const { results: atrasados } = await env.DB.prepare(
    `SELECT e.id, q.nome AS equipamento, COALESCE(u.nome, '(desconhecido)') AS usuario, e.retirada_em
       FROM arm_emprestimos e
       JOIN arm_equipamentos q ON q.slot = e.slot
       LEFT JOIN arm_usuarios u ON u.id = e.usuario_id
      WHERE e.devolvido_em IS NULL
        AND julianday('now') - julianday(e.retirada_em) >= ? / 24.0`
  )
    .bind(atrasoHoras)
    .all();

  const alertas = (await env.KV.get(KV_ALERTAS, 'json')) || [];
  for (const a of atrasados) {
    const chave = `${KV_COOLDOWN}atraso:${a.id}`;
    if (await env.KV.get(chave)) continue;
    alertas.unshift({
      em: agoraIso(),
      tipo: 'devolucao_atrasada',
      texto: `${a.equipamento} com ${a.usuario} desde ${a.retirada_em} UTC`,
    });
    await env.KV.put(chave, '1', { expirationTtl: Math.max(cooldownS, 60) });
  }
  await env.KV.put(KV_ALERTAS, JSON.stringify(alertas.slice(0, 20)));

  await env.DB.batch([
    env.DB.prepare(
      `DELETE FROM arm_emprestimos WHERE devolvido_em IS NOT NULL AND devolvido_em < datetime('now', ?)`
    ).bind(`-${retEmp} days`),
    env.DB.prepare(`DELETE FROM arm_eventos WHERE ts < datetime('now', ?)`).bind(`-${retAcessos} days`),
  ]);

  return { atrasados: atrasados.length };
}

async function sha256Hex(texto) {
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(texto));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

function agoraIso() {
  return new Date().toISOString().slice(0, 19).replace('T', ' ');
}

function epochParaIso(s) {
  return new Date(s * 1000).toISOString().slice(0, 19).replace('T', ' ');
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
  });
}
