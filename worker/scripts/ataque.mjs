// Teste de ataque ao tópico de comando (Etapa 7 e Etapa 10 "No ataque").
//
// Simula alguém que conseguiu credenciais do broker e tenta abrir o armário.
// 1. comando sem assinatura
// 2. comando com assinatura inventada
// 3. replay: um comando legítimo assinado pelo Worker publicado duas vezes
//
// Uso (na pasta worker):
//   MQTT_HOST=SEU_ENDERECO.emqxsl.com MQTT_USER=painel MQTT_PASS=... \
//   WORKER_URL=https://armario-emprestimo.SEU_USUARIO.workers.dev PAINEL_SENHA=... \
//   npm run ataque

import mqtt from 'mqtt';

const {
  MQTT_HOST,
  MQTT_USER,
  MQTT_PASS,
  WORKER_URL,
  PAINEL_SENHA,
  TOPICO_BASE = 'sis1a/hirrua/lab1/armario',
  DEVICE_ID = 'lab1',
} = process.env;

if (!MQTT_HOST || !MQTT_USER || !MQTT_PASS) {
  console.error('Defina MQTT_HOST, MQTT_USER e MQTT_PASS (e WORKER_URL e PAINEL_SENHA para o teste de replay).');
  process.exit(1);
}

const esperar = (ms) => new Promise((r) => setTimeout(r, ms));
const acks = [];

const cliente = mqtt.connect(`mqtts://${MQTT_HOST}:8883`, {
  username: MQTT_USER,
  password: MQTT_PASS,
  clientId: 'teste-ataque-' + Math.random().toString(16).slice(2, 8),
  rejectUnauthorized: true,
});

cliente.on('error', (e) => {
  console.error('Erro MQTT:', e.message);
  process.exit(1);
});

cliente.on('message', (topico, buf) => {
  const txt = buf.toString();
  console.log(`   <- ${topico.slice(TOPICO_BASE.length + 1)}: ${txt}`);
  if (topico.endsWith('/ack')) acks.push(JSON.parse(txt));
});

cliente.on('connect', async () => {
  console.log(`Conectado em mqtts://${MQTT_HOST}:8883 (TLS, certificado conferido)\n`);
  cliente.subscribe([`${TOPICO_BASE}/ack`, `${TOPICO_BASE}/alerta`]);
  await esperar(1000);

  const publicar = (descricao, payload) => {
    console.log(`-> ${descricao}\n   ${JSON.stringify(payload)}`);
    cliente.publish(`${TOPICO_BASE}/comando`, JSON.stringify(payload), { qos: 1 });
  };

  const agora = Date.now();
  publicar('Ataque 1, comando sem assinatura', { device: DEVICE_ID, acao: 'liberar', seq: agora, ts: Math.floor(agora / 1000) });
  await esperar(4000);

  publicar('Ataque 2, assinatura inventada', {
    device: DEVICE_ID,
    acao: 'liberar',
    seq: agora + 1,
    ts: Math.floor(agora / 1000),
    sig: 'a'.repeat(64),
  });
  await esperar(4000);

  if (WORKER_URL && PAINEL_SENHA) {
    const r = await fetch(`${WORKER_URL}/api/comando`, {
      method: 'POST',
      headers: { authorization: `Bearer ${PAINEL_SENHA}`, 'content-type': 'application/json' },
      body: JSON.stringify({ acao: 'travar' }),
    });
    const legitimo = await r.json();
    publicar('Comando legítimo "travar" assinado pelo Worker (deve ser executado)', legitimo);
    await esperar(4000);
    publicar('Ataque 3, replay do mesmo comando (deve ser recusado)', legitimo);
    await esperar(4000);
  } else {
    console.log('(teste de replay pulado: defina WORKER_URL e PAINEL_SENHA)');
  }

  console.log('\nResumo dos acks recebidos:');
  for (const a of acks) console.log(`  seq ${a.seq} ${a.acao} -> ${a.resultado}${a.motivo ? ' (' + a.motivo + ')' : ''}`);
  cliente.end();
});
