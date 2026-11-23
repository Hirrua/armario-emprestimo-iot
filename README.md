# Armário de Empréstimo de Laboratório

Trabalho N2 de IoT (G0813). O armário registra quem pegou cada equipamento e quando devolveu, mesmo sem internet, e só aceita comandos remotos assinados.

## O que o sistema faz

- O usuário digita o PIN no teclado e confirma com `#`. O ESP32 confere o PIN localmente (hash SHA-256 de `id:pin`), destrava o servo por uma janela curta e tira uma "foto" dos slots.
- O HC-SR04 mede a porta com histerese (aberta acima de 15 cm e fechada abaixo de 10 cm). Quando a porta fecha, o ESP32 trava de novo e compara os slots. Slot que esvaziou vira **retirada** e slot que encheu vira **devolução**, sempre ligadas ao usuário da sessão.
- Cada evento vai para uma fila persistente na NVS e é enviado ao Worker por HTTPS. Se a internet cair, o armário continua funcionando e a fila é enviada quando a rede volta, sem duplicar (cada evento tem id único).
- Telemetria, estado (retido, com Last Will), alertas e ack seguem por MQTT com TLS na porta 8883.
- O painel (servido pelo próprio Worker) mostra o estado em tempo real por MQTT sobre WebSocket seguro, o histórico vindo do D1 e permite liberar, travar e sincronizar. O comando só aparece como executado quando chega o ack do ESP32.
- Comandos remotos são assinados com HMAC-SHA256 pelo Worker. O ESP32 recusa assinatura inválida, replay (seq menor ou igual ao último aceito, guardado na NVS) e comando com horário fora de ±60 s.

## Estrutura

```
firmware/
  sketch.ino          firmware do ESP32 (máquina de estados + task de rede)
  diagram.json        circuito do Wokwi
  libraries.txt       bibliotecas do Wokwi
  certificados.h      certificados raiz para conferir o broker e o Worker
  secrets.example.h   modelo do secrets.h (o real fica fora do Git)
worker/
  src/index.js        rotas do Worker
  src/assinatura.js   HMAC do comando
  src/painel.html     painel web
  schema.sql          tabelas arm_* no D1
  seed.sql            equipamentos e usuários de teste
  scripts/ataque.mjs  teste de comando falso e replay
  wrangler.toml       bindings do D1, KV, cron e variáveis
  .dev.vars.example   modelo dos segredos locais
docs/                 caderno de projeto
```

## Circuito (Wokwi)

| Componente | GPIO | Papel |
|---|---|---|
| Teclado 4x4 | linhas 13, 14, 27, 26 · colunas 25, 33, 32, 16 | PIN do usuário |
| Servo | 18 | trava (0° travado, 90° liberado) |
| HC-SR04 | TRIG 5 · ECHO 34 | porta aberta ou fechada |
| Chaves deslizantes | 21, 22, 23 | presença do equipamento em cada slot |
| Buzzer | 19 | bipes e sirene |
| LED verde / vermelho | 4 / 15 | liberado / travado (vermelho pisca em alarme, bloqueio ou falha) |

## Como montar

### 1. Broker MQTT (EMQX Cloud Serverless, gratuito)

1. Crie uma conta em cloud-intl.emqx.com e uma implantação **Serverless** (limite de gasto 0, sem cartão).
2. Em Access Control > Authentication crie dois usuários, `armario-lab1` (para o ESP32) e `painel` (para o navegador).
3. Na Overview anote o endereço (`xxxx.ala.<regiao>.emqxsl.com`) e baixe o CA certificate. A porta TLS é 8883 e a de WebSocket seguro é 8084.
4. Cole o conteúdo do CA baixado no lugar indicado no fim de `firmware/certificados.h`.

### 2. Worker, D1 e KV

```bash
cd worker
npm install
npx wrangler login
```

Edite o `wrangler.toml` com o nome e o id do D1 e o id do KV que já existem (`npx wrangler d1 list` e `npx wrangler kv namespace list` mostram) e com o endereço do EMQX em `MQTT_HOST`.

```bash
npm run db:remote                         # cria as tabelas arm_* e os dados de teste
openssl rand -hex 32                      # rode duas vezes, uma para cada segredo abaixo
npx wrangler secret put DEVICE_TOKEN
npx wrangler secret put HMAC_KEY
npx wrangler secret put PAINEL_SENHA
npx wrangler secret put MQTT_PAINEL_USER  # painel
npx wrangler secret put MQTT_PAINEL_PASS
npm run deploy
```

O deploy mostra a URL `https://armario-emprestimo.<usuario>.workers.dev`.

### 3. Firmware no Wokwi

1. Crie um projeto ESP32 novo em wokwi.com.
2. Substitua `sketch.ino` e `diagram.json` pelos arquivos da pasta `firmware/`.
3. Crie as abas `certificados.h` e `secrets.h` (este último a partir do `secrets.example.h`, com os mesmos `DEVICE_TOKEN` e `HMAC_KEY` do Worker).
4. No Library Manager adicione PubSubClient, ArduinoJson, Keypad e ESP32Servo.
5. Clique em Play.

Não salve o projeto do Wokwi como público com o `secrets.h` preenchido.

## Como testar

PINs de teste do `seed.sql`: usuário 1 → `1234`, usuário 2 → `2580`, usuário 3 → `7777`.

No Serial do Wokwi existem três comandos de teste: `status`, `wifi off` e `wifi on`.

Para o ataque ao tópico de comando:

```bash
cd worker
MQTT_HOST=xxxx.ala.us-east-1.emqxsl.com MQTT_USER=painel MQTT_PASS=... \
WORKER_URL=https://armario-emprestimo.<usuario>.workers.dev PAINEL_SENHA=... \
npm run ataque
```

O roteiro completo dos testes da Etapa 10 está em `docs/roteiro-de-testes.md`.

## Teste local do Worker (sem Cloudflare)

```bash
cd worker
cp .dev.vars.example .dev.vars   # preencha
npm run db:local
npm run dev                      # http://localhost:8787
```
