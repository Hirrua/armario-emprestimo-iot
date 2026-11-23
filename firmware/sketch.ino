/*
  Armário de Empréstimo de Laboratório (IoT · Trabalho N2)

  Sentir    teclado (PIN), HC-SR04 (porta aberta/fechada), chaves de presença nos 3 slots
  Decidir   máquina de estados no ESP32, funciona sem internet
  Agir      servo (trava), buzzer (sirene), LEDs (sinalização)
  Nuvem     MQTT com TLS (telemetria, estado, comando assinado, ack, alerta)
            HTTPS para o Worker (histórico no D1, usuários e limites no KV)

  A rede roda numa task separada (core 0). O loop (core 1) só cuida de sensores,
  decisão e atuadores, então o armário continua respondendo mesmo quando a
  internet cai ou um handshake TLS demora.
*/

#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>
#include <Keypad.h>
#include <ESP32Servo.h>
#include <Preferences.h>
#include <time.h>
#include "mbedtls/md.h"
#include "esp_arduino_version.h"

#include "secrets.h"
#include "certificados.h"

// Comandos pelo Serial ("wifi off", "wifi on", "reboot", "status") para os testes de falha.
#define MODO_TESTE 1

/* ---------- pinos ---------- */

const uint8_t PIN_SERVO = 18;
const uint8_t PIN_TRIG = 5;
const uint8_t PIN_ECHO = 34;
const uint8_t PIN_BUZZER = 19;
const uint8_t PIN_LED_VERDE = 4;
const uint8_t PIN_LED_VERMELHO = 15;
const uint8_t NUM_SLOTS = 3;
const uint8_t PIN_SLOTS[NUM_SLOTS] = {21, 22, 23};

const byte LINHAS = 4, COLUNAS = 4;
char TECLAS[LINHAS][COLUNAS] = {
  {'1', '2', '3', 'A'},
  {'4', '5', '6', 'B'},
  {'7', '8', '9', 'C'},
  {'*', '0', '#', 'D'}};
byte PINOS_LINHAS[LINHAS] = {13, 14, 27, 26};
byte PINOS_COLUNAS[COLUNAS] = {25, 33, 32, 16};

/* ---------- constantes ---------- */

const int SERVO_TRAVADO = 0;
const int SERVO_LIBERADO = 90;
const float PORTA_ABRE_CM = 15.0;     // histerese: aberta acima de 15 cm
const float PORTA_FECHA_CM = 10.0;    // fechada abaixo de 10 cm
const uint8_t LEITURAS_INVALIDAS_FALHA = 3;
const uint32_t FECHADA_ESTAVEL_MS = 1000;
const uint32_t TELEMETRIA_MS = 15000;
const uint32_t SYNC_MS = 300000;
const uint32_t ENVIO_FILA_MS = 5000;
const uint32_t RECONEXAO_MS = 5000;
const int32_t JANELA_COMANDO_S = 60;
const uint8_t FILA_MAX = 40;
const uint8_t MAX_USUARIOS = 20;
const uint8_t MAX_TIPOS_ALERTA = 8;

/* ---------- estado ---------- */

enum Estado { TRAVADO, LIBERADO, ABERTO, BLOQUEADO };
const char *NOME_ESTADO[] = {"travado", "liberado", "aberto", "bloqueado"};

struct Limites {
  uint32_t janelaAberturaS = 10;
  uint32_t portaAbertaMaxS = 30;
  uint8_t maxTentativas = 3;
  uint32_t bloqueioS = 30;
  uint32_t cooldownAlertaS = 120;
} limites;

struct Usuario {
  int id;
  char hash[65];
};
Usuario usuarios[MAX_USUARIOS];
uint8_t totalUsuarios = 0;

Estado estado = TRAVADO;
uint32_t estadoDesde = 0;
uint32_t prazoAbertura = 0;
uint32_t bloqueioAte = 0;
int usuarioSessao = 0;            // 0 = sessão aberta pelo painel
bool slotsAntes[NUM_SLOTS];
bool slots[NUM_SLOTS];
uint8_t tentativasErradas = 0;
String pinDigitado;

float distanciaCm = -1;
bool portaAberta = false;
bool sensorOk = true;
uint8_t leiturasInvalidas = 0;
uint32_t fechadaDesde = 0;
uint32_t ultimaLeituraMs = 0;

bool alarmeAtivo = false;
bool travadoComPortaFechada = false;   // evita falso alarme logo depois de travar com a porta ainda aberta
uint32_t alarmeToggleMs = 0;
bool alarmeSom = false;

uint64_t ultimoSeqComando = 0;
uint32_t bootCount = 0;
uint32_t seqEvento = 0;
uint32_t eventosPerdidos = 0;

struct CooldownAlerta {
  char tipo[28];
  uint32_t ultimoMs;
};
CooldownAlerta cooldowns[MAX_TIPOS_ALERTA];
uint8_t totalCooldowns = 0;

volatile bool wifiPermitido = true;
volatile bool pedidoSync = true;
volatile bool syncNovo = false;
volatile bool estadoMudou = true;
volatile bool mqttConectado = false;
volatile int32_t rssiAtual = 0;
uint32_t ultimaTelemetria = 0;

// Comunicação entre o loop (core 1) e a task de rede (core 0)
enum TopicoSaida : uint8_t { T_TELEMETRIA, T_ESTADO, T_ACK, T_ALERTA };
struct MsgSaida {
  TopicoSaida topico;
  bool retain;
  char payload[400];
};
struct MsgComando {
  uint16_t tam;
  char payload[400];
};
QueueHandle_t filaSaida;
QueueHandle_t filaComandos;
SemaphoreHandle_t mutexPrefs;

Preferences prefs;
Servo trava;
Keypad teclado = Keypad(makeKeymap(TECLAS), PINOS_LINHAS, PINOS_COLUNAS, LINHAS, COLUNAS);
WiFiClientSecure tlsMqtt;
WiFiClientSecure tlsHttp;
PubSubClient mqtt(tlsMqtt);

String tTelemetria, tEstado, tComando, tAck, tAlerta;

/* ---------- utilitários ---------- */

bool horaValida() { return time(nullptr) > 1700000000; }
uint32_t agoraEpoch() { return horaValida() ? (uint32_t)time(nullptr) : 0; }

String hexDe(const uint8_t *b, size_t n) {
  static const char *H = "0123456789abcdef";
  String s;
  s.reserve(n * 2);
  for (size_t i = 0; i < n; i++) {
    s += H[b[i] >> 4];
    s += H[b[i] & 0x0f];
  }
  return s;
}

String sha256Hex(const String &txt) {
  uint8_t out[32];
  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0);
  mbedtls_md_starts(&ctx);
  mbedtls_md_update(&ctx, (const uint8_t *)txt.c_str(), txt.length());
  mbedtls_md_finish(&ctx, out);
  mbedtls_md_free(&ctx);
  return hexDe(out, 32);
}

String hmacSha256Hex(const char *chave, const String &msg) {
  uint8_t out[32];
  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
  mbedtls_md_hmac_starts(&ctx, (const uint8_t *)chave, strlen(chave));
  mbedtls_md_hmac_update(&ctx, (const uint8_t *)msg.c_str(), msg.length());
  mbedtls_md_hmac_finish(&ctx, out);
  mbedtls_md_free(&ctx);
  return hexDe(out, 32);
}

bool iguaisTempoConstante(const String &a, const String &b) {
  if (a.length() != b.length()) return false;
  uint8_t dif = 0;
  for (size_t i = 0; i < a.length(); i++) dif |= a[i] ^ b[i];
  return dif == 0;
}

String u64ParaTexto(uint64_t v) {
  char buf[24];
  snprintf(buf, sizeof(buf), "%llu", (unsigned long long)v);
  return String(buf);
}

/* ---------- atuadores ---------- */

void travar() { trava.write(SERVO_TRAVADO); }
void destravar() { trava.write(SERVO_LIBERADO); }

void bip(int freq, int ms) { tone(PIN_BUZZER, freq, ms); }

void atualizarAlarme() {
  if (!alarmeAtivo) {
    if (alarmeSom) {
      noTone(PIN_BUZZER);
      alarmeSom = false;
    }
    return;
  }
  if (millis() - alarmeToggleMs >= 300) {
    alarmeToggleMs = millis();
    alarmeSom = !alarmeSom;
    if (alarmeSom) tone(PIN_BUZZER, 2000);
    else noTone(PIN_BUZZER);
  }
}

void atualizarLeds() {
  bool pisca = (millis() / 250) % 2;
  bool liberado = (estado == LIBERADO || estado == ABERTO);
  digitalWrite(PIN_LED_VERDE, liberado ? HIGH : LOW);
  if (estado == BLOQUEADO || !sensorOk || alarmeAtivo) digitalWrite(PIN_LED_VERMELHO, pisca);
  else digitalWrite(PIN_LED_VERMELHO, liberado ? LOW : HIGH);
}

/* ---------- fila de eventos persistente (NVS) ---------- */

struct TravaPrefs {
  TravaPrefs() { xSemaphoreTake(mutexPrefs, portMAX_DELAY); }
  ~TravaPrefs() { xSemaphoreGive(mutexPrefs); }
};

uint32_t filaTamanho() {
  TravaPrefs t;
  return prefs.getUInt("ft", 0) - prefs.getUInt("fh", 0);
}

void enfileirar(JsonDocument &ev) {
  ev["id"] = String(DEVICE_ID) + "-" + String(bootCount) + "-" + String(++seqEvento);
  ev["ts"] = agoraEpoch();
  String s;
  serializeJson(ev, s);

  TravaPrefs t;
  uint32_t ini = prefs.getUInt("fh", 0), fim = prefs.getUInt("ft", 0);
  if (fim - ini >= FILA_MAX) {
    ini++;
    eventosPerdidos++;
    prefs.putUInt("fh", ini);
  }
  prefs.putString(("e" + String(fim % FILA_MAX)).c_str(), s);
  prefs.putUInt("ft", fim + 1);
  Serial.printf("[evento] %s (fila=%u)\n", s.c_str(), (unsigned)(fim + 1 - ini));
}

void registrar(const char *tipo, int usuarioId, int slot, const char *resultado, const char *detalhe) {
  JsonDocument ev;
  ev["tipo"] = tipo;
  if (usuarioId > 0) ev["usuario_id"] = usuarioId;
  if (slot > 0) ev["slot"] = slot;
  if (resultado) ev["resultado"] = resultado;
  if (detalhe) ev["detalhe"] = detalhe;
  enfileirar(ev);
}

// Roda na task de rede. Retorna o tempo até a próxima tentativa.
uint32_t enviarFila() {
  uint32_t ini, fim, n;
  String corpo = String("{\"device\":\"") + DEVICE_ID + "\",\"eventos\":[";
  {
    TravaPrefs t;
    ini = prefs.getUInt("fh", 0);
    fim = prefs.getUInt("ft", 0);
    if (ini == fim) return ENVIO_FILA_MS;
    n = (fim - ini) > 10 ? 10 : (fim - ini);
    for (uint32_t i = 0; i < n; i++) {
      if (i) corpo += ",";
      corpo += prefs.getString(("e" + String((ini + i) % FILA_MAX)).c_str(), "{}");
    }
  }
  corpo += "]}";

  HTTPClient http;
  http.setTimeout(8000);
  if (!http.begin(tlsHttp, String(WORKER_URL) + "/api/eventos")) return 30000;
  http.addHeader("Content-Type", "application/json");
  http.addHeader("Authorization", String("Bearer ") + DEVICE_TOKEN);
  int codigo = http.POST(corpo);
  http.end();

  if (codigo != 200) {
    Serial.printf("[http] falha ao enviar fila (codigo %d)\n", codigo);
    return 30000;
  }
  {
    TravaPrefs t;
    uint32_t atual = prefs.getUInt("fh", 0);
    if (ini + n > atual) prefs.putUInt("fh", ini + n);
  }
  Serial.printf("[http] %u evento(s) gravados no D1\n", (unsigned)n);
  return ENVIO_FILA_MS;
}

/* ---------- usuários e limites (vindos do KV pelo Worker) ---------- */

void aplicarSync(JsonDocument &doc) {
  JsonArray lista = doc["usuarios"].as<JsonArray>();
  totalUsuarios = 0;
  for (JsonObject u : lista) {
    if (totalUsuarios >= MAX_USUARIOS) break;
    const char *h = u["h"] | "";
    if (strlen(h) != 64) continue;
    usuarios[totalUsuarios].id = u["id"] | 0;
    strlcpy(usuarios[totalUsuarios].hash, h, sizeof(usuarios[0].hash));
    totalUsuarios++;
  }
  JsonObject c = doc["config"];
  limites.janelaAberturaS = c["janela_abertura_s"] | limites.janelaAberturaS;
  limites.portaAbertaMaxS = c["porta_aberta_max_s"] | limites.portaAbertaMaxS;
  limites.maxTentativas = c["max_tentativas"] | limites.maxTentativas;
  limites.bloqueioS = c["bloqueio_s"] | limites.bloqueioS;
  limites.cooldownAlertaS = c["cooldown_alerta_s"] | limites.cooldownAlertaS;
}

void carregarSyncSalvo() {
  String s;
  {
    TravaPrefs t;
    s = prefs.getString("sync", "");
  }
  if (s.isEmpty()) return;
  JsonDocument doc;
  if (deserializeJson(doc, s) == DeserializationError::Ok) aplicarSync(doc);
  Serial.printf("[boot] %u usuario(s) carregados da memoria local\n", totalUsuarios);
}

bool sincronizar() {
  HTTPClient http;
  http.setTimeout(8000);
  if (!http.begin(tlsHttp, String(WORKER_URL) + "/api/sync")) return false;
  http.addHeader("Authorization", String("Bearer ") + DEVICE_TOKEN);
  int codigo = http.GET();
  String resp = codigo == 200 ? http.getString() : "";
  http.end();
  if (codigo != 200) {
    Serial.printf("[sync] falhou (codigo %d), mantendo lista local\n", codigo);
    return false;
  }
  JsonDocument doc;
  if (deserializeJson(doc, resp) != DeserializationError::Ok) return false;
  {
    TravaPrefs t;
    prefs.putString("sync", resp);
  }
  syncNovo = true;   // o loop aplica a lista nova no próximo ciclo
  Serial.printf("[sync] lista de usuarios e limites baixada (%u usuario(s))\n", (unsigned)doc["usuarios"].size());
  return true;
}

int validarPin(const String &pin) {
  for (uint8_t i = 0; i < totalUsuarios; i++) {
    String h = sha256Hex(String(usuarios[i].id) + ":" + pin);
    if (iguaisTempoConstante(h, String(usuarios[i].hash))) return usuarios[i].id;
  }
  return 0;
}

/* ---------- MQTT ---------- */

void enfileirarSaida(TopicoSaida topico, const String &payload, bool retain) {
  if (!mqttConectado) return;
  MsgSaida m;
  m.topico = topico;
  m.retain = retain;
  strlcpy(m.payload, payload.c_str(), sizeof(m.payload));
  xQueueSend(filaSaida, &m, 0);
}

void publicarEstado() {
  if (!mqttConectado) return;
  JsonDocument d;
  d["online"] = true;
  d["estado"] = NOME_ESTADO[estado];
  d["trava"] = (estado == LIBERADO || estado == ABERTO) ? "liberado" : "travado";
  d["porta"] = !sensorOk ? "desconhecida" : (portaAberta ? "aberta" : "fechada");
  d["sensor"] = sensorOk ? "ok" : "falha";
  JsonArray s = d["slots"].to<JsonArray>();
  for (uint8_t i = 0; i < NUM_SLOTS; i++) s.add(slots[i] ? 1 : 0);
  d["ts"] = agoraEpoch();
  String out;
  serializeJson(d, out);
  estadoMudou = false;
  enfileirarSaida(T_ESTADO, out, true);
}

void publicarTelemetria() {
  if (!mqttConectado) return;
  JsonDocument d;
  d["dist_cm"] = sensorOk ? distanciaCm : -1;
  d["porta"] = !sensorOk ? "desconhecida" : (portaAberta ? "aberta" : "fechada");
  d["trava"] = (estado == LIBERADO || estado == ABERTO) ? "liberado" : "travado";
  d["sensor"] = sensorOk ? "ok" : "falha";
  d["estado"] = NOME_ESTADO[estado];
  JsonArray s = d["slots"].to<JsonArray>();
  for (uint8_t i = 0; i < NUM_SLOTS; i++) s.add(slots[i] ? 1 : 0);
  d["fila"] = filaTamanho();
  d["rssi_dbm"] = rssiAtual;
  d["uptime_s"] = millis() / 1000;
  d["ts"] = agoraEpoch();
  String out;
  serializeJson(d, out);
  enfileirarSaida(T_TELEMETRIA, out, false);
}

bool cooldownLiberado(const char *tipo) {
  uint32_t agora = millis();
  for (uint8_t i = 0; i < totalCooldowns; i++) {
    if (strcmp(cooldowns[i].tipo, tipo) == 0) {
      if (agora - cooldowns[i].ultimoMs < limites.cooldownAlertaS * 1000UL) return false;
      cooldowns[i].ultimoMs = agora;
      return true;
    }
  }
  if (totalCooldowns < MAX_TIPOS_ALERTA) {
    strlcpy(cooldowns[totalCooldowns].tipo, tipo, sizeof(cooldowns[0].tipo));
    cooldowns[totalCooldowns].ultimoMs = agora;
    totalCooldowns++;
  }
  return true;
}

void alerta(const char *tipo, const String &detalhe) {
  if (!cooldownLiberado(tipo)) {
    Serial.printf("[alerta] %s suprimido pelo cooldown\n", tipo);
    return;
  }
  Serial.printf("[alerta] %s %s\n", tipo, detalhe.c_str());
  registrar("alerta", usuarioSessao, 0, tipo, detalhe.c_str());
  JsonDocument d;
  d["tipo"] = tipo;
  d["detalhe"] = detalhe;
  d["ts"] = agoraEpoch();
  String out;
  serializeJson(d, out);
  enfileirarSaida(T_ALERTA, out, false);
}

void publicarAck(uint64_t seq, const char *acao, bool ok, const char *motivo) {
  Serial.printf("[comando] %s seq=%s -> %s %s\n", acao, u64ParaTexto(seq).c_str(), ok ? "executado" : "recusado", motivo ? motivo : "");
  String out = String("{\"seq\":") + u64ParaTexto(seq) + ",\"acao\":\"" + acao + "\",\"resultado\":\"" +
               (ok ? "executado" : "recusado") + "\"";
  if (motivo) out += String(",\"motivo\":\"") + motivo + "\"";
  out += "}";
  enfileirarSaida(T_ACK, out, false);
}

void iniciarSessao(int usuarioId);
void encerrarSessao(const char *motivo);

// Callback do PubSubClient (task de rede): só copia para a fila, quem decide é o loop.
void aoReceberMqtt(char *topico, byte *payload, unsigned int tam) {
  MsgComando c;
  c.tam = tam < sizeof(c.payload) ? tam : sizeof(c.payload) - 1;
  memcpy(c.payload, payload, c.tam);
  c.payload[c.tam] = 0;
  xQueueSend(filaComandos, &c, 0);
}

void tratarComando(const char *payload, size_t tam) {
  JsonDocument d;
  if (deserializeJson(d, payload, tam) != DeserializationError::Ok) {
    publicarAck(0, "?", false, "json_invalido");
    alerta("comando_invalido", "payload nao e JSON");
    return;
  }
  const char *device = d["device"] | "";
  const char *acao = d["acao"] | "";
  uint64_t seq = d["seq"].as<uint64_t>();
  uint32_t ts = d["ts"].as<uint32_t>();
  String sig = d["sig"] | "";

  if (strcmp(device, DEVICE_ID) != 0) {
    publicarAck(seq, acao, false, "device_errado");
    return;
  }
  String msg = String(device) + "|" + acao + "|" + u64ParaTexto(seq) + "|" + String(ts);
  if (!iguaisTempoConstante(hmacSha256Hex(HMAC_KEY, msg), sig)) {
    publicarAck(seq, acao, false, "assinatura_invalida");
    alerta("comando_invalido", String("assinatura invalida para '") + acao + "'");
    return;
  }
  if (seq <= ultimoSeqComando) {
    publicarAck(seq, acao, false, "replay");
    alerta("comando_invalido", "comando repetido (replay) recusado");
    return;
  }
  if (!horaValida()) {
    publicarAck(seq, acao, false, "sem_hora");
    return;
  }
  int32_t desvio = (int32_t)(agoraEpoch() - ts);
  if (desvio > JANELA_COMANDO_S || desvio < -JANELA_COMANDO_S) {
    publicarAck(seq, acao, false, "expirado");
    return;
  }

  ultimoSeqComando = seq;
  {
    TravaPrefs t;
    prefs.putULong64("seq", seq);
  }

  if (strcmp(acao, "travar") == 0) {
    if (estado == LIBERADO || estado == ABERTO) encerrarSessao("travado pelo painel");
    else travar();
    registrar("comando", 0, 0, "executado", "travar");
    publicarAck(seq, acao, true, nullptr);
  } else if (strcmp(acao, "liberar") == 0) {
    if (!sensorOk) {
      registrar("comando", 0, 0, "recusado", "liberar com sensor em falha");
      publicarAck(seq, acao, false, "sensor_falha");
      return;
    }
    if (estado == TRAVADO || estado == BLOQUEADO) iniciarSessao(0);
    registrar("comando", 0, 0, "executado", "liberar");
    publicarAck(seq, acao, true, nullptr);
  } else if (strcmp(acao, "sincronizar") == 0) {
    pedidoSync = true;
    publicarAck(seq, acao, true, nullptr);
  } else {
    publicarAck(seq, acao, false, "acao_desconhecida");
  }
}

void conectarMqtt() {
  String clientId = String("armario-") + DEVICE_ID;
  const char *lwt = "{\"online\":false}";
  Serial.println("[mqtt] conectando com TLS na porta 8883...");
  if (mqtt.connect(clientId.c_str(), MQTT_USER, MQTT_PASS, tEstado.c_str(), 1, true, lwt)) {
    Serial.println("[mqtt] conectado, certificado do broker conferido");
    mqtt.subscribe(tComando.c_str(), 1);
    mqttConectado = true;
    estadoMudou = true;   // o loop republica o estado retido
  } else {
    Serial.printf("[mqtt] falhou, rc=%d\n", mqtt.state());
  }
}

/* ---------- sensores ---------- */

void lerSlots() {
  for (uint8_t i = 0; i < NUM_SLOTS; i++) {
    bool presente = digitalRead(PIN_SLOTS[i]) == LOW;
    if (presente != slots[i]) {
      slots[i] = presente;
      estadoMudou = true;
      Serial.printf("[slot] %u %s\n", i + 1, presente ? "presente" : "vazio");
      if (estado == TRAVADO || estado == BLOQUEADO) {
        alerta(presente ? "item_inserido_travado" : "item_removido_travado",
               String("slot ") + (i + 1) + (presente ? " recebeu item" : " ficou vazio") + " com o armario travado");
      }
    }
  }
}

void lerPorta() {
  if (millis() - ultimaLeituraMs < 200) return;
  ultimaLeituraMs = millis();

  digitalWrite(PIN_TRIG, LOW);
  delayMicroseconds(2);
  digitalWrite(PIN_TRIG, HIGH);
  delayMicroseconds(10);
  digitalWrite(PIN_TRIG, LOW);
  unsigned long dur = pulseIn(PIN_ECHO, HIGH, 30000);
  float d = dur * 0.0343f / 2.0f;

  if (dur == 0 || d < 2.0f || d > 450.0f) {
    if (leiturasInvalidas < 255) leiturasInvalidas++;
    if (sensorOk && leiturasInvalidas >= LEITURAS_INVALIDAS_FALHA) {
      sensorOk = false;
      estadoMudou = true;
      alerta("sensor_falha", "HC-SR04 sem leitura valida, armario fica travado");
    }
    return;
  }

  leiturasInvalidas = 0;
  distanciaCm = d;
  if (!sensorOk) {
    sensorOk = true;
    estadoMudou = true;
    Serial.println("[sensor] leitura normalizada");
  }
  bool antes = portaAberta;
  if (!portaAberta && d >= PORTA_ABRE_CM) portaAberta = true;
  else if (portaAberta && d <= PORTA_FECHA_CM) portaAberta = false;
  if (antes != portaAberta) {
    estadoMudou = true;
    Serial.printf("[porta] %s (%.1f cm)\n", portaAberta ? "aberta" : "fechada", d);
  }
}

/* ---------- máquina de estados ---------- */

void mudarEstado(Estado novo) {
  if (novo == estado) return;
  Serial.printf("[estado] %s -> %s\n", NOME_ESTADO[estado], NOME_ESTADO[novo]);
  estado = novo;
  estadoDesde = millis();
  estadoMudou = true;
  if (novo == TRAVADO) travadoComPortaFechada = sensorOk && !portaAberta;
}

void iniciarSessao(int usuarioId) {
  usuarioSessao = usuarioId;
  memcpy(slotsAntes, slots, sizeof(slots));
  prazoAbertura = millis() + limites.janelaAberturaS * 1000UL;
  tentativasErradas = 0;
  destravar();
  bip(1500, 80);
  mudarEstado(LIBERADO);
}

void encerrarSessao(const char *motivo) {
  travar();
  alarmeAtivo = false;
  uint8_t mudancas = 0;
  for (uint8_t i = 0; i < NUM_SLOTS; i++) {
    if (slotsAntes[i] && !slots[i]) {
      registrar("retirada", usuarioSessao, i + 1, nullptr, nullptr);
      mudancas++;
    } else if (!slotsAntes[i] && slots[i]) {
      registrar("devolucao", usuarioSessao, i + 1, nullptr, nullptr);
      mudancas++;
    }
  }
  {
    TravaPrefs t;
    prefs.putUChar("slots", (slots[0] ? 1 : 0) | (slots[1] ? 2 : 0) | (slots[2] ? 4 : 0));
  }
  Serial.printf("[sessao] encerrada (%s), %u movimentacao(oes)\n", motivo, mudancas);
  usuarioSessao = 0;
  mudarEstado(TRAVADO);
}

void tratarTecla(char k) {
  if (estado == BLOQUEADO) {
    bip(300, 150);
    return;
  }
  if (estado != TRAVADO) return;
  bip(2500, 30);

  if (k == '*') {
    pinDigitado = "";
    return;
  }
  if (k != '#') {
    if (k >= '0' && k <= '9' && pinDigitado.length() < 8) pinDigitado += k;
    return;
  }

  String pin = pinDigitado;
  pinDigitado = "";
  if (pin.length() < 4) return;

  if (!sensorOk) {
    registrar("acesso", 0, 0, "bloqueado", "sensor da porta em falha");
    bip(300, 600);
    return;
  }

  int uid = validarPin(pin);
  if (uid > 0) {
    registrar("acesso", uid, 0, "liberado", "pin");
    Serial.printf("[acesso] usuario %d liberado\n", uid);
    iniciarSessao(uid);
    return;
  }

  tentativasErradas++;
  registrar("acesso", 0, 0, "negado", "pin incorreto");
  bip(300, 600);
  Serial.printf("[acesso] negado (%u/%u)\n", tentativasErradas, limites.maxTentativas);
  if (tentativasErradas >= limites.maxTentativas) {
    tentativasErradas = 0;
    bloqueioAte = millis() + limites.bloqueioS * 1000UL;
    mudarEstado(BLOQUEADO);
    alerta("tentativas_excedidas", String(limites.maxTentativas) + " PINs errados, teclado bloqueado por " + limites.bloqueioS + " s");
  }
}

void verificarViolacao() {
  if (!sensorOk) return;
  if (!portaAberta) {
    travadoComPortaFechada = true;
    if (alarmeAtivo) alarmeAtivo = false;
    return;
  }
  if (travadoComPortaFechada && !alarmeAtivo) {
    alarmeAtivo = true;
    alerta("violacao", "porta aberta com o armario travado");
  }
}

void maquinaDeEstados() {
  uint32_t agora = millis();
  switch (estado) {
    case TRAVADO:
      verificarViolacao();
      break;

    case BLOQUEADO:
      verificarViolacao();
      if ((int32_t)(agora - bloqueioAte) >= 0) mudarEstado(TRAVADO);
      break;

    case LIBERADO:
      if (!sensorOk) {
        encerrarSessao("sensor falhou antes da abertura");
      } else if (portaAberta) {
        mudarEstado(ABERTO);
        fechadaDesde = 0;
      } else if ((int32_t)(agora - prazoAbertura) >= 0) {
        encerrarSessao("janela de abertura expirou");
      }
      break;

    case ABERTO:
      if (!sensorOk) {
        alerta("sensor_falha", "sensor falhou com a porta aberta, sessao encerrada");
        encerrarSessao("sensor falhou");
        break;
      }
      if (!portaAberta) {
        if (fechadaDesde == 0) fechadaDesde = agora;
        if (agora - fechadaDesde >= FECHADA_ESTAVEL_MS) encerrarSessao("porta fechada");
      } else {
        fechadaDesde = 0;
        if (!alarmeAtivo && agora - estadoDesde >= limites.portaAbertaMaxS * 1000UL) {
          alarmeAtivo = true;
          alerta("porta_aberta", String("porta aberta ha mais de ") + limites.portaAbertaMaxS + " s");
        }
      }
      break;
  }
}

/* ---------- rede (task no core 0) ---------- */

const char *topicoDe(TopicoSaida t) {
  switch (t) {
    case T_TELEMETRIA: return tTelemetria.c_str();
    case T_ESTADO: return tEstado.c_str();
    case T_ACK: return tAck.c_str();
    default: return tAlerta.c_str();
  }
}

void taskRede(void *) {
  uint32_t ultimaTentativaWifi = 0, ultimaTentativaMqtt = 0, ultimoSync = 0, ultimoEnvio = 0;
  uint32_t esperaEnvio = ENVIO_FILA_MS;
  uint32_t conectadoDesde = 0;
  bool wifiLigado = true;
  bool ntpIniciado = false;

  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASS, 6);
  ultimaTentativaWifi = millis();

  for (;;) {
    uint32_t agora = millis();

    if (!wifiPermitido) {
      if (wifiLigado) {
        // Fecha o socket sem DISCONNECT do MQTT, como numa queda real: o broker publica o Last Will.
        tlsMqtt.stop();
        mqttConectado = false;
        WiFi.disconnect(true);
        wifiLigado = false;
      }
      vTaskDelay(pdMS_TO_TICKS(200));
      continue;
    }
    if (!wifiLigado) {
      WiFi.mode(WIFI_STA);
      wifiLigado = true;
      ultimaTentativaWifi = 0;
    }

    if (WiFi.status() != WL_CONNECTED) {
      mqttConectado = false;
      conectadoDesde = 0;
      if (agora - ultimaTentativaWifi > 10000) {
        ultimaTentativaWifi = agora;
        Serial.println("[wifi] conectando...");
        WiFi.disconnect();
        WiFi.begin(WIFI_SSID, WIFI_PASS, 6);
      }
      vTaskDelay(pdMS_TO_TICKS(200));
      continue;
    }
    rssiAtual = WiFi.RSSI();

    // Dá um tempo para a pilha de rede assentar antes do NTP e da primeira conexão TLS.
    if (conectadoDesde == 0) {
      conectadoDesde = agora;
      Serial.printf("[wifi] conectado, IP %s\n", WiFi.localIP().toString().c_str());
    }
    if (agora - conectadoDesde < 2000) {
      vTaskDelay(pdMS_TO_TICKS(100));
      continue;
    }
    if (!ntpIniciado) {
      configTime(0, 0, "pool.ntp.org", "time.google.com");
      ntpIniciado = true;
    }

    if (!horaValida()) {
      vTaskDelay(pdMS_TO_TICKS(200));
      continue;
    }

    if (!mqtt.connected()) {
      if (mqttConectado) Serial.println("[mqtt] conexao perdida");
      mqttConectado = false;
      if (agora - ultimaTentativaMqtt > RECONEXAO_MS) {
        ultimaTentativaMqtt = agora;
        conectarMqtt();
      }
    } else {
      mqtt.loop();
      MsgSaida m;
      while (xQueueReceive(filaSaida, &m, 0) == pdTRUE) {
        mqtt.publish(topicoDe(m.topico), m.payload, m.retain);
      }
    }

    if (pedidoSync || agora - ultimoSync > SYNC_MS) {
      ultimoSync = agora;
      pedidoSync = false;
      sincronizar();
    } else if (agora - ultimoEnvio > esperaEnvio && filaTamanho() > 0) {
      ultimoEnvio = agora;
      esperaEnvio = enviarFila();
    }

    vTaskDelay(pdMS_TO_TICKS(10));
  }
}

#if MODO_TESTE
void comandosSerial() {
  if (!Serial.available()) return;
  String c = Serial.readStringUntil('\n');
  c.trim();
  if (c == "wifi off") {
    wifiPermitido = false;
    Serial.println("[teste] Wi-Fi desligado, o armario segue funcionando localmente");
  } else if (c == "wifi on") {
    wifiPermitido = true;
    Serial.println("[teste] Wi-Fi religado");
  } else if (c == "reboot") {
    // Reinicia o chip sem apagar a flash, como tirar e ligar o USB.
    Serial.println("[teste] reiniciando...");
    delay(100);
    ESP.restart();
  } else if (c == "status") {
    Serial.printf("[status] estado=%s porta=%s dist=%.1f sensor=%s slots=%d%d%d fila=%u perdidos=%u usuarios=%u wifi=%s mqtt=%s hora=%s\n",
                  NOME_ESTADO[estado], portaAberta ? "aberta" : "fechada", distanciaCm, sensorOk ? "ok" : "falha",
                  slots[0], slots[1], slots[2], (unsigned)filaTamanho(), (unsigned)eventosPerdidos, totalUsuarios,
                  WiFi.status() == WL_CONNECTED ? "ok" : "off", mqttConectado ? "ok" : "off", horaValida() ? "ok" : "sem NTP");
  }
}
#endif

/* ---------- setup e loop ---------- */

void setup() {
  Serial.begin(115200);
  Serial.setTimeout(20);

  // Estado seguro primeiro: ao ligar ou reiniciar, a trava fecha antes de qualquer coisa.
#if ESP_ARDUINO_VERSION_MAJOR < 3
  setToneChannel(15);   // no core 2.x o tone() usaria o canal 0, o mesmo do servo
#endif
  ESP32PWM::allocateTimer(0);
  trava.setPeriodHertz(50);
  trava.attach(PIN_SERVO, 500, 2400);
  travar();

  pinMode(PIN_TRIG, OUTPUT);
  pinMode(PIN_ECHO, INPUT);
  pinMode(PIN_LED_VERDE, OUTPUT);
  pinMode(PIN_LED_VERMELHO, OUTPUT);
  pinMode(PIN_BUZZER, OUTPUT);
  for (uint8_t i = 0; i < NUM_SLOTS; i++) pinMode(PIN_SLOTS[i], INPUT_PULLUP);

  Serial.println();
  Serial.println("=== Armario de Emprestimo ===");

  mutexPrefs = xSemaphoreCreateMutex();
  filaSaida = xQueueCreate(12, sizeof(MsgSaida));
  filaComandos = xQueueCreate(4, sizeof(MsgComando));

  prefs.begin("armario", false);
  bootCount = prefs.getUInt("boot", 0) + 1;
  prefs.putUInt("boot", bootCount);
  ultimoSeqComando = prefs.getULong64("seq", 0);
  carregarSyncSalvo();

  tTelemetria = String(TOPICO_BASE) + "/telemetria";
  tEstado = String(TOPICO_BASE) + "/estado";
  tComando = String(TOPICO_BASE) + "/comando";
  tAck = String(TOPICO_BASE) + "/ack";
  tAlerta = String(TOPICO_BASE) + "/alerta";

  for (uint8_t i = 0; i < NUM_SLOTS; i++) slots[i] = digitalRead(PIN_SLOTS[i]) == LOW;
  memcpy(slotsAntes, slots, sizeof(slots));
  uint8_t salvos;
  {
    TravaPrefs t;
    salvos = prefs.getUChar("slots", 0xFF);
  }
  uint8_t atuais = (slots[0] ? 1 : 0) | (slots[1] ? 2 : 0) | (slots[2] ? 4 : 0);
  Serial.printf("[boot] boot #%u, trava fechada, slots=%d%d%d, fila=%u\n", (unsigned)bootCount, slots[0], slots[1], slots[2], (unsigned)filaTamanho());
  registrar("boot", 0, 0, nullptr, nullptr);
  if (salvos != 0xFF && salvos != atuais) {
    alerta("inventario_divergente", "slots mudaram enquanto o armario estava desligado");
  }
  {
    TravaPrefs t;
    prefs.putUChar("slots", atuais);
  }

  tlsMqtt.setCACert(ROOT_CA_BUNDLE);
  tlsHttp.setCACert(ROOT_CA_BUNDLE);
  mqtt.setServer(MQTT_HOST, MQTT_PORT);
  mqtt.setBufferSize(1024);
  mqtt.setKeepAlive(30);
  mqtt.setSocketTimeout(10);
  mqtt.setCallback(aoReceberMqtt);

  xTaskCreatePinnedToCore(taskRede, "rede", 16384, nullptr, 1, nullptr, 0);

  estadoDesde = millis();
  travadoComPortaFechada = false;
  bip(1000, 100);
}

void loop() {
  char k = teclado.getKey();
  if (k) tratarTecla(k);

  lerPorta();
  lerSlots();
  maquinaDeEstados();
  atualizarAlarme();
  atualizarLeds();

#if MODO_TESTE
  comandosSerial();
#endif

  if (syncNovo) {
    syncNovo = false;
    carregarSyncSalvo();
    Serial.printf("[sync] aplicado, %u usuario(s), porta max %us, janela %us\n", totalUsuarios,
                  (unsigned)limites.portaAbertaMaxS, (unsigned)limites.janelaAberturaS);
  }

  MsgComando cmd;
  if (xQueueReceive(filaComandos, &cmd, 0) == pdTRUE) tratarComando(cmd.payload, cmd.tam);

  if (estadoMudou) publicarEstado();
  if (millis() - ultimaTelemetria > TELEMETRIA_MS) {
    ultimaTelemetria = millis();
    publicarTelemetria();
  }
  delay(5);
}
