#pragma once

// Copie este arquivo para secrets.h e preencha. O secrets.h está no .gitignore.
// No Wokwi, crie uma aba chamada secrets.h com o mesmo conteúdo preenchido.

// Wi-Fi (no Wokwi a rede é "Wokwi-GUEST", sem senha)
#define WIFI_SSID     "Wokwi-GUEST"
#define WIFI_PASS     ""

// Broker MQTT com TLS (EMQX Cloud Serverless, porta 8883). Credencial exclusiva do armário.
#define MQTT_HOST     "SEU_ENDERECO.ala.us-east-1.emqxsl.com"
#define MQTT_PORT     8883
#define MQTT_USER     "armario-lab1"
#define MQTT_PASS     "senha_do_armario_no_emqx"

// Identidade do armário e raiz dos tópicos (iguais ao wrangler.toml)
#define DEVICE_ID     "lab1"
#define TOPICO_BASE   "sis1a/hirrua/lab1/armario"

// Worker na Cloudflare (sem barra no final)
#define WORKER_URL    "https://armario-emprestimo.SEU_USUARIO.workers.dev"

// Mesmos valores cadastrados com "wrangler secret put" (gere com: openssl rand -hex 32)
#define DEVICE_TOKEN  "cole_aqui_o_device_token"
#define HMAC_KEY      "cole_aqui_a_hmac_key"
