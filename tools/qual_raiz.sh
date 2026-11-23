#!/usr/bin/env bash
# Mostra a cadeia de certificados de um servidor e a autoridade raiz que a assina.
# Uso: tools/qual_raiz.sh armario-emprestimo.SEU_USUARIO.workers.dev
#      tools/qual_raiz.sh SEU_ENDERECO.emqxsl.com 8883
host="${1:?informe o host}"
porta="${2:-443}"
echo | openssl s_client -connect "$host:$porta" -servername "$host" -showcerts 2>/dev/null \
  | grep -E "^ *[0-9]+ s:|^ *i:" 
echo
echo "A última linha 'i:' é a raiz. Ela precisa estar em firmware/certificados.h."
