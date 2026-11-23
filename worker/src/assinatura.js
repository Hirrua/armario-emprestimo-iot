export function mensagemComando(c) {
  return `${c.device}|${c.acao}|${c.seq}|${c.ts}`;
}

export async function hmacHex(chave, mensagem) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(chave), { name: 'HMAC', hash: 'SHA-256' }, false, [
    'sign',
  ]);
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(mensagem));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

export async function envelopar(chave, obj) {
  const dados = JSON.stringify(obj);
  return JSON.stringify({ dados, sig: await hmacHex(chave, dados) });
}

export async function abrirEnvelope(chave, texto) {
  let env;
  try {
    env = typeof texto === 'string' ? JSON.parse(texto) : texto;
  } catch {
    return null;
  }
  if (!env || typeof env.dados !== 'string' || typeof env.sig !== 'string') return null;
  const esperado = await hmacHex(chave, env.dados);
  if (esperado.length !== env.sig.length) return null;
  let dif = 0;
  for (let i = 0; i < esperado.length; i++) dif |= esperado.charCodeAt(i) ^ env.sig.charCodeAt(i);
  if (dif !== 0) return null;
  try {
    return JSON.parse(env.dados);
  } catch {
    return null;
  }
}
