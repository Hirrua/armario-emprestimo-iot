-- Tabelas do Armário de Empréstimo.
-- O prefixo arm_ evita conflito com as tabelas do outro trabalho que usam o mesmo D1.

CREATE TABLE IF NOT EXISTS arm_usuarios (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  nome       TEXT    NOT NULL,
  pin_hash   TEXT    NOT NULL,
  ativo      INTEGER NOT NULL DEFAULT 1,
  criado_em  TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS arm_equipamentos (
  slot  INTEGER PRIMARY KEY,
  nome  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS arm_emprestimos (
  id                INTEGER PRIMARY KEY AUTOINCREMENT,
  slot              INTEGER NOT NULL REFERENCES arm_equipamentos(slot),
  usuario_id        INTEGER REFERENCES arm_usuarios(id),
  retirada_em       TEXT    NOT NULL,
  devolvido_em      TEXT,
  devolvido_por     INTEGER REFERENCES arm_usuarios(id),
  evento_retirada   TEXT UNIQUE,
  evento_devolucao  TEXT UNIQUE
);

CREATE INDEX IF NOT EXISTS idx_arm_emp_abertos ON arm_emprestimos(slot, devolvido_em);
CREATE INDEX IF NOT EXISTS idx_arm_emp_retirada ON arm_emprestimos(retirada_em);

-- Todo evento que chega do ESP32. O id é gerado no ESP32 (device-boot-seq),
-- então reenviar a fila depois de uma queda de rede não duplica nada.
CREATE TABLE IF NOT EXISTS arm_eventos (
  id               TEXT PRIMARY KEY,
  device           TEXT    NOT NULL,
  tipo             TEXT    NOT NULL,
  ts               TEXT    NOT NULL,
  hora_aproximada  INTEGER NOT NULL DEFAULT 0,
  usuario_id       INTEGER,
  slot             INTEGER,
  resultado        TEXT,
  detalhe          TEXT,
  recebido_em      TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_arm_evt_ts ON arm_eventos(ts);
CREATE INDEX IF NOT EXISTS idx_arm_evt_tipo ON arm_eventos(tipo, ts);
