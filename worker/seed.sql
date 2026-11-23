-- Dados iniciais para demonstração.
-- pin_hash = SHA-256 de "<id>:<pin>". PINs de teste: 1 -> 1234, 2 -> 2580, 3 -> 7777.

INSERT OR IGNORE INTO arm_equipamentos (slot, nome) VALUES
  (1, 'Multímetro digital'),
  (2, 'Osciloscópio portátil'),
  (3, 'Kit Arduino');

INSERT OR IGNORE INTO arm_usuarios (id, nome, pin_hash) VALUES
  (1, 'Professor','e3ebee0ac16ab73da385eae0743463bbe5917c4ead6389d624ce91ae5360cb5f'),
  (2, 'Aluno A',       'f969fc550fe79f994f82607beb60af93b407b16af6ab1650a731cc6e6c90fdc7'),
  (3, 'Aluno B',       '2d34923d07d1893fe801b5f12ccdbd32a2fc230add3d3f5471748ec3d0be09e2');
