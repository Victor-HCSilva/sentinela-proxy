-- Configurações de interface padrão
INSERT OR IGNORE INTO configs
(id, traffic_visible, theme)
VALUES (1234, 32, 'Dark');


-- Dominios conhecidos
INSERT OR IGNORE INTO urls (id, url) VALUES (1, 'google.com');
INSERT OR IGNORE INTO urls (id, url) VALUES (2, 'globo.com');
INSERT OR IGNORE INTO urls (id, url) VALUES (3, 'youtube.com');
INSERT OR IGNORE INTO urls (id, url) VALUES (4, 'facebook.com');
INSERT OR IGNORE INTO urls (id, url) VALUES (5, 'chatgpt.com');
INSERT OR IGNORE INTO urls (id, url) VALUES (6, 'x.com');
INSERT OR IGNORE INTO urls (id, url) VALUES (7, 'reddit.com');


-- Dominios de anuncios
INSERT OR IGNORE INTO adds_domains (url_id) VALUES (4); -- facebook
INSERT OR IGNORE INTO adds_domains (url_id) VALUES (2); -- globo


-- Black List
INSERT OR IGNORE INTO black_list (url_id) VALUES (2); -- globo


-- Headers que podem ser excluidos
INSERT OR IGNORE INTO exclude_headers (field_name) VALUES ('cookie');
INSERT OR IGNORE INTO exclude_headers (field_name) VALUES ('User-Agent');
INSERT OR IGNORE INTO exclude_headers (field_name) VALUES ('Authorization');


-- White list
INSERT OR IGNORE INTO white_list (url_id) VALUES (1);
INSERT OR IGNORE INTO white_list (url_id) VALUES (3);

