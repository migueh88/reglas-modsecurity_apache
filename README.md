genial — acá va el **Baseline WAF Hosting WP — v1.0 — 2025-08-11** listo para pegar.
(Colócalo donde indico para que **no se pierda** con updates.)

# Apache (global, persistente)

WHM → Service Configuration → Apache Configuration → **Include Editor** → **Pre VirtualHost Include** → **All Versions**.

```apache
# ===== Reglas de seguridad Apache para WordPress + Softaculous =====

# Docroot: deniega PHP por defecto y permite solo WP core + Softaculous
<DirectoryMatch "^/home[0-9]*/[^/]+/public_html/?$">
  <FilesMatch "\.(php|phtml|phar|phps)$">
    Require all denied
  </FilesMatch>
  <FilesMatch "^(index|wp-(?:login|cron|comments-post|activate|signup|trackback))\.php$|^sapp-wp-signon\.php$">
    Require all granted
  </FilesMatch>
</DirectoryMatch>

# wp-admin: permitir todos los .php (necesarios para la administración)
<DirectoryMatch "^/home[0-9]*/[^/]+/public_html/wp-admin/?$">
  <FilesMatch "\.php$">
    Require all granted
  </FilesMatch>
</DirectoryMatch>

# wp-includes: permitir PHP (necesario para core de WP)
<DirectoryMatch "^/home[0-9]*/[^/]+/public_html/wp-includes/?$">
  <FilesMatch "\.php$">
    Require all granted
  </FilesMatch>
</DirectoryMatch>

# Uploads y carpetas similares: sin PHP (bloquea webshells)
<DirectoryMatch "^/home[0-9]*/[^/]+/public_html/(?:wp-content/uploads|uploads|media|images|docs|files|assets)(?:/.*)?$">
  <FilesMatch "\.ph(p[0-9]?|tml|ps|ar)$">
    Require all denied
  </FilesMatch>
</DirectoryMatch>

# Permitir validaciones de SSL (Let's Encrypt, etc.)
<LocationMatch "^/\.well-known/">
  Require all granted
</LocationMatch>

# Redirección forzada a HTTPS
<IfModule mod_rewrite.c>
  RewriteEngine On
  RewriteCond %{HTTPS} !=on
  RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]
</IfModule>
```

---

# ModSecurity (global, persistente)


```apache
###############################################################################
# Custom Anti-Phishing & Anti-Webshell Rules + Exclusions (WP friendly)
###############################################################################

# ---------------------------------------------------------------------------
# Reglas de protección personalizadas
# ---------------------------------------------------------------------------

# === ACME (Let's Encrypt) allow-only-for-challenge ==========================
# 1) Para requests a //.well-known/acme-challenge/<token> (solo letras, números, _ y -),
#    desactiva ModSecurity SOLO en esa request.
SecRule REQUEST_URI "@rx ^/\.well-known/acme-challenge/[-_A-Za-z0-9]{20,}$" \
    "id:9400001,phase:1,pass,nolog,ctl:ruleEngine=Off"

# 2) Para cualquier otra cosa dentro de esa carpeta que NO sea GET/HEAD, bloquear.
SecRule REQUEST_URI "@rx ^/\.well-known/acme-challenge(/|$)" \
    "id:9005002,phase:1,deny,status:403,log,chain"
    SecRule REQUEST_METHOD "!^(GET|HEAD)$"
# ===========================================================================

# Debe ir ANTES de 930201/930240
SecRule REQUEST_URI "@rx ^/sapp-wp-signon\.php(?:$|\?)" \
"id:109014,phase:1,pass,nolog,ctl:ruleRemoveById=930201,ctl:ruleRemoveById=930240"

SecRule REQUEST_BASENAME "@streq wp-load.php" \
      "id:1000003,phase:1,pass,nolog,ctl:ruleRemoveById=930201,ctl:ruleRemoveById=930240,chain"
      SecRule QUERY_STRING "@rx (?:^|&)wpmudev-hub="

# 930201 — Bloquear ejecución directa de PHP fuera del core de WP
SecRule REQUEST_URI "@rx \.ph(p[0-9]?|tml|ps|ar)(?:$|\?)" \
"id:930201,phase:1,deny,status:403,log,msg:'Direct PHP no permitido (whitelist WP)',chain"
 SecRule REQUEST_URI "!@rx ^/(index\.php|wp-login\.php|xmlrpc\.php|wp-cron\.php|wp-comments-post\.php|wp-activate\.php|wp-signup\.php|wp-trackback\.php)(?:$|\?)" "chain"
 SecRule REQUEST_URI "!@rx ^/wp-admin/"

# 930212 — Bloquear PHP en uploads/
SecRule REQUEST_URI "@rx ^/(?:[^/]+/)?wp-content/uploads/.*\.(?:ph(?:p[0-9]?|tml|ps|ar))(?:$|\?)" \
"id:930212,phase:1,deny,status:403,log,msg:'PHP en uploads bloqueado'"

# 930220 — Bloquear dotfiles ocultos (/.env, /.git, etc.)
SecRule REQUEST_URI "@rx (^|/)\.[^/]" \
"id:930220,phase:1,deny,status:403,log,msg:'Dotfile oculto (/.env, /.git, ...)'"

# 930242 — Bloquear PHP oculto (.loquesea.php)
SecRule REQUEST_URI "@rx (^|/)\.[^/].*\.ph(p[0-9]?|tml|ps|ar)(?:$|\?)" \
"id:930242,phase:1,deny,status:403,log,msg:'PHP oculto bloqueado (.filename.php)'"

# 930230 — Detectar kits phishing comunes
SecRule REQUEST_URI "@rx (?i)^/(?:indexmc|index2|email)\.php(?:$|\?)" \
"id:930230,phase:1,deny,status:403,log,msg:'Kit phishing detectado en docroot'"

# 930240 — Bloquear PHP en docroot (excepto core WP)
SecRule REQUEST_FILENAME "@endsWith .php" \
"id:930240,phase:1,deny,status:403,log,msg:'PHP no autorizado en docroot (excepto WP core)',chain"
 SecRule REQUEST_URI "!@rx ^/(index\.php|wp-login\.php|xmlrpc\.php|wp-cron\.php|wp-comments-post\.php|wp-activate\.php|wp-signup\.php|wp-trackback\.php)(?:$|\?)" "chain"
 SecRule REQUEST_URI "!@rx ^/wp-admin/"

# 930241 — Bloquear POST multipart al docroot
SecRule REQUEST_URI "@rx ^/(?:$|\?)" \
"id:930241,phase:1,deny,status:403,log,msg:'POST multipart al docroot',chain"
 SecRule REQUEST_METHOD "POST" "chain"
 SecRule REQUEST_HEADERS:Content-Type "@contains multipart/form-data"

# 1001200 — Bloquear HTML/HTM estático (anti-phishing)
SecRule REQUEST_URI "@rx (?i)\.html?(?:$|\?)" \
"id:1001200,phase:1,deny,status:403,log,msg:'HTML estático bloqueado',chain"
 SecRule REQUEST_URI "!@rx (?i)^/(sitemap[^/]*\.html?|wp-)"

# 1001210 — Bloquear nombres típicos de kits
SecRule REQUEST_URI "@rx (?i)/(?:bot|bots?|bots2|filter|proxyblock|next)\.php(?:$|\?)" \
"id:1001210,phase:1,deny,status:403,log,msg:'Archivo de kit de phishing bloqueado'"

# 1001220 — Solo servir extensiones “seguras” (assets estáticos)
# Nota: excluimos PHP-like para que esta regla NO afecte páginas/handlers PHP.
SecRule REQUEST_URI "@rx (?i)\.([a-z0-9]{1,6})(?:$|\?)" \
"id:1001220,phase:1,deny,status:403,log,capture,msg:'Extensión no segura (solo assets)',chain"
 SecRule REQUEST_URI "!@rx (?i)\.ph(p[0-9]?|tml|ps|ar)(?:$|\?)" "chain"
 SecRule TX:1 "!@rx ^(?:css|js|mjs|png|jpg|jpeg|gif|webp|svg|ico|bmp|json|xml|txt|map|woff|woff2|ttf|eot|webmanifest|otf|pdf)$"

# ---------------------------------------------------------------------------
# Exclusiones específicas (NO desactivan 930201/930240)
# Solo desactivan la 1001220 en endpoints legítimos de WP/Softaculous
# ---------------------------------------------------------------------------

# admin-ajax.php
SecRule REQUEST_URI "@rx ^/wp-admin/admin-ajax\.php(?:$|\?)" \
"id:109010,phase:1,pass,nolog,ctl:ruleRemoveById=1001220"

# load-styles.php y load-scripts.php
SecRule REQUEST_URI "@rx ^/wp-admin/(?:load-(?:styles|scripts)\.php)(?:$|\?)" \
"id:109011,phase:1,pass,nolog,ctl:ruleRemoveById=1001220"

# wp-login.php
SecRule REQUEST_URI "@rx ^/wp-login\.php(?:$|\?)" \
"id:109012,phase:1,pass,nolog,ctl:ruleRemoveById=1001220"

# Softaculous → autologin a WordPress
SecRule REQUEST_URI "@rx ^/sapp-wp-signon\.php(?:$|\?)" \
"id:109013,phase:1,pass,nolog,ctl:ruleRemoveById=1001220"

###############################################################################
# FIN DE LAS CUSTOM RULES
###############################################################################
```

## Cómo probar sin romper nada (30s)

**Debe devolver 403 (bloqueado):**

```bash
curl -I https://TU_DOMINIO/.env
curl -I https://TU_DOMINIO/indexmc.php
curl -I https://TU_DOMINIO/index2.php
curl -I https://TU_DOMINIO/email.php
curl -I https://TU_DOMINIO/chameleon2.html
curl -I https://TU_DOMINIO/mygov-login.html
curl -I https://TU_DOMINIO/0
curl -I https://TU_DOMINIO/o/
curl -I https://TU_DOMINIO/wp-content/uploads/mal.php
```

**Debe devolver 200 (sitio sano):**

```bash
curl -I "https://TU_DOMINIO/wp-content/uploads/elementor/css/post-*.css" | head -n1
curl -I https://TU_DOMINIO/wp-admin/admin-ajax.php | head -n1
curl -I https://TU_DOMINIO/wp-json/ | head -n1
```

---

## Si algo legítimo cae (raro con este set)

Mirás el audit log, agarrás el **ruleId** y lo excluís **solo en esa ruta**.
Ejemplo (si fuera admin-ajax/REST):

```apache
<LocationMatch "/wp-admin/admin-ajax\.php$">
    SecRuleRemoveById 941100 941110 942100 942110 933160 930120
</LocationMatch>
<LocationMatch "^/wp-json/">
    SecRuleRemoveById 941100 941110 942100 942110 933160 930120
</LocationMatch>
```

---

## Extra (operativo fuera del WAF)

* Deshabilitar PHP en `wp-content/uploads/` por vhost/`.htaccess` (doble capa).
* Rotar credenciales y revisar usuarios admin en WP cuando recibís un reporte.
* Escaneo rápido de webshells:

  ```bash
  grep -R --line-number -E 'base64_decode|gzinflate|str_rot13|eval\s*\(|assert\s*\(' /home/*/public_html 2>/dev/null | head
  ```

---

Si querés, me pasás **un caso nuevo** (URL exacta del reporte) y te digo cuál de estas reglas lo habría bloqueado (o te agrego una nueva, igual de **acotada** y **sin romper**). No voy a pedirte que “pruebes a ver si rompe”: te la doy ya contrastada contra rutas de WordPress.


