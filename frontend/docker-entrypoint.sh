#!/bin/sh
set -eu

PUBLIC_HOST="${PUBLIC_HOST:-localhost}"
TLS_MODE="${TLS_MODE:-internal}"
ACME_EMAIL="${ACME_EMAIL:-admin@localhost}"
CERT_DIR="/var/lib/angie/certs"
ACME_DIR="/var/lib/angie/acme"
CONF_DIR="/etc/angie/conf.d"

mkdir -p "$CERT_DIR" "$ACME_DIR" "$CONF_DIR"

use_acme=0
if [ "$TLS_MODE" = "acme" ] && [ "$PUBLIC_HOST" != "localhost" ]; then
  use_acme=1
fi

if [ "$use_acme" -eq 1 ]; then
  cat > "$CONF_DIR/acme-http.conf" <<EOF
resolver 1.1.1.1 8.8.8.8 valid=300s ipv6=off;
resolver_timeout 5s;
acme_client_path ${ACME_DIR};
acme_client letsencrypt https://acme-v02.api.letsencrypt.org/directory email=${ACME_EMAIL};
EOF
  cat > "$CONF_DIR/ssl.conf" <<'EOF'
acme letsencrypt;
ssl_certificate $acme_cert_letsencrypt;
ssl_certificate_key $acme_cert_key_letsencrypt;
EOF
else
  : > "$CONF_DIR/acme-http.conf"
  if [ ! -f "$CERT_DIR/cert.pem" ]; then
    openssl ecparam -genkey -name prime256v1 -out "$CERT_DIR/key.pem" 2>/dev/null
    openssl req -new -x509 -nodes -days 825 \
      -key "$CERT_DIR/key.pem" -out "$CERT_DIR/cert.pem" \
      -subj "/CN=ophthalmoguide.ru" \
       -addext "subjectAltName=DNS:ophthalmoguide.ru,DNS:${PUBLIC_HOST},DNS:localhost,IP:127.0.0.1" \
      || openssl req -new -x509 -nodes -days 825 \
        -key "$CERT_DIR/key.pem" -out "$CERT_DIR/cert.pem" \
        -subj "/CN=${PUBLIC_HOST}"
  fi
  cat > "$CONF_DIR/ssl.conf" <<EOF
ssl_certificate ${CERT_DIR}/cert.pem;
ssl_certificate_key ${CERT_DIR}/key.pem;
EOF
fi

sed -e "s/__PUBLIC_HOST__/${PUBLIC_HOST}/g" -e "s/__CAP_SITE_KEY__/${CAP_SITE_KEY:-f31d5d6959}/g" /etc/angie/angie.conf.template > /etc/angie/angie.conf

if [ "$use_acme" -eq 1 ]; then
  sed -i '/# MARKER_HTTP_REDIRECT_START/,/# MARKER_HTTP_REDIRECT_END/d' /etc/angie/angie.conf
  sed -i 's|# MARKER_ACME_HTTP_LISTEN|listen 80;\n        listen [::]:80;|' /etc/angie/angie.conf
else
  sed -i '/# MARKER_ACME_HTTP_LISTEN/d' /etc/angie/angie.conf
fi

exec "$@"
