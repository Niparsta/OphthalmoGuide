FROM node:20-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN if [ -f package-lock.json ]; then npm ci; else npm install; fi
COPY . .
ARG VITE_AUTHENTIK_CLIENT_ID
ARG VITE_AUTHENTIK_ENABLED
ENV VITE_AUTHENTIK_CLIENT_ID=$VITE_AUTHENTIK_CLIENT_ID
ENV VITE_AUTHENTIK_ENABLED=$VITE_AUTHENTIK_ENABLED
RUN npm run build

# Официальный образ: angie:latest / angie:minimal (тега :alpine нет).
# Собираем на alpine:3.22 + пакет angie из репозитория Angie — как в документации.
FROM alpine:3.22

RUN set -eux \
    && apk add --no-cache ca-certificates curl openssl \
    && curl -fsSL -o /etc/apk/keys/angie-signing.rsa https://angie.software/keys/angie-signing.rsa \
    && echo "https://download.angie.software/angie/alpine/v$(grep -oE '^[0-9]+\.[0-9]+' /etc/alpine-release)/main" >> /etc/apk/repositories \
    && apk add --no-cache angie \
    && rm -f /etc/apk/keys/angie-signing.rsa \
    && ln -sf /dev/stdout /var/log/angie/access.log \
    && ln -sf /dev/stderr /var/log/angie/error.log

RUN rm -rf /usr/share/angie/html/*
COPY --from=build /app/dist /usr/share/angie/html
COPY angie/angie.conf.template /etc/angie/angie.conf.template
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN sed -i 's/\r$//' /docker-entrypoint.sh \
    && chmod +x /docker-entrypoint.sh \
    && mkdir -p /etc/angie/conf.d /var/lib/angie/certs /var/lib/angie/acme /run/angie

EXPOSE 80 443
ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["angie", "-g", "daemon off;"]
