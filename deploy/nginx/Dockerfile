# Cobe News – the proxy image (ghcr.io/g0urmetd/cobe-news-proxy, locally cobe-news-proxy:latest): nginx as published,
# plus the configuration of Cobe News – exactly the files docker-compose.yml mounted up to 0.1.48: the template (filled
# in by nginx's own 20-envsubst-on-templates.sh into /etc/nginx/conf.d), the names (16-server-names.envsh, sourced
# before it) and the certificate watch (40-cert-watch.sh). nginx's own entrypoint scripts stay as they are. Build
# context: this folder only (.dockerignore – never deploy/certs). docs/BETRIEB.md: HTTPS.
# base image pinned by digest (the tag for the reader; update with the others – docs/BETRIEB.md: Entwicklung, Basis-Images)
FROM nginx:1.30-alpine@sha256:0e52bd054126cdc040b1276c0af347aeb02a41b9cfe305d6094767ac30e97949
# nginx's entrypoint sources/runs only executable files there
COPY --chmod=0755 16-server-names.envsh 40-cert-watch.sh /docker-entrypoint.d/
# without --chmod: it would also be the mode of the new folder /etc/nginx/templates (0644: closed); the file is 0644 in Git
COPY cobe-news.conf.template /etc/nginx/templates/default.conf.template
