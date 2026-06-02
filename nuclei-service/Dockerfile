# ── Stage 1: Pull nuclei binary ───────────────────────────────────────────────
FROM projectdiscovery/nuclei:latest AS nuclei-bin

# ── Stage 2: Node.js HTTP wrapper runtime ─────────────────────────────────────
FROM node:20-alpine

ARG NUCLEI_TEMPLATES_DIR=/root/nuclei-templates

# Install system deps
RUN apk add --no-cache curl git ca-certificates

# Copy nuclei binary from official image
COPY --from=nuclei-bin /usr/local/bin/nuclei /usr/local/bin/nuclei

# Create non-root user for running scans
RUN addgroup -g 1002 -S nuclei \
 && adduser  -u 1002 -S nuclei -G nuclei \
 && mkdir -p /home/nuclei/.config/nuclei \
               /home/nuclei/nuclei-templates \
               /tmp/nuclei-output \
 && chown -R nuclei:nuclei /home/nuclei /tmp/nuclei-output

WORKDIR /app

COPY package.json ./
RUN npm install --omit=dev

COPY server.js ./

# Pre-update templates at build time so first scan doesn't block
RUN nuclei -update-templates -ud /home/nuclei/nuclei-templates || true

RUN chown -R nuclei:nuclei /app

USER nuclei

ENV NUCLEI_TEMPLATES_DIR=/home/nuclei/nuclei-templates
ENV PORT=8088

EXPOSE 8088

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
  CMD curl -sf http://localhost:8088/health || exit 1

CMD ["node", "server.js"]
