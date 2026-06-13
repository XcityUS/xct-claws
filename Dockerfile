# --- Stage 1: Build web UI ---
FROM node:22-alpine AS web-builder
WORKDIR /src/web
# Pin pnpm: `latest` started pulling v11, which made
# pnpm-workspace.yaml's onlyBuiltDependencies allow-list ineffective
# under --frozen-lockfile (v11 wants an interactive `pnpm approve-builds`
# step that has nowhere to run in a non-TTY Docker build), failing the
# image build with ERR_PNPM_IGNORED_BUILDS on msw/sharp/unrs-resolver.
RUN corepack enable && corepack prepare pnpm@10.15.0 --activate
COPY web/package.json web/pnpm-lock.yaml web/pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile
COPY web/ .
RUN pnpm build

# --- Stage 1b: Build worldseed bundled plugin (Node 22 for util.styleText) ---
# Use debian-slim instead of alpine — some npm package postinstall scripts
# (notably in the openclaw graph) link against glibc and fail under musl
# with exit code 254 inside docker buildkit.
FROM node:22-slim AS worldseed-builder
# git is required because the openclaw dep graph pulls some packages from
# git URLs at install time; without it npm exits with ENOENT spawn git.
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src/worldseed
COPY bundled-plugins/worldseed-channel/package.json bundled-plugins/worldseed-channel/tsconfig.json ./
RUN npm install --no-audit --no-fund --loglevel=error
COPY bundled-plugins/worldseed-channel/index.ts ./
COPY bundled-plugins/worldseed-channel/src ./src
COPY bundled-plugins/worldseed-channel/plugin.json bundled-plugins/worldseed-channel/README.md bundled-plugins/worldseed-channel/SKILL.md ./
# tsc emits dist/ even with type errors (the worldseed plugin has a few
# non-fatal property-access errors against openclaw 2026.3.13 type defs).
RUN node node_modules/typescript/bin/tsc || true
# Drop devDeps (typescript, @types/node) so the final image is smaller.
RUN npm prune --omit=dev --loglevel=error

# --- Stage 2: Build Go binary ---
FROM golang:1.25-alpine AS go-builder
RUN apk add --no-cache git
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Embed the built web UI
COPY --from=web-builder /src/web/out internal/setup/web
ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown
# Stamp BOTH symbol sets — `main.*` for the legacy `fastclaw version` CLI
# consumer and `internal/buildinfo.*` for the agent runtime + the About
# page in the web UI. Mirrors the Makefile / scripts/release.sh ldflags
# so a docker-built image identifies itself the same way the released
# binary does; without the buildinfo line the About page silently shows
# "dev" on every published image (the symptom that triggered this fix).
RUN CGO_ENABLED=0 go build \
    -ldflags "-s -w \
      -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE} \
      -X github.com/fastclaw-ai/fastclaw/internal/buildinfo.Version=${VERSION} \
      -X github.com/fastclaw-ai/fastclaw/internal/buildinfo.Commit=${COMMIT} \
      -X github.com/fastclaw-ai/fastclaw/internal/buildinfo.Date=${DATE}" \
    -o /fastclaw ./cmd/fastclaw

# --- Stage 3: Runtime ---
FROM alpine:3.21
# nodejs is needed by the openclaw-plugin-bridge and any bundled JS plugins
# (e.g. worldseed). util.styleText requires Node >=20, which alpine 3.21 ships.
RUN apk add --no-cache ca-certificates tzdata nodejs
COPY --from=go-builder /fastclaw /usr/local/bin/fastclaw

# OpenClaw plugin bridge (precompiled CJS proxy; routes JSON-RPC <-> OpenClaw plugin)
COPY tools/openclaw-plugin-bridge/proxy.js /opt/fastclaw/openclaw-bridge/proxy.js

# Bundled plugins live at /opt and are copied into FASTCLAW_HOME/plugins by the
# entrypoint on first boot. We avoid placing them directly under FASTCLAW_HOME
# because that path is a volume mount target on production hosts, which would
# shadow files baked into the image.
COPY --from=worldseed-builder /src/worldseed /opt/fastclaw/bundled-plugins/worldseed

COPY scripts/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Default data directory. Override at runtime with FASTCLAW_HOME, but the
# default value here lets `docker run fastclaw/fastclaw` work with no env.
ENV FASTCLAW_HOME=/data/.fastclaw \
    HOME=/data
# No volume directive here: compose/k8s mount the data dir explicitly,
# and Railway's Dockerfile validator rejects it (even in comments).
RUN mkdir -p /data/.fastclaw /data/.fastclaw/skills

# Bundle built-in skills
COPY skills/ /data/.fastclaw/skills/

EXPOSE 18953
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["gateway"]
