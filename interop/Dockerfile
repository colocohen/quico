# ============================================================
#  quico — QUIC Interop Runner endpoint
#  https://github.com/quic-interop/quic-interop-runner
#
#  The base image provides /setup.sh, /wait-for-it.sh, tcpdump and iproute2.
#
#  Build from the REPOSITORY ROOT so that index.js and src/ are in context:
#      docker build -f interop/Dockerfile -t quico-interop .
#
#  Publish (the online runner needs linux/amd64; multi-platform is preferred
#  so others can run the interop locally on arm64 too):
#      docker buildx create --use
#      docker buildx build --pull --push --platform linux/amd64,linux/arm64 \
#        --build-arg QUICO_COMMIT=$(git rev-parse --short HEAD) \
#        -f interop/Dockerfile -t <dockerhub-user>/quico-interop:latest .
# ============================================================

FROM martenseemann/quic-network-simulator-endpoint:latest

# ---- Node.js ----------------------------------------------------------------
# The base image is Ubuntu. Pin a major version so interop results are
# reproducible across rebuilds.
ARG NODE_MAJOR=22
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates curl gnupg && \
    mkdir -p /etc/apt/keyrings && \
    curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key \
      | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg && \
    echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_${NODE_MAJOR}.x nodistro main" \
      > /etc/apt/sources.list.d/nodesource.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends nodejs && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /quico

# ---- Dependencies -----------------------------------------------------------
# package.json alone first: this layer is cached and only rebuilds when the
# dependency set changes, not on every source edit.
COPY package.json ./
RUN npm install --omit=dev --no-audit --no-fund

# Every interop test case uses a generated CA and certificate, so a lemon-tls
# without peer-certificate validation would turn the whole matrix red with a
# confusing TLS error instead of an obvious one. Fail the build loudly rather
# than publish an endpoint that only appears to work.
RUN grep -qr "ALTNAME_INVALID" /quico/node_modules/lemon-tls/src/ \
    || (echo "ERROR: installed lemon-tls does not validate peer certificates" && exit 1)

# ---- Application ------------------------------------------------------------
COPY index.js ./
COPY src/ ./src/
COPY interop/interop.js ./interop.js

# Which commit produced this image. Shown at the top of every run's output,
# which saves a lot of confusion when a published result looks wrong.
ARG QUICO_COMMIT=unknown
RUN echo "$QUICO_COMMIT" > /quico/commit.txt

# ---- Entrypoint -------------------------------------------------------------
COPY interop/run_endpoint.sh /run_endpoint.sh
RUN chmod +x /run_endpoint.sh

# Room for the 10 MB transfers plus reassembly buffers.
ENV NODE_OPTIONS="--max-old-space-size=2048"

# One [bbr] line per round-trip (~30/s) into the logs — cheap, and it turns a
# failed run into a readable congestion-control timeline instead of a guessing
# game. The per-packet QUICO_DEBUG trace stays off: it is heavy enough to
# become the bottleneck it observes (2 MB measured 33s with it, 3s without).
ENV QUICO_DEBUG_BBR=1

ENTRYPOINT [ "/run_endpoint.sh" ]
