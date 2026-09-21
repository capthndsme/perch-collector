# syntax=docker/dockerfile:1

# ---- build: cgo + libpcap + nDPI 5.0 from source -----------------------------
# Debian bookworm ships nDPI 4.2; the daemon targets the 5.0 API, so the
# library is built here (libndpi only, no ndpiReader) and shipped below.
FROM golang:1.23-bookworm AS build
ARG NDPI_VERSION=5.0
# Stamped into the start-up log line, /healthz, the hello and announces.
ARG VERSION=dev
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      libpcap-dev pkg-config git autoconf automake libtool ca-certificates \
 && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 --branch "${NDPI_VERSION}" https://github.com/ntop/nDPI /tmp/ndpi \
 && cd /tmp/ndpi \
 && ./autogen.sh \
 && ./configure --with-only-libndpi --prefix=/usr/local \
 && make -j"$(nproc)" \
 && make install \
 && ldconfig \
 && rm -rf /tmp/ndpi
ENV PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN make build-ndpi BIN=/out/perch-collector LDFLAGS="-s -w -X main.version=${VERSION}"

# ---- runtime -----------------------------------------------------------------
FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends libpcap0.8 ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /usr/local/lib/libndpi.so* /usr/local/lib/
COPY --from=build /out/perch-collector /usr/local/bin/perch-collector
# Fail the build if the binary needs a library the image does not carry.
RUN ldconfig && ! ldd /usr/local/bin/perch-collector | grep 'not found'

# No config file is needed: a missing collector.yaml means built-in defaults,
# and these environment variables turn the defaults into a container-friendly
# nDPI setup. Override any of them with `-e` (see CONFIG.md for the full list).
ENV PERCH_COLLECTOR_LISTEN=0.0.0.0:9800 \
    PERCH_COLLECTOR_CLASSIFICATION_MODE=ndpi \
    PERCH_COLLECTOR_SNAP_LEN=1500

# Run with: --network host --cap-add NET_RAW --cap-add NET_ADMIN
# The capture interface is auto-detected from the default route;
# set PERCH_COLLECTOR_INTERFACE for a bridge or mirror port.
EXPOSE 9800
ENTRYPOINT ["perch-collector"]
