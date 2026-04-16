# syntax=docker/dockerfile:1

FROM rust:1.85-bookworm AS build-base
ARG ENDPOINT_DIR_NAME="TrustTunnel"
WORKDIR /home/${ENDPOINT_DIR_NAME}

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    clang \
    libclang-dev \
    pkg-config \
    perl \
    make \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock rust-toolchain.toml Makefile ./
COPY deeplink ./deeplink
COPY endpoint ./endpoint
COPY lib ./lib
COPY macros ./macros
COPY tools ./tools

FROM build-base AS build-endpoint
RUN cargo build --release --bin trusttunnel_endpoint --bin setup_wizard

FROM rust:1.85-bookworm AS build-classic-agent
ARG ENDPOINT_DIR_NAME="TrustTunnel"
WORKDIR /home/${ENDPOINT_DIR_NAME}

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    clang \
    libclang-dev \
    pkg-config \
    perl \
    make \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock rust-toolchain.toml Makefile ./
COPY deeplink ./deeplink
COPY endpoint ./endpoint
COPY lib ./lib
COPY macros ./macros
COPY tools ./tools

RUN cargo build --release --bin classic_agent

FROM debian:bookworm-slim AS trusttunnel-endpoint
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build-endpoint /home/TrustTunnel/target/release/setup_wizard /usr/local/bin/
COPY --from=build-endpoint /home/TrustTunnel/target/release/trusttunnel_endpoint /usr/local/bin/
RUN ln -s /usr/local/bin/trusttunnel_endpoint /usr/local/bin/trusttunnel-endpoint \
    && ln -s /usr/local/bin/setup_wizard /bin/setup_wizard \
    && ln -s /usr/local/bin/trusttunnel_endpoint /bin/trusttunnel_endpoint
COPY --chmod=755 docker-entrypoint.sh /scripts/

WORKDIR /trusttunnel_endpoint
VOLUME /trusttunnel_endpoint/
ENTRYPOINT ["/scripts/docker-entrypoint.sh"]

FROM debian:bookworm-slim AS trusttunnel-classic-agent
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build-classic-agent /home/TrustTunnel/target/release/classic_agent /bin/
COPY --from=build-endpoint /home/TrustTunnel/target/release/trusttunnel_endpoint /usr/local/bin/
RUN ln -s /usr/local/bin/trusttunnel_endpoint /bin/trusttunnel_endpoint
WORKDIR /runtime
ENTRYPOINT ["/bin/classic_agent"]
