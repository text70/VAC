# syntax=docker/dockerfile:1
#------------------------------------------------------------------------------
# Builder stage: Build VAC binaries inside the container for compatibility
#------------------------------------------------------------------------------
FROM docker.io/ubuntu:22.04 AS builder

RUN apt-get update && apt-get install -y \
    build-essential \
    pkg-config \
    libssl-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Rust via rustup (matches runtime GLIBC 2.35)
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /usr/src/VAC
COPY . .
RUN cargo fetch

# Build the necessary components
RUN cargo build --release -p vac-integrity -p vac-daemon

#------------------------------------------------------------------------------
# Server stage: Install RustDedicated + Carbon
#------------------------------------------------------------------------------
FROM docker.io/steamcmd/steamcmd:ubuntu-22 AS server

ENV DEBIAN_FRONTEND=noninteractive
ENV SERVER_DIR=/server
ENV CARBON_VERSION=production_build

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    wget \
    xz-utils \
    lib32gcc-s1 \
    lib32stdc++6 \
    && rm -rf /var/lib/apt/lists/*

# Install RustDedicated server
RUN mkdir -p ${SERVER_DIR} && \
    steamcmd +force_install_dir ${SERVER_DIR} \
    +login anonymous \
    +app_update 258550 validate \
    +quit

# Install Carbon mod
RUN CARBON_URL="https://github.com/CarbonCommunity/Carbon/releases/download/${CARBON_VERSION}/Carbon.Linux.Release.tar.gz" && \
    wget -qO /tmp/carbon.tar.gz "${CARBON_URL}" && \
    tar -xzf /tmp/carbon.tar.gz -C ${SERVER_DIR} && \
    rm /tmp/carbon.tar.gz

#------------------------------------------------------------------------------
# Runtime stage: Combine everything
#------------------------------------------------------------------------------
FROM docker.io/steamcmd/steamcmd:ubuntu-22

ENV DEBIAN_FRONTEND=noninteractive
ENV SERVER_DIR=/server
ENV CARBON_HOME=${SERVER_DIR}/carbon
ENV NATIVE_DIR=${CARBON_HOME}/native
ENV PLUGINS_DIR=${CARBON_HOME}/plugins

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    lib32gcc-s1 \
    lib32stdc++6 \
    && rm -rf /var/lib/apt/lists/*

# Copy RustDedicated + Carbon from server stage
COPY --from=server ${SERVER_DIR} ${SERVER_DIR}

# Copy VAC binaries from builder stage
COPY --from=builder /usr/src/VAC/target/release/libvac_integrity.so ${NATIVE_DIR}/
COPY --from=builder /usr/src/VAC/target/release/vac-daemon ${NATIVE_DIR}/

# Copy VacIntegrity C# plugin source
COPY vac-plugin/VacIntegrity.cs ${PLUGINS_DIR}/

# Copy entrypoint
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

WORKDIR ${SERVER_DIR}

EXPOSE 28015/udp  # Game port (client connections)
EXPOSE 28082/tcp  # Query / RCON port
EXPOSE 28084/tcp  # VAC daemon listener (client scan results)

ENTRYPOINT ["/entrypoint.sh"]
