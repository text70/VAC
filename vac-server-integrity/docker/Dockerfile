# syntax=docker/dockerfile:1
#------------------------------------------------------------------------------
# Builder stage: compile VAC Rust binaries on glibc 2.31 (Debian bullseye) so
# they run on the runtime image's glibc 2.35 (ubuntu-22).  Host-built binaries
# are NOT used — they carry newer glibc symbols and crash the container.
#------------------------------------------------------------------------------
FROM docker.io/rust:1-bullseye AS builder

WORKDIR /build

COPY Cargo.toml Cargo.lock ./
COPY vac-core/ vac-core/
COPY vac-sys/ vac-sys/
COPY vac-crypto/ vac-crypto/
COPY vac-module-systeminfo/ vac-module-systeminfo/
COPY vac-module-processhandle/ vac-module-processhandle/
COPY vac-module-processmonitor/ vac-module-processmonitor/
COPY vac-module-deviceinfo/ vac-module-deviceinfo/
COPY vac-module-driverinfo/ vac-module-driverinfo/
COPY vac-module-readmodules/ vac-module-readmodules/
COPY vac-host/ vac-host/
COPY vac-client-core/ vac-client-core/
COPY vac-client-linux/ vac-client-linux/
COPY vac-client-win/ vac-client-win/
COPY vac-daemon/ vac-daemon/
COPY vac-daemon-win/ vac-daemon-win/
COPY tools/ tools/
COPY test-harness/ test-harness/

RUN cargo build --release -p vac-integrity -p vac-daemon -p gen-keys

#------------------------------------------------------------------------------
# Server stage: Install RustDedicated + Carbon (pre-built VAC binaries)
#------------------------------------------------------------------------------
FROM docker.io/steamcmd/steamcmd:ubuntu-22 AS server

ENV DEBIAN_FRONTEND=noninteractive
ENV SERVER_DIR=/server

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

# Clean steamcmd cache (~500MB)
RUN rm -rf /root/.local/share/Steam/steamcmd/linux32 /root/Steam/logs

# Install Carbon mod
ENV CARBON_VERSION=production_build
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

# Copy VAC binaries built in the builder stage (glibc-2.31 compatible)
COPY --from=builder /build/target/release/libvac_integrity.so ${NATIVE_DIR}/
COPY --from=builder /build/target/release/vac-daemon ${NATIVE_DIR}/
COPY --from=builder /build/target/release/gen-keys /usr/local/bin/gen-keys

# Copy VacIntegrity C# plugin source (compiled at runtime by Carbon)
COPY vac-plugin/VacIntegrity.cs ${PLUGINS_DIR}/

# Copy entrypoint
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

WORKDIR ${SERVER_DIR}

EXPOSE 28015/udp
EXPOSE 28082/tcp
EXPOSE 28084/tcp
EXPOSE 28085/tcp

ENTRYPOINT ["/entrypoint.sh"]
