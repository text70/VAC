# syntax=docker/dockerfile:1
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

# Copy pre-built VAC binaries from host context (staged in docker/build-staging/)
COPY docker/build-staging/libvac_integrity.so ${NATIVE_DIR}/
COPY docker/build-staging/vac-daemon ${NATIVE_DIR}/

# Copy VacIntegrity C# plugin source
COPY vac-plugin/VacIntegrity.cs ${PLUGINS_DIR}/

# Copy entrypoint
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

WORKDIR ${SERVER_DIR}

EXPOSE 28015/udp
EXPOSE 28082/tcp
EXPOSE 28084/tcp

ENTRYPOINT ["/entrypoint.sh"]