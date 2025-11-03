FROM ubuntu:24.04
RUN \
  apt-get update \
  && apt-get upgrade -y \
  && apt -y install gettext-base libssl-dev wget gnupg curl\
  && apt clean \
  && apt install -y --no-install-recommends ca-certificates \
  && update-ca-certificates \
  && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /etc/apt/keyrings \
  && curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg \
  && chmod a+r /etc/apt/keyrings/docker.gpg
RUN echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  tee /etc/apt/sources.list.d/docker.list > /dev/null
RUN apt-get update \
  && apt-get install -y docker-ce docker-ce-cli containerd.io

# --- ARG & ENV Setup ---
ARG DOCKER_APP_PATH
ARG BITVM_CACHE_PATH
ARG CA_PEM_PATH
ARG SERVER_PEM_PATH
ARG CLIENT_PEM_PATH
ARG AGGREGATOR_PEM_PATH
ARG CLEMENTINE_CORE_PATH
ARG CLEMENTINE_CLI_PATH
ARG PARAM

# Add ARGs for file paths and the key content
ARG CLIENT_KEY_PATH
ARG SERVER_KEY_PATH

ENV PARAM=$PARAM
ENV CLEMENTINE_CORE_PATH=$CLEMENTINE_CORE_PATH
ENV DOCKER_APP_PATH=$DOCKER_APP_PATH

# Set ENV for file paths and the key content
ENV CLIENT_KEY_PATH=$CLIENT_KEY_PATH
ENV SERVER_KEY_PATH=$SERVER_KEY_PATH

WORKDIR $DOCKER_APP_PATH

COPY ${BITVM_CACHE_PATH} .
COPY ${CA_PEM_PATH} .
COPY ${SERVER_PEM_PATH} .
COPY ${CLIENT_PEM_PATH} .
COPY ${AGGREGATOR_PEM_PATH} .
COPY ${CLEMENTINE_CORE_PATH} .
COPY ${CLEMENTINE_CLI_PATH} .

RUN echo "CLEMENTINE_CORE_PATH: $CLEMENTINE_CORE_PATH" \
    && echo "DOCKER_APP_PATH: $DOCKER_APP_PATH" \
    && echo "PARAM: $PARAM"

# --- Entrypoint Setup ---
# Copy the entrypoint script into the container to $DOCKER_APP_PATH
COPY devops/dockers/clementine/entrypoint.sh $DOCKER_APP_PATH/entrypoint.sh
# Make it executable
RUN chmod +x $DOCKER_APP_PATH/entrypoint.sh

# Set the entrypoint to our script
ENTRYPOINT ["/bin/bash", "-c", "$DOCKER_APP_PATH/entrypoint.sh"]
