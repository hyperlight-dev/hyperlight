FROM ghcr.io/hyperlight-dev/hyperlight-devcontainer:latest

COPY .env /tmp/.env

RUN . /tmp/.env && \
    sudo groupadd -r -g ${DEVICE_GID} -U ${USER} ${DEVICE_GROUP}

