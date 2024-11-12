## Dockerfile for devcontainer

FROM mcr.microsoft.com/devcontainers/base:debian AS base

ARG USER
ARG GROUP
ARG RUST_TOOLCHAIN

ENV HOME="/home/${USER}"
ENV PATH="$HOME/.cargo/bin:$PATH"

# Install dependencies
RUN apt-get update \
    && apt-get -y install \
        build-essential \
        cmake \
        curl \
        git \
        gnupg \
        lsb-release \
        make \
        software-properties-common \
        sudo \
        wget

# Install llvm
RUN wget https://apt.llvm.org/llvm.sh \
    && chmod +x ./llvm.sh         \
    && sudo ./llvm.sh 17 all      \
    && sudo ln -s /usr/lib/llvm-17/bin/clang-cl /usr/bin/clang-cl \
    && sudo ln -s /usr/lib/llvm-17/bin/llvm-lib /usr/bin/llvm-lib \
    && sudo ln -s /usr/lib/llvm-17/bin/lld-link /usr/bin/lld-link \
    && sudo ln -s /usr/lib/llvm-17/bin/llvm-ml /usr/bin/llvm-ml   \
    && sudo ln -s /usr/lib/llvm-17/bin/ld.lld /usr/bin/ld.lld     \
    && sudo ln -s /usr/lib/llvm-17/bin/clang /usr/bin/clang

FROM base AS dev

# Make sure the devcontainer user has sudo access
RUN chown -R "${USER}:$GROUP" /home/${USER} \
    && echo "${USER} ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# Persist bash hystory
RUN SNIPPET="export PROMPT_COMMAND='history -a' && export HISTFILE=/commandhistory/.bash_history" \
    && mkdir /commandhistory \
    && touch /commandhistory/.bash_history \
    && chown -R $USER /commandhistory \
    && echo "$SNIPPET" >> "/home/$USER/.bashrc"

USER $USER

# Install rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y \
    && rustup default $RUST_TOOLCHAIN \
    && rustup target add x86_64-unknown-linux-gnu \
    && rustup target add x86_64-unknown-none      \
    && rustup target add x86_64-pc-windows-msvc   \
    && cargo install just

