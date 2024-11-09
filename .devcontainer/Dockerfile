## Dockerfile for devcontainer

FROM mcr.microsoft.com/devcontainers/base:debian AS base

ARG USERNAME
ARG HYPERVISOR

ENV HOME="/home/${USERNAME}"
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
        net-tools \
        software-properties-common \
        sudo \
        tree \
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

# Create HYPERVISOR user/group so we can assign the vscode user to the group and
# use the device when it needs
RUN groupadd $HYPERVISOR \
    && useradd -r -g $HYPERVISOR $HYPERVISOR \
    && usermod -a -G $HYPERVISOR $USERNAME

# Make sure the devcontainer user has sudo access
RUN group_id=$(id -g) \
    ; group_name=$(getent group ${group_id} | cut -d: -f1) \
    && chown -R "${USERNAME}:$group_name" /home/${USERNAME} \
    && echo "${USERNAME} ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# Persist bash hystory
RUN SNIPPET="export PROMPT_COMMAND='history -a' && export HISTFILE=/commandhistory/.bash_history" \
    && mkdir /commandhistory \
    && touch /commandhistory/.bash_history \
    && chown -R $USERNAME /commandhistory \
    && echo "$SNIPPET" >> "/home/$USERNAME/.bashrc"

USER $USERNAME

# Install rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y \
    && cargo install just

