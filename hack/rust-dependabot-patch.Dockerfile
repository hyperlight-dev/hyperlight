FROM dependabot/dependabot-script
RUN rustup toolchain install 1.85.0 && rustup default 1.85.0
