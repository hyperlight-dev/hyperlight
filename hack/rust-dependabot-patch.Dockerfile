FROM dependabot/dependabot-script
RUN rustup toolchain install 1.85 && rustup default 1.85
