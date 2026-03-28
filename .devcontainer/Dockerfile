FROM ubuntu:22.04

# Avoid interactive prompts during package installation.
ENV DEBIAN_FRONTEND=noninteractive

# Install system packages.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    git \
    gnupg \
    iproute2 \
    python3 \
    shellcheck \
    software-properties-common \
    sudo \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Add p4lang apt repository.
RUN . /etc/lsb-release && \
    echo "deb http://download.opensuse.org/repositories/home:/p4lang/xUbuntu_${DISTRIB_RELEASE}/ /" \
    | tee /etc/apt/sources.list.d/home:p4lang.list && \
    curl -fsSL "https://download.opensuse.org/repositories/home:p4lang/xUbuntu_${DISTRIB_RELEASE}/Release.key" \
    | gpg --dearmor | tee /etc/apt/trusted.gpg.d/home_p4lang.gpg > /dev/null

# Install P4 tools.
RUN apt-get update && apt-get install -y --no-install-recommends \
    p4lang-p4c \
    p4lang-bmv2 \
    && rm -rf /var/lib/apt/lists/*

# Install Bazelisk as bazel.
ARG TARGETARCH
RUN BAZELISK_ARCH=$([ "$TARGETARCH" = "arm64" ] && echo "arm64" || echo "amd64") && \
    curl -fsSL -o /usr/local/bin/bazel \
    "https://github.com/bazelbuild/bazelisk/releases/download/v1.28.1/bazelisk-linux-${BAZELISK_ARCH}" && \
    chmod +x /usr/local/bin/bazel

# Install buildifier.
RUN BUILDIFIER_ARCH=$([ "$TARGETARCH" = "arm64" ] && echo "arm64" || echo "amd64") && \
    curl -fsSL -o /usr/local/bin/buildifier \
    "https://github.com/bazelbuild/buildtools/releases/download/v8.5.1/buildifier-linux-${BUILDIFIER_ARCH}" && \
    chmod +x /usr/local/bin/buildifier

# Install shfmt.
RUN SHFMT_ARCH=$([ "$TARGETARCH" = "arm64" ] && echo "arm64" || echo "amd64") && \
    curl -fsSL -o /usr/local/bin/shfmt \
    "https://github.com/mvdan/sh/releases/download/v3.13.0/shfmt_v3.13.0_linux_${SHFMT_ARCH}" && \
    chmod +x /usr/local/bin/shfmt

# Install dprint.
RUN DPRINT_ARCH=$([ "$TARGETARCH" = "arm64" ] && echo "aarch64" || echo "x86_64") && \
    curl -fsSL "https://github.com/dprint/dprint/releases/download/0.53.0/dprint-${DPRINT_ARCH}-unknown-linux-gnu.zip" \
    -o /tmp/dprint.zip && \
    unzip -o /tmp/dprint.zip -d /usr/local/bin/ dprint && \
    chmod +x /usr/local/bin/dprint && \
    rm /tmp/dprint.zip

# Install uv (Python package manager).
RUN curl -fsSL https://astral.sh/uv/install.sh | env UV_INSTALL_DIR=/usr/local/bin sh

# Create non-root user. Bazel discourages running as root.
# Grant passwordless sudo for network setup (veth pairs for BMv2 testing).
RUN useradd -m dev && \
    mkdir -p /home/dev/.cache/bazel && \
    chown -R dev:dev /home/dev && \
    echo "dev ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# Trust /workspace for git operations.
RUN git config --system --add safe.directory /workspace

USER dev
ENV PATH="/home/dev/.local/bin:${PATH}"

# Install Python tools via uv.
RUN uv tool install ruff && \
    uv tool install sphinx --with furo --with myst-parser && \
    uv tool install sphinx-autobuild --with furo --with myst-parser
