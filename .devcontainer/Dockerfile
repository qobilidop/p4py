FROM ubuntu:24.04

# Avoid interactive prompts during package installation.
ENV DEBIAN_FRONTEND=noninteractive

# Install system packages.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    curl \
    git \
    python3 \
    shellcheck \
    unzip \
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
RUN useradd -m dev && \
    mkdir -p /home/dev/.cache/bazel && \
    chown -R dev:dev /home/dev

# Trust /workspace for git operations.
RUN git config --system --add safe.directory /workspace

USER dev
ENV PATH="/home/dev/.local/bin:${PATH}"

# Install Python tools via uv.
RUN uv tool install ruff && \
    uv tool install sphinx --with furo --with myst-parser && \
    uv tool install sphinx-autobuild --with furo --with myst-parser
