# syntax=docker/dockerfile:1.7
###############################################################################
# Lacuna container image
#
# Multi-stage build:
#   1. base  — system packages
#   2. tools — OSS security tools (semgrep, trivy, gitleaks, osv-scanner)
#   3. final — Lacuna + Claude Code + tools, slimmed
###############################################################################

FROM node:20-bookworm-slim AS base

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        git \
        jq \
        build-essential \
        pkg-config \
        python3 \
        python3-dev \
        python3-pip \
        python3-venv \
        clang \
        clang-tools \
        llvm \
        libfuzzer-14-dev \
        cmake \
        autoconf \
        automake \
        libtool \
        ninja-build \
        meson \
        gdb \
    && rm -rf /var/lib/apt/lists/*

###############################################################################
FROM base AS tools

# Trivy (deps & IaC scanning)
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
        | sh -s -- -b /usr/local/bin

# osv-scanner (deps)
RUN curl -sSfL -o /usr/local/bin/osv-scanner \
        https://github.com/google/osv-scanner/releases/latest/download/osv-scanner_linux_amd64 \
    && chmod +x /usr/local/bin/osv-scanner

# gitleaks (secrets)
RUN curl -sSfL https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_linux_x64.tar.gz \
        | tar -xz -C /usr/local/bin gitleaks \
    && chmod +x /usr/local/bin/gitleaks

# semgrep (semantic patterns) — install via pip in final stage to share python env

###############################################################################
FROM tools AS final

# Claude Code CLI
RUN npm install -g @anthropic-ai/claude-code

# Java runtime for ysoserial + Chromium runtime deps for Playwright
RUN apt-get update && apt-get install -y --no-install-recommends \
        default-jre-headless \
        # Chromium runtime libraries (Playwright will install the browser itself)
        libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 libcups2 \
        libdrm2 libdbus-1-3 libxkbcommon0 libxcomposite1 libxdamage1 \
        libxext6 libxfixes3 libxrandr2 libgbm1 libpango-1.0-0 \
        libcairo2 libasound2 libatspi2.0-0 \
    && rm -rf /var/lib/apt/lists/*

# ysoserial.jar — Java deserialization gadget generator (deep oracle).
# Downloaded once at build time so runtime can wrap it via subprocess.
RUN curl -sSfL -o /opt/ysoserial-all.jar \
        https://github.com/frohoff/ysoserial/releases/download/v0.0.6/ysoserial-all.jar \
    || echo "ysoserial download failed at build; install at runtime if needed"

# Lacuna python package
WORKDIR /opt/lacuna
COPY pyproject.toml ./
COPY src/ ./src/
RUN pip3 install --no-cache-dir --break-system-packages \
        semgrep \
        sqlmap \
        playwright \
        gopherus \
        -e .

# Install Chromium for Playwright (deep DAST). Headed browsers catch
# DOM-XSS / postMessage / DOM clobbering invisible to HTTP-only fuzzing.
RUN python3 -m playwright install --with-deps chromium \
    || echo "playwright browser install failed at build; will retry at runtime"

# Claude Code config (the .claude/ directory is what makes the agent "Lacuna")
COPY .claude/ /opt/lacuna/.claude/

# Bitbucket pipe entrypoint
COPY bitbucket-pipe/pipe.sh /opt/lacuna/pipe.sh
RUN chmod +x /opt/lacuna/pipe.sh

# Lacuna's runtime state (ephemeral, fresh per scan)
RUN mkdir -p /state /workspace /reports /state/fuzz /state/sanitizer-builds

ENV LACUNA_KG_PATH=/state/lacuna.db \
    LACUNA_EVIDENCE_DIR=/state/evidence \
    LACUNA_TOOL_CACHE_DIR=/state/tool_results \
    LACUNA_CLAUDE_HOME=/opt/lacuna/.claude \
    LACUNA_MODE=sast \
    LACUNA_MANIFEST=app.lacuna.yaml \
    LACUNA_FAIL_ON=critical \
    LACUNA_MODEL_OPUS=claude-opus-4-7 \
    LACUNA_MODEL_SONNET=claude-sonnet-4-6 \
    LACUNA_MODEL_HAIKU=claude-haiku-4-5 \
    LACUNA_WALL_CLOCK_HOURS=4 \
    LACUNA_BUDGET_USD=50 \
    LACUNA_MAX_PARALLEL_SUBAGENTS=8 \
    LACUNA_FUZZ_BUDGET_MINUTES=60 \
    LACUNA_FUZZ_WORKSPACE=/state/fuzz \
    LACUNA_SANITIZER_BUILD_DIR=/state/sanitizer-builds \
    LACUNA_SYMEX_TIMEOUT_S=60 \
    CC=clang \
    CXX=clang++ \
    YSOSERIAL_JAR=/opt/ysoserial-all.jar \
    GOPHERUS_BIN=gopherus

WORKDIR /workspace
ENTRYPOINT ["/opt/lacuna/pipe.sh"]
