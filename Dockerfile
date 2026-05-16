# syntax=docker/dockerfile:1.7
###############################################################################
# Lacuna container image
#
# Multi-stage build:
#   1. base       — python:3.11-slim-bookworm + apt build deps
#   2. oss-tools  — downloads trivy, gitleaks, osv-scanner into /usr/local/bin
#   3. final      — base + Node + Lacuna's pip venv; explicitly COPYs the
#                   oss-tools binaries instead of inheriting them, so the
#                   final image's lineage is obvious from the Dockerfile.
#
# Build arguments:
#   ORACLES (default "yes") — when set to "yes", the build installs the
#     heavy deep-oracle dependencies (sqlmap, gopherus, ysoserial.jar,
#     Playwright + chromium runtime libs). Set to "no" if you don't need
#     them; the relevant tools will fail loudly at runtime rather than
#     silently degrading.
###############################################################################

ARG ORACLES=yes

FROM python:3.11-slim-bookworm AS base

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Build tooling for sanitized builds, plus git/curl/etc for cloning and
# tool installation. Node.js is NOT installed here — it's added only in
# the `final` stage for the Claude Code CLI.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        git \
        jq \
        build-essential \
        pkg-config \
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
FROM base AS oss-tools

# Trivy (deps & IaC scanning).
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
        | sh -s -- -b /usr/local/bin

# osv-scanner (deps).
RUN curl -sSfL -o /usr/local/bin/osv-scanner \
        https://github.com/google/osv-scanner/releases/latest/download/osv-scanner_linux_amd64 \
    && chmod +x /usr/local/bin/osv-scanner

# gitleaks (secrets).
RUN curl -sSfL https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_linux_x64.tar.gz \
        | tar -xz -C /usr/local/bin gitleaks \
    && chmod +x /usr/local/bin/gitleaks

###############################################################################
FROM base AS final

ARG ORACLES

# Bring in the binaries built in oss-tools. Explicit COPY --from makes
# the cross-stage dependency obvious; nothing in `final` inherits from
# `oss-tools` implicitly.
COPY --from=oss-tools /usr/local/bin/trivy        /usr/local/bin/trivy
COPY --from=oss-tools /usr/local/bin/osv-scanner  /usr/local/bin/osv-scanner
COPY --from=oss-tools /usr/local/bin/gitleaks     /usr/local/bin/gitleaks

# Node.js (for Claude Code CLI).
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

RUN npm install -g @anthropic-ai/claude-code

# Java runtime for ysoserial + Chromium runtime libs for Playwright.
# Only installed when the deep-oracle build arg is on.
RUN if [ "$ORACLES" = "yes" ]; then \
        apt-get update && apt-get install -y --no-install-recommends \
            default-jre-headless \
            libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 libcups2 \
            libdrm2 libdbus-1-3 libxkbcommon0 libxcomposite1 libxdamage1 \
            libxext6 libxfixes3 libxrandr2 libgbm1 libpango-1.0-0 \
            libcairo2 libasound2 libatspi2.0-0 \
        && rm -rf /var/lib/apt/lists/*; \
    fi

# ysoserial.jar — Java deserialization gadget generator (deep oracle).
# Fail loudly when ORACLES=yes; the validator depends on it being there.
RUN if [ "$ORACLES" = "yes" ]; then \
        curl -fsSL -o /opt/ysoserial-all.jar \
            https://github.com/frohoff/ysoserial/releases/download/v0.0.6/ysoserial-all.jar; \
    fi

# Build the Lacuna Python package inside a dedicated venv. This avoids
# the PEP 668 "externally managed environment" issue on Debian and means
# every `python` invocation resolves to the venv interpreter without us
# having to splice in --break-system-packages.
ENV VIRTUAL_ENV=/opt/venv
RUN python -m venv "$VIRTUAL_ENV"
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

WORKDIR /opt/lacuna
COPY pyproject.toml ./
COPY src/ ./src/

RUN pip install --upgrade pip \
    && pip install -e .

RUN if [ "$ORACLES" = "yes" ]; then \
        pip install semgrep sqlmap playwright gopherus angr; \
    fi

# Install Chromium for Playwright (deep DAST). Fail loud when
# ORACLES=yes — the operator opted into oracles.
RUN if [ "$ORACLES" = "yes" ]; then \
        python -m playwright install --with-deps chromium; \
    fi

# Claude Code config (the .claude/ directory is what makes the agent "Lacuna").
COPY .claude/ /opt/lacuna/.claude/

# Bitbucket pipe entrypoint.
COPY bitbucket-pipe/pipe.sh /opt/lacuna/pipe.sh
RUN chmod +x /opt/lacuna/pipe.sh

# Lacuna's runtime state (ephemeral, fresh per scan).
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
