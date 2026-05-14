#!/usr/bin/env bash
###############################################################################
# Lacuna entrypoint. Detects whether running as a Bitbucket Pipe or ad-hoc and
# dispatches accordingly.
###############################################################################

set -euo pipefail

# Read the canonical version straight out of the Python package so the script
# never drifts from src/lacuna/__init__.py. ``python3`` must be on PATH; the
# Lacuna Dockerfile guarantees that.
LACUNA_VERSION="$(python3 -c 'from lacuna import __version__; print(__version__)' 2>/dev/null || echo 'unknown')"
LACUNA_HOME="${LACUNA_HOME:-/opt/lacuna}"
LACUNA_CLAUDE_HOME="${LACUNA_CLAUDE_HOME:-/opt/lacuna/.claude}"
LACUNA_STATE_DIR="${LACUNA_STATE_DIR:-/state}"
LACUNA_REPORTS_DIR="${LACUNA_REPORTS_DIR:-/reports}"
LACUNA_WORKSPACE="${LACUNA_WORKSPACE:-/workspace}"

# Default Foundry deployment names — override via env
export LACUNA_MODEL_OPUS="${LACUNA_MODEL_OPUS:-claude-opus-4-7}"
export LACUNA_MODEL_SONNET="${LACUNA_MODEL_SONNET:-claude-sonnet-4-6}"
export LACUNA_MODEL_HAIKU="${LACUNA_MODEL_HAIKU:-claude-haiku-4-5}"

# ASCII rule for log readability
rule() { printf "%80s\n" | tr ' ' '─'; }

log() {
  printf "[lacuna %s] %s\n" "$(date -u +%H:%M:%S)" "$*"
}

die() {
  log "FATAL: $*" >&2
  exit 2
}

###############################################################################
# Pre-flight
###############################################################################

rule
log "Lacuna ${LACUNA_VERSION} starting"
log "Mode: ${LACUNA_MODE:-sast}"
log "Manifest: ${LACUNA_MANIFEST:-app.lacuna.yaml}"
rule

# Foundry auth — accept key or AAD token
if [[ -z "${AZURE_FOUNDRY_ENDPOINT:-}" ]]; then
  die "AZURE_FOUNDRY_ENDPOINT is required."
fi
if [[ -z "${AZURE_FOUNDRY_KEY:-}" && -z "${AZURE_FOUNDRY_AAD_TOKEN:-}" ]]; then
  die "One of AZURE_FOUNDRY_KEY or AZURE_FOUNDRY_AAD_TOKEN is required."
fi

# Wire Claude Code to Foundry via Anthropic-compatible env
export ANTHROPIC_BASE_URL="${AZURE_FOUNDRY_ENDPOINT}"
if [[ -n "${AZURE_FOUNDRY_AAD_TOKEN:-}" ]]; then
  export ANTHROPIC_AUTH_TOKEN="${AZURE_FOUNDRY_AAD_TOKEN}"
  log "Auth: Entra/AAD bearer token"
else
  export ANTHROPIC_API_KEY="${AZURE_FOUNDRY_KEY}"
  log "Auth: API key"
fi
export ANTHROPIC_MODEL="${LACUNA_MODEL_OPUS}"
export ANTHROPIC_SMALL_FAST_MODEL="${LACUNA_MODEL_HAIKU}"

# Detect Bitbucket Pipe vs ad-hoc
if [[ -n "${BITBUCKET_BUILD_NUMBER:-}" ]]; then
  log "Detected Bitbucket Pipelines run #${BITBUCKET_BUILD_NUMBER}"
  WORKSPACE_SRC="${BITBUCKET_CLONE_DIR:-${LACUNA_WORKSPACE}}"
else
  log "Ad-hoc invocation"
  WORKSPACE_SRC="${LACUNA_WORKSPACE}"
fi

# Fresh state for ephemeral KG
rm -rf "${LACUNA_STATE_DIR}" || true
mkdir -p "${LACUNA_STATE_DIR}" "${LACUNA_REPORTS_DIR}"
mkdir -p "${LACUNA_STATE_DIR}/evidence" "${LACUNA_STATE_DIR}/tool_results"

export LACUNA_KG_PATH="${LACUNA_STATE_DIR}/lacuna.db"
export LACUNA_EVIDENCE_DIR="${LACUNA_STATE_DIR}/evidence"
export LACUNA_TOOL_CACHE_DIR="${LACUNA_STATE_DIR}/tool_results"
export LACUNA_REPORTS_DIR

###############################################################################
# CLI dispatch
###############################################################################

# Allow `lacuna scan ...` style invocation
if [[ "${1:-scan}" == "scan" ]]; then
  shift || true
  exec python3 -m lacuna scan \
        --manifest "${LACUNA_MANIFEST:-${WORKSPACE_SRC}/app.lacuna.yaml}" \
        --workspace "${WORKSPACE_SRC}" \
        --mode "${LACUNA_MODE:-sast}" \
        --fail-on "${LACUNA_FAIL_ON:-critical}" \
        "$@"
fi

# Fall through to other subcommands
exec python3 -m lacuna "$@"
