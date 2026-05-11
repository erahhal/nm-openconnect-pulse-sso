#!/usr/bin/env bash
# Install the local CA into the user's browser trust stores.
#
# Required for:
#   1. The user's browser to accept the local TLS cert presented by the
#      MITM proxy (instead of showing "NET::ERR_CERT_AUTHORITY_INVALID").
#   2. Bypassing Chrome's HSTS enforcement for HSTS-pinned domains. Chrome
#      only ignores HSTS pins when the chain terminates in a *locally
#      installed* root — i.e. one that lives in the user's NSS DB, NOT
#      one that's only in the system bundle (/etc/ssl/certs/...).
#
# Run after each nixos-rebuild (or after `pulse-browser-auth-trust uninstall`).
# Idempotent — safe to run repeatedly.
#
# Substituted at build time:
#   @CA_CERT@   — store path of the local CA cert
#   @CERTUTIL@  — path to nss certutil

set -euo pipefail

CA_CERT="@CA_CERT@"
CERTUTIL="@CERTUTIL@"
NICK="Pulse Browser Auth Local CA"

action="${1:-install}"

trust_flags="C,,"   # C = trusted CA for issuing server certs (X.509 SSL)

# --- helpers ---------------------------------------------------------------

info() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
ok()   { printf '  \033[1;32m✓\033[0m %s\n' "$*"; }
warn() { printf '  \033[1;33m!\033[0m %s\n' "$*"; }
err()  { printf '  \033[1;31m✗\033[0m %s\n' "$*" >&2; }

# Add the CA into one NSS DB (sql:<dir>). Removes any prior entry under the
# same nickname first so re-runs after a CA rotation pick up the new key.
install_into() {
    local db="$1"
    "$CERTUTIL" -D -d "sql:$db" -n "$NICK" 2>/dev/null || true
    "$CERTUTIL" -A -d "sql:$db" -t "$trust_flags" -n "$NICK" -i "$CA_CERT"
}

remove_from() {
    local db="$1"
    if "$CERTUTIL" -L -d "sql:$db" -n "$NICK" >/dev/null 2>&1; then
        "$CERTUTIL" -D -d "sql:$db" -n "$NICK"
        ok "removed from $db"
    fi
}

check_in() {
    local db="$1"
    if "$CERTUTIL" -L -d "sql:$db" -n "$NICK" >/dev/null 2>&1; then
        ok "trusted in $db"
    else
        warn "NOT trusted in $db"
    fi
}

# --- discover trust stores -------------------------------------------------

# Chromium-family (Chrome, Chromium, Brave, Vivaldi, Opera, Edge) all share
# this one NSS DB on Linux.
CHROMIUM_DB="$HOME/.pki/nssdb"

# Firefox stores per-profile.
firefox_profiles() {
    shopt -s nullglob
    for p in "$HOME"/.mozilla/firefox/*/; do
        [[ -f "$p/cert9.db" ]] && printf '%s\n' "${p%/}"
    done
    shopt -u nullglob
}

# --- actions ---------------------------------------------------------------

case "$action" in
install)
    info "Installing $NICK"
    info "Source: $CA_CERT"

    mkdir -p "$CHROMIUM_DB"
    if [[ ! -f "$CHROMIUM_DB/cert9.db" ]]; then
        info "Initializing empty NSS DB at $CHROMIUM_DB"
        "$CERTUTIL" -N -d "sql:$CHROMIUM_DB" --empty-password
    fi
    install_into "$CHROMIUM_DB"
    ok "Installed into Chromium-family DB: $CHROMIUM_DB"
    info "  (covers Chrome, Chromium, Brave, Vivaldi, Edge, Opera)"

    profiles=$(firefox_profiles)
    if [[ -n "$profiles" ]]; then
        while IFS= read -r p; do
            install_into "$p"
            ok "Installed into Firefox profile: $p"
        done <<<"$profiles"
    else
        info "(no Firefox profiles found — skipping)"
    fi

    echo
    info "IMPORTANT: fully restart any open browser windows before retrying"
    info "           the VPN auth. Chrome caches NSS trust at process start."
    ;;

uninstall)
    info "Removing $NICK from all browser trust stores"
    [[ -d "$CHROMIUM_DB" ]] && remove_from "$CHROMIUM_DB"
    while IFS= read -r p; do
        remove_from "$p"
    done < <(firefox_profiles)
    ;;

check|status)
    info "Trust status for $NICK"
    if [[ -d "$CHROMIUM_DB" ]]; then
        check_in "$CHROMIUM_DB"
    else
        warn "Chromium-family NSS DB not initialized: $CHROMIUM_DB"
    fi
    while IFS= read -r p; do
        check_in "$p"
    done < <(firefox_profiles)
    ;;

*)
    err "Unknown action: $action"
    echo "Usage: $(basename "$0") {install|uninstall|check}" >&2
    exit 2
    ;;
esac
