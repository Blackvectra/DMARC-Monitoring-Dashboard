#!/usr/bin/env bash
#
# The privileged half of the update button.
#
# The web app runs as an unprivileged account and cannot replace its own
# files. That is deliberate: it holds credentials that rewrite customers' DNS,
# and a web application that can also install software is a far larger thing
# to have compromised. So the app writes down a version it would like, and
# this - started by a systemd path unit watching that file, running as root -
# decides whether to act on it.
#
# What crosses the boundary is a version string and nothing else. This treats
# that string as hostile anyway, because a file on disk is not a promise about
# what wrote it:
#
#   1. It must match a narrow version shape. No slashes, no spaces, nothing
#      that could climb out of a directory or be interpreted rather than
#      compared.
#   2. It must be a release that actually exists on the configured channel,
#      checked against GitHub here rather than trusted from the request. So
#      the worst an attacker who owned the web app could achieve is
#      installing a genuine release of this product.
#   3. A prerelease is refused unless this machine is on the preview channel.
#
# Installed by deploy/install-update-agent.sh. See DEPLOYING.md.

set -euo pipefail

ROOT="${DMARC_ROOT:-/opt/dmarc}"
REPO="${DMARC_REPO:-Blackvectra/DMARC-Monitoring-Dashboard}"
CHANNEL="${DMARC_CHANNEL:-stable}"
USER_NAME="${DMARC_USER:-dmarc}"

SPOOL="${ROOT}/data/updates"
REQUEST="${SPOOL}/requested.json"
STATUS="${SPOOL}/status.json"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Written as the app's user so the app can read it back; it only ever reads.
say() {
    local state="$1" version="$2" message="$3" stamp="${4:-}"
    local tmp="${STATUS}.tmp"

    cat > "$tmp" <<JSON
{
  "State": "${state}",
  "Version": "${version}",
  "Message": $(printf '%s' "$message" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))'),
  "At": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "Stamp": "${stamp}"
}
JSON
    chown "${USER_NAME}:${USER_NAME}" "$tmp"
    mv "$tmp" "$STATUS"
}

[[ -f "$REQUEST" ]] || exit 0

# Taken first, so a request cannot be processed twice if anything retriggers.
WORK="$(mktemp)"
mv "$REQUEST" "$WORK"
trap 'rm -f "$WORK"' EXIT

VERSION="$(python3 -c '
import json, sys
with open(sys.argv[1]) as f:
    print(json.load(f).get("Version", ""))
' "$WORK")"

BY="$(python3 -c '
import json, sys
with open(sys.argv[1]) as f:
    print(json.load(f).get("RequestedBy", "unknown"))
' "$WORK")"

# ---- 1. shape ---------------------------------------------------------------
if ! [[ "$VERSION" =~ ^v[0-9]{1,4}(\.[0-9]{1,4}){1,3}(-[A-Za-z0-9.]{1,32})?$ ]]; then
    say Failed "$VERSION" "Refused: '${VERSION}' is not a version number. Nothing was installed."
    exit 1
fi

say Running "$VERSION" "Checking that ${VERSION} is a published release."

# ---- 2. is it real? ---------------------------------------------------------
auth=()
[[ -n "${GITHUB_TOKEN:-}" ]] && auth=(--header "Authorization: Bearer ${GITHUB_TOKEN}")

release="$(curl -fsSL "${auth[@]}" -H "Accept: application/vnd.github+json" \
    "https://api.github.com/repos/${REPO}/releases/tags/${VERSION}" 2>/dev/null || true)"

if [[ -z "$release" ]]; then
    say Failed "$VERSION" "Refused: ${VERSION} is not a published release of ${REPO}. Nothing was installed."
    exit 1
fi

# ---- 3. prerelease only on the preview channel ------------------------------
prerelease="$(printf '%s' "$release" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("prerelease", False))')"
if [[ "$prerelease" == "True" && "$CHANNEL" != "preview" ]]; then
    say Failed "$VERSION" \
        "Refused: ${VERSION} is a prerelease and this machine is on the ${CHANNEL} channel. Nothing was installed."
    exit 1
fi

# ---- do it ------------------------------------------------------------------
say Running "$VERSION" "Installing ${VERSION}, asked for by ${BY}. The service will restart."

log="${SPOOL}/last-update.log"
if DMARC_ROOT="$ROOT" DMARC_REPO="$REPO" DMARC_USER="$USER_NAME" \
   "${HERE}/update.sh" "$VERSION" > "$log" 2>&1; then
    stamp="$(grep -oP 'app-\K[0-9]{8}-[0-9]{6}' "$log" | head -1 || true)"
    say Succeeded "$VERSION" "Updated to ${VERSION}. The previous install was kept, for rolling back." "$stamp"
else
    # update.sh puts the old application back itself before failing, so the
    # service is already running again by the time this is written.
    say Failed "$VERSION" \
        "Installing ${VERSION} failed and the previous version was put back. See ${log}."
    exit 1
fi
