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

# Every string that goes into the status file is encoded as JSON rather than
# pasted between quotes. The version in particular is UNVALIDATED at the point
# the first refusal is written - that is the whole point of the refusal - and
# pasting it raw let a crafted version close the string and add its own keys:
#
#   Version: v1.0.0", "State": "Succeeded
#
# produced a status file with State twice, and a last-key-wins reader (which
# System.Text.Json is) showed the operator a green "Succeeded" for an update
# that had just been refused. The one component whose job is to report honestly
# across a privilege boundary could be made to lie.
j() { printf '%s' "${1-}" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))'; }

# Written as the app's user so the app can read it back; it only ever reads.
say() {
    local state="$1" version="$2" message="$3" stamp="${4:-}"
    local tmp="${STATUS}.tmp"

    cat > "$tmp" <<JSON
{
  "State": $(j "$state"),
  "Version": $(j "$version"),
  "Message": $(j "$message"),
  "At": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "Stamp": $(j "$stamp")
}
JSON
    chown "${USER_NAME}:${USER_NAME}" "$tmp" 2>/dev/null || true
    mv "$tmp" "$STATUS"
}

[[ -f "$REQUEST" ]] || exit 0

# Taken first, so a request cannot be processed twice if anything retriggers.
WORK="$(mktemp)"
mv "$REQUEST" "$WORK"
trap 'rm -f "$WORK"' EXIT

# A file on disk is not a promise about what wrote it, so reading it has to
# survive anything: empty, truncated, not JSON, JSON that is not an object, a
# Version that is a number or a list. This used to be two bare python
# one-liners, and any of those cases threw a traceback which - under `set -e`,
# and AFTER the request had already been moved aside above - killed the agent
# without ever writing a status. The page was then left saying "Requested,
# waiting for the update service to pick it up" for ever, with nothing left on
# disk that would ever change it.
FIELDS="$(python3 - "$WORK" <<'PY' || true
import json, sys

def clean(value, fallback=""):
    if not isinstance(value, str):
        return fallback
    # Flattened, because these are carried back through a tab-separated line,
    # and truncated so a megabyte of junk cannot become the status message.
    return value.replace("\t", " ").replace("\n", " ").replace("\r", " ")[:200]

try:
    with open(sys.argv[1]) as handle:
        request = json.load(handle)
    if not isinstance(request, dict):
        raise ValueError("not an object")
except Exception:
    print("\t\tunreadable")
    sys.exit(0)

print(clean(request.get("Version")) + "\t" + clean(request.get("RequestedBy"), "unknown") + "\tok")
PY
)"

VERSION="$(printf '%s' "$FIELDS" | cut -f1)"
BY="$(printf '%s' "$FIELDS" | cut -f2)"
READABLE="$(printf '%s' "$FIELDS" | cut -f3)"

if [[ "$READABLE" != "ok" ]]; then
    say Failed "" \
        "The update request could not be read - it is not valid JSON. Nothing was installed. Press Install again."
    exit 1
fi

# ---- 1. shape ---------------------------------------------------------------
if ! [[ "$VERSION" =~ ^v[0-9]{1,4}(\.[0-9]{1,4}){1,3}(-[A-Za-z0-9.]{1,32})?$ ]]; then
    say Failed "$VERSION" "Refused: '${VERSION}' is not a version number. Nothing was installed."
    exit 1
fi

say Running "$VERSION" "Checking that ${VERSION} is a published release."

# ---- 2. is it real? ---------------------------------------------------------
auth=()
[[ -n "${GITHUB_TOKEN:-}" ]] && auth=(--header "Authorization: Bearer ${GITHUB_TOKEN}")

# The status code is kept, not just the body. "GitHub says there is no such
# release" and "this server could not reach GitHub" are different answers, and
# the old code turned both into the first one: with the network down, a
# perfectly real release was reported as "not a published release", sending
# whoever read it to look for a tag that was there all along. This product
# refuses to report a failed DNS lookup as an absent record; the same honesty
# is owed here.
answer="$(curl -sSL -w $'\n%{http_code}' "${auth[@]}" -H "Accept: application/vnd.github+json" \
    "https://api.github.com/repos/${REPO}/releases/tags/${VERSION}" 2>/dev/null || true)"

code="$(printf '%s' "$answer" | tail -n 1)"
release="$(printf '%s' "$answer" | sed '$d')"

case "$code" in
    200)
        ;;
    404)
        say Failed "$VERSION" \
            "Refused: ${VERSION} is not a published release of ${REPO}. Nothing was installed."
        exit 1
        ;;
    401|403)
        say Failed "$VERSION" \
            "Could not check ${VERSION}: GitHub refused the request (HTTP ${code}). If ${REPO} is private, the update agent needs a read-only token in /etc/dmarc-update.env. Nothing was installed."
        exit 1
        ;;
    ""|000)
        say Failed "$VERSION" \
            "Could not check whether ${VERSION} exists: this server could not reach GitHub. That is a network problem on this machine, not a missing release. Nothing was installed."
        exit 1
        ;;
    *)
        say Failed "$VERSION" \
            "Could not check whether ${VERSION} exists: GitHub answered HTTP ${code}. Nothing was installed."
        exit 1
        ;;
esac

# ---- 3. prerelease only on the preview channel ------------------------------
# Guarded: a 200 with a body that is not the JSON expected must not kill the
# agent and leave the page waiting for ever.
prerelease="$(printf '%s' "$release" | python3 -c \
    'import json,sys
try:
    print(json.load(sys.stdin).get("prerelease", False))
except Exception:
    print("unknown")' || true)"

if [[ "$prerelease" == "unknown" ]]; then
    say Failed "$VERSION" \
        "Could not check whether ${VERSION} exists: GitHub answered with something this could not read. Nothing was installed."
    exit 1
fi

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
