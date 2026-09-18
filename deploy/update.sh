#!/usr/bin/env bash
#
# Update a deployed DMARC Monitor to a released version.
#
# The shape this belongs to: development happens on branches and lands on
# main, and none of that reaches this machine. Tagging a version builds the
# artifacts, and this installs one of those tags. Work in progress cannot
# arrive on a box managing customers' DNS because somebody merged something.
#
# What it does, in order, and why that order:
#
#   1. Backs up the database with SQLite's own .backup, not cp. Copying a
#      SQLite file while something has it open produces a file that looks
#      fine and is not.
#   2. Keeps the old application directory rather than overwriting it, so
#      rolling back is a move rather than a download.
#   3. Applies schema migrations AFTER the new binary is in place and BEFORE
#      the service starts, because it is the new build that knows what
#      migrations exist.
#   4. Checks the app actually answers before calling it done, and puts the
#      old one back if it does not.
#
# Usage:
#   sudo ./update.sh v1.3.0                 public repository
#   GITHUB_TOKEN=... sudo -E ./update.sh v1.3.0     private one

set -euo pipefail

REPO="${DMARC_REPO:-Blackvectra/DMARC-Monitoring-Dashboard}"
ROOT="${DMARC_ROOT:-/opt/dmarc}"
SERVICE="${DMARC_SERVICE:-dmarc-web}"
USER_NAME="${DMARC_USER:-dmarc}"
HEALTH_URL="${DMARC_HEALTH_URL:-http://127.0.0.1:5000/}"
ARCH="${DMARC_ARCH:-}"

VERSION="${1:-}"
if [[ -z "$VERSION" ]]; then
    echo "usage: $0 <version>   e.g. $0 v1.3.0" >&2
    exit 64
fi

[[ "$VERSION" == v* ]] || VERSION="v$VERSION"

if [[ -z "$ARCH" ]]; then
    case "$(uname -m)" in
        x86_64)  ARCH=linux-x64   ;;
        aarch64) ARCH=linux-arm64 ;;
        *) echo "unsupported architecture $(uname -m); set DMARC_ARCH" >&2; exit 1 ;;
    esac
fi

STAMP="$(date -u +%Y%m%d-%H%M%S)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

auth=()
[[ -n "${GITHUB_TOKEN:-}" ]] && auth=(--header "Authorization: Bearer ${GITHUB_TOKEN}")

download() {
    local name="$1" into="$2"
    echo "  fetching $name"

    # The API rather than the browser URL, because it is the one that works
    # for a private repository with a token.
    local id
    id=$(curl -fsSL "${auth[@]}" -H "Accept: application/vnd.github+json" \
            "https://api.github.com/repos/${REPO}/releases/tags/${VERSION}" \
        | grep -B 3 "\"name\": \"${name}\"" | grep '"id"' | head -1 | tr -dc '0-9')

    [[ -n "$id" ]] || { echo "  $name is not attached to $VERSION" >&2; return 1; }

    curl -fsSL "${auth[@]}" -H "Accept: application/octet-stream" \
        "https://api.github.com/repos/${REPO}/releases/assets/${id}" -o "$into"
}

echo "Updating ${ROOT} to ${VERSION} (${ARCH})"

# ---- get everything before touching the running install ---------------------
download "dmarc-web.zip"   "$WORK/web.zip"
download "dmarc-${ARCH}"   "$WORK/dmarc"

unzip -q "$WORK/web.zip" -d "$WORK/unpacked"
test -f "$WORK/unpacked/dmarc-web/DmarcMonitor.Web.dll" \
    || { echo "the bundle does not contain the application" >&2; exit 1; }

chmod +x "$WORK/dmarc"

# ---- back up ----------------------------------------------------------------
echo "  backing up the database"
sudo -u "$USER_NAME" sqlite3 "${ROOT}/data/dmarc.db" \
    ".backup '${ROOT}/data/dmarc-${STAMP}.db'"

# ---- swap -------------------------------------------------------------------
echo "  stopping ${SERVICE}"
systemctl stop "$SERVICE"

mv "${ROOT}/app" "${ROOT}/app-${STAMP}"
mv "$WORK/unpacked/dmarc-web" "${ROOT}/app"
chown -R "${USER_NAME}:${USER_NAME}" "${ROOT}/app"

# appsettings.Production.json lives in the app directory and is not part of
# the release, so it has to come across or the new install has no database
# path, no tenant and no sign-in.
if [[ -f "${ROOT}/app-${STAMP}/appsettings.Production.json" ]]; then
    cp -p "${ROOT}/app-${STAMP}/appsettings.Production.json" "${ROOT}/app/"
    echo "  carried appsettings.Production.json across"
fi

cp -p /usr/local/bin/dmarc "${WORK}/dmarc-previous" 2>/dev/null || true
install -m 0755 "$WORK/dmarc" /usr/local/bin/dmarc

# ---- migrate ----------------------------------------------------------------
# After the new binary, before the service: the new build is the one that
# knows which migrations exist.
echo "  applying any schema change"
sudo -u "$USER_NAME" /usr/local/bin/dmarc init-db --db "${ROOT}/data/dmarc.db"

# ---- start and prove it works ----------------------------------------------
echo "  starting ${SERVICE}"
systemctl start "$SERVICE"

ok=false
for _ in $(seq 1 30); do
    sleep 2
    # Any answer at all, including a redirect to sign-in: the app is up and
    # routing. A connection refused is not.
    if curl -fsS -o /dev/null -w '%{http_code}' "$HEALTH_URL" 2>/dev/null | grep -qE '^(2|3|4)'; then
        ok=true
        break
    fi
done

if [[ "$ok" == true ]]; then
    echo
    echo "Updated to ${VERSION}."
    echo "  previous install: ${ROOT}/app-${STAMP}"
    echo "  database backup:  ${ROOT}/data/dmarc-${STAMP}.db"
    echo
    echo "Keep both until you are happy. To roll back:"
    echo "  sudo ./rollback.sh ${STAMP}"
    exit 0
fi

# ---- it did not come back ---------------------------------------------------
echo >&2
echo "The service did not answer after the update. Putting the old one back." >&2

systemctl stop "$SERVICE" || true
rm -rf "${ROOT}/app"
mv "${ROOT}/app-${STAMP}" "${ROOT}/app"
[[ -f "${WORK}/dmarc-previous" ]] && install -m 0755 "${WORK}/dmarc-previous" /usr/local/bin/dmarc
systemctl start "$SERVICE"

echo >&2
echo "Rolled back to the previous application." >&2
echo "The database was NOT rolled back: a migration that ran is still applied." >&2
echo "If the new version had one, restore ${ROOT}/data/dmarc-${STAMP}.db as well:" >&2
echo "  sudo systemctl stop ${SERVICE}" >&2
echo "  sudo -u ${USER_NAME} cp ${ROOT}/data/dmarc-${STAMP}.db ${ROOT}/data/dmarc.db" >&2
echo "  sudo systemctl start ${SERVICE}" >&2
exit 1
