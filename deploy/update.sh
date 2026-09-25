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
#   1. Backs up the database - the organization's and every client's file -
#      with SQLite's own .backup, not cp. Copying a SQLite file while
#      something has it open produces a file that looks fine and is not.
#   2. Keeps the old application directory rather than overwriting it, so
#      rolling back is a move rather than a download.
#   3. Applies schema migrations AFTER the new binary is in place and BEFORE
#      the service starts, because it is the new build that knows what
#      migrations exist.
#   4. Checks the app actually answers before calling it done, and puts the
#      old one back if it does not - with the database as it was, when the
#      new one changed its schema, because the old application cannot read
#      what the new one migrated it to.
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

# Checked here rather than discovered halfway through. A missing sqlite3 found
# after the application directory has been moved aside is a stopped service and
# a confusing error; found now it is one line and nothing has been touched.
#
# The hint names the package manager this machine actually has. It said apt,
# which on Amazon Linux is advice for a different operating system - and the
# one package called something else there is sqlite3, which is sqlite.
pkg_hint() {
    if command -v dnf >/dev/null 2>&1; then
        echo "sudo dnf install -y $(printf '%s\n' "$@" | sed 's/^sqlite3$/sqlite/' | tr '\n' ' ')"
    elif command -v apt-get >/dev/null 2>&1; then
        echo "sudo apt install -y $*"
    else
        echo "install these with your package manager: $*"
    fi
}

missing=()
for tool in curl unzip sqlite3 python3 systemctl; do
    command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
done
if (( ${#missing[@]} )); then
    echo "missing: ${missing[*]}" >&2
    echo "install them first:  $(pkg_hint "${missing[@]}")" >&2
    exit 69
fi

for path in "${ROOT}/app" "${ROOT}/data/dmarc.db"; do
    [[ -e "$path" ]] || { echo "$path does not exist - is ${ROOT} really the install?" >&2; exit 66; }
done

STAMP="$(date -u +%Y%m%d-%H%M%S)"
WORK="$(mktemp -d)"
DATA="${ROOT}/data"

# ---- putting it back, whatever went wrong -----------------------------------
#
# Everything from the swap onwards can fail: a migration that will not apply, a
# chown that fails, a service that will not start, the disk filling up. Only one
# of those used to be handled - the app not answering afterwards - and because
# this script runs under `set -e`, any of the others exited immediately, several
# lines above the code that puts things back. That left the service STOPPED, the
# new application in place, the old one sitting in app-<stamp>, and nothing on
# its way to fix it. The site stayed down until somebody noticed.
#
# So the restore hangs off the exit trap instead, and covers every path out of
# the script between the swap and the end.
SWAPPED=false
DONE=false
MIGRATING=false
SCHEMA_BEFORE=""

schema_version() {
    sudo -u "$USER_NAME" sqlite3 "${DATA}/dmarc.db" "SELECT COALESCE(MAX(version), '') FROM schema_migrations" 2>/dev/null
}

# The database as it was before this update, back in place. What the new
# version wrote is moved aside beside it, never deleted - the organization's
# database, its journal, and the folder of client files that goes with it.
# Every step is checked: a copy made over a database that did not move aside
# first would destroy it.
put_database_back() {
    local aside="${DATA}/dmarc-replaced-${STAMP}" sidecar
    mv "${DATA}/dmarc.db" "${aside}.db" || return 1
    for sidecar in wal shm; do
        if [[ -f "${DATA}/dmarc.db-${sidecar}" ]]; then
            mv "${DATA}/dmarc.db-${sidecar}" "${aside}.db-${sidecar}" || return 1
        fi
    done
    if [[ -d "${DATA}/dmarc-clients" ]]; then
        mv "${DATA}/dmarc-clients" "${aside}-clients" || return 1
    fi
    sudo -u "$USER_NAME" cp "${DATA}/dmarc-${STAMP}.db" "${DATA}/dmarc.db" || return 1
    if [[ -d "${DATA}/dmarc-${STAMP}-clients" ]]; then
        sudo -u "$USER_NAME" cp -a "${DATA}/dmarc-${STAMP}-clients" "${DATA}/dmarc-clients" || return 1
    fi
}

restore() {
    [[ "$SWAPPED" == true && "$DONE" == false ]] || return 0

    echo >&2
    echo "The update did not complete. Putting the previous application back." >&2

    systemctl stop "$SERVICE" 2>/dev/null || true
    rm -rf "${ROOT}/app"
    mv "${ROOT}/app-${STAMP}" "${ROOT}/app"
    [[ -f "${WORK}/dmarc-previous" ]] && install -m 0755 "${WORK}/dmarc-previous" /usr/local/bin/dmarc

    # The previous application cannot read a schema it has never heard of -
    # and after the upgrade that gives every client a file of its own, it
    # would find no client's reports at all. So a migration that ran is
    # undone by putting back the copy taken before it, not left for somebody
    # to discover from an empty dashboard.
    local now=""
    [[ "$MIGRATING" == true ]] && now="$(schema_version || true)"
    if [[ "$MIGRATING" == true && "$now" != "$SCHEMA_BEFORE" ]]; then
        if put_database_back; then
            echo "The database was at schema ${SCHEMA_BEFORE:-unknown} and the new version moved it to ${now:-an unreadable state}," >&2
            echo "so the copy taken before the update was put back. What the new version wrote is kept at" >&2
            echo "  ${DATA}/dmarc-replaced-${STAMP}.db (and -clients/ beside it, if it made one)." >&2
        else
            echo "The database could NOT be put back automatically. With the service stopped:" >&2
            echo "  move ${DATA}/dmarc.db and ${DATA}/dmarc-clients aside, then" >&2
            echo "  sudo -u ${USER_NAME} cp ${DATA}/dmarc-${STAMP}.db ${DATA}/dmarc.db" >&2
            echo "  sudo -u ${USER_NAME} cp -a ${DATA}/dmarc-${STAMP}-clients ${DATA}/dmarc-clients   (if it exists)" >&2
        fi
    else
        echo "The database was left as it is: the update had not changed its schema." >&2
    fi

    systemctl start "$SERVICE" || true

    echo >&2
    echo "Rolled back to the previous application." >&2
}

trap 'restore; rm -rf "$WORK"' EXIT

auth=()
[[ -n "${GITHUB_TOKEN:-}" ]] && auth=(--header "Authorization: Bearer ${GITHUB_TOKEN}")

download() {
    local name="$1" into="$2"
    echo "  fetching $name"

    # The API rather than the browser URL, because it is the one that works
    # for a private repository with a token.
    local meta id
    meta="$(curl -fsSL "${auth[@]}" -H "Accept: application/vnd.github+json" \
        "https://api.github.com/repos/${REPO}/releases/tags/${VERSION}")" || {
        echo "  could not reach GitHub to look up ${VERSION}." >&2
        echo "  This is a network or credentials problem, not a missing release." >&2
        return 1
    }

    # Parsed properly rather than with grep -B 3. The old version depended on
    # "id" appearing exactly three lines above "name" in GitHub's response
    # formatting: a field order change, or an asset whose surrounding fields
    # happened to contain digits, and it would fetch the wrong asset or none.
    id="$(printf '%s' "$meta" | python3 -c '
import json, sys
want = sys.argv[1]
for asset in json.load(sys.stdin).get("assets", []):
    if asset.get("name") == want:
        print(asset["id"]); break
' "$name")"

    [[ -n "$id" ]] || { echo "  $name is not attached to $VERSION" >&2; return 1; }

    curl -fsSL "${auth[@]}" -H "Accept: application/octet-stream" \
        "https://api.github.com/repos/${REPO}/releases/assets/${id}" -o "$into"
}

echo "Updating ${ROOT} to ${VERSION} (${ARCH})"

# ---- get everything before touching the running install ---------------------
download "dmarc-web.zip"   "$WORK/web.zip"
download "dmarc-${ARCH}"   "$WORK/dmarc"
download "SHA256SUMS.txt"  "$WORK/SHA256SUMS.txt"

# Checked against the sums the release published before anything is unpacked
# or installed. The release has always carried SHA256SUMS.txt and this never
# read it, so the only thing between a tampered asset and a root-run install
# was TLS to api.github.com. A mismatch stops here, with the running install
# untouched. Release files are named, so each is checked under its own name.
verify() {
    local published="$1" local_file="$2" want got
    want="$(awk -v f="$published" '$2 == f || $2 == "*" f { print $1; exit }' "$WORK/SHA256SUMS.txt")"
    [[ -n "$want" ]] || { echo "  $published is not listed in SHA256SUMS.txt; refusing to install it." >&2; return 1; }
    got="$(sha256sum "$local_file" | awk '{ print $1 }')"
    [[ "$want" == "$got" ]] || { echo "  $published does not match its published checksum; refusing to install it." >&2; return 1; }
    echo "  $published checksum ok"
}
verify "dmarc-web.zip"  "$WORK/web.zip"
verify "dmarc-${ARCH}"  "$WORK/dmarc"

unzip -q "$WORK/web.zip" -d "$WORK/unpacked"
test -f "$WORK/unpacked/dmarc-web/DmarcMonitor.Web.dll" \
    || { echo "the bundle does not contain the application" >&2; exit 1; }

chmod +x "$WORK/dmarc"

# ---- the runtime the new build needs ----------------------------------------
# The web bundle is not self-contained, and moving from .NET 8 to .NET 10
# means a release this script fetches may need a runtime the server does not
# have. Swapped in regardless, the service would not start and the rollback
# below would have to undo it; refused here, nothing has been touched yet.
needed="$(python3 - "$WORK/unpacked/dmarc-web/DmarcMonitor.Web.runtimeconfig.json" <<'PY' 2>/dev/null || true
import json, sys
options = json.load(open(sys.argv[1]))["runtimeOptions"]
for framework in options.get("frameworks") or [options.get("framework", {})]:
    if framework.get("name") == "Microsoft.AspNetCore.App":
        print(framework["version"].split(".")[0])
PY
)"
dotnet_bin="$(systemctl cat "$SERVICE" 2>/dev/null | sed -n 's/^ExecStart=\([^ ]*dotnet\) .*/\1/p' | tail -1)"
dotnet_bin="${dotnet_bin:-$(command -v dotnet || true)}"
if [[ -n "$needed" && -n "$dotnet_bin" ]] \
    && ! "$dotnet_bin" --list-runtimes 2>/dev/null | grep -q "^Microsoft.AspNetCore.App ${needed}\."; then
    echo "this release needs the ASP.NET Core ${needed} runtime, and ${dotnet_bin} does not have it." >&2
    echo "install it first - $(pkg_hint "aspnetcore-runtime-${needed}.0"), or re-run bootstrap.sh, which" >&2
    echo "installs Microsoft's copy where the distribution has none - then run this again." >&2
    echo "Nothing has been changed." >&2
    exit 69
fi

# ---- back up ----------------------------------------------------------------
# The organization's database and every client's file beside it (see
# docs/CLIENT-FILES.md). The client files first: the organization's database
# hands out the row ids the files use, so a copy of it taken after them is
# never behind them.
#
# The copy of the folder is named for the copy of the database - dmarc-<stamp>.db
# keeps its clients in dmarc-<stamp>-clients/ - which is where the application
# looks for a database's clients, so the pair opens as it stands.
echo "  backing up the database"
if [[ -d "${DATA}/dmarc-clients" ]]; then
    sudo -u "$USER_NAME" mkdir -m 0700 "${DATA}/dmarc-${STAMP}-clients"
    for file in "${DATA}/dmarc-clients"/*.db; do
        [[ -e "$file" ]] || continue
        sudo -u "$USER_NAME" sqlite3 "$file" ".backup '${DATA}/dmarc-${STAMP}-clients/$(basename "$file")'"
    done
fi
sudo -u "$USER_NAME" sqlite3 "${DATA}/dmarc.db" ".backup '${DATA}/dmarc-${STAMP}.db'"
SCHEMA_BEFORE="$(schema_version || true)"

# ---- swap -------------------------------------------------------------------
echo "  stopping ${SERVICE}"
systemctl stop "$SERVICE"

# From here on there is a previous install set aside that has to be put back if
# anything below fails. The trap above does that; this is what arms it.
mv "${ROOT}/app" "${ROOT}/app-${STAMP}"
SWAPPED=true

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
MIGRATING=true
sudo -u "$USER_NAME" /usr/local/bin/dmarc init-db --db "${DATA}/dmarc.db"

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

if [[ "$ok" != true ]]; then
    # The trap puts the old application back and says so. Nothing to do here
    # but stop, so that there is one restore path rather than two that can
    # drift apart.
    echo >&2
    echo "The service did not answer at ${HEALTH_URL} after the update." >&2
    exit 1
fi

DONE=true

echo
echo "Updated to ${VERSION}."
echo "  previous install: ${ROOT}/app-${STAMP}"
echo "  database backup:  ${DATA}/dmarc-${STAMP}.db"
if [[ -d "${DATA}/dmarc-${STAMP}-clients" ]]; then
    echo "                    ${DATA}/dmarc-${STAMP}-clients/  (every client's file)"
fi
echo
echo "Keep both until you are happy. To roll back:"
echo "  sudo ./rollback.sh ${STAMP}"
exit 0
