#!/usr/bin/env bash
#
# Put back the install that update.sh moved aside.
#
# The application and the database are separate decisions, and this is
# deliberate. Swapping the application back is always safe. Restoring the
# database is not always WANTED - if the new version applied no migration,
# the current database is fine and holds everything collected since the
# update, which restoring would throw away.
#
# Usage:
#   sudo ./rollback.sh 20260918-120000            application only
#   sudo ./rollback.sh 20260918-120000 --database  and the database

set -euo pipefail

ROOT="${DMARC_ROOT:-/opt/dmarc}"
SERVICE="${DMARC_SERVICE:-dmarc-web}"
USER_NAME="${DMARC_USER:-dmarc}"

# The stamp is the first thing that is not a flag, and --database may be on
# either side of it: "rollback.sh --database <stamp>" is the order a person
# types about as often as the other one, and reading position 1 as the stamp
# makes that one fail with "no install kept at app---database".
STAMP=""
RESTORE_DB=false
for arg in "$@"; do
    case "$arg" in
        --database) RESTORE_DB=true ;;
        -*) echo "unknown option: ${arg}" >&2; echo "usage: $0 <stamp> [--database]" >&2; exit 64 ;;
        *) [[ -z "$STAMP" ]] && STAMP="$arg" || { echo "give one stamp, not two: ${STAMP} and ${arg}" >&2; exit 64; } ;;
    esac
done

if [[ -z "$STAMP" ]]; then
    echo "usage: $0 <stamp> [--database]" >&2
    echo >&2
    echo "available:" >&2
    ls -1d "${ROOT}"/app-* 2>/dev/null | sed "s|${ROOT}/app-|  |" >&2 || echo "  none" >&2
    exit 64
fi

OLD_APP="${ROOT}/app-${STAMP}"
OLD_DB="${ROOT}/data/dmarc-${STAMP}.db"

[[ -d "$OLD_APP" ]] || { echo "no install kept at ${OLD_APP}" >&2; exit 66; }

if [[ "$RESTORE_DB" == true && ! -f "$OLD_DB" ]]; then
    # Before anything is stopped or moved. Finding this out after the service
    # is down turns a rollback into an outage.
    echo "no database backup at ${OLD_DB}" >&2
    exit 66
fi

echo "Rolling back to ${STAMP}"

NOW="$(date -u +%Y%m%d-%H%M%S)"
MOVED_AWAY=false
DONE=false

# The recovery tool needs its own recovery. Between the two moves below there
# is no ${ROOT}/app at all, and if the second one fails - a full disk, a
# permission, anything - the previous behavior was to exit with the service
# stopped and no application present. That leaves the operator worse off than
# before they ran it, which is the one thing a rollback must never do.
restore() {
    [[ "$MOVED_AWAY" == true && "$DONE" == false ]] || return 0
    echo "The rollback did not complete. Putting back what was running." >&2
    rm -rf "${ROOT}/app"
    mv "${ROOT}/app-rolledback-${NOW}" "${ROOT}/app" 2>/dev/null || true
    systemctl start "$SERVICE" || true
    echo "The service was restarted on the version it was already running." >&2
}
trap restore EXIT

systemctl stop "$SERVICE"

mv "${ROOT}/app" "${ROOT}/app-rolledback-${NOW}"
MOVED_AWAY=true
mv "$OLD_APP" "${ROOT}/app"
chown -R "${USER_NAME}:${USER_NAME}" "${ROOT}/app"

if [[ "$RESTORE_DB" == true ]]; then
    # The current one is kept rather than overwritten: it holds everything
    # collected since the update, and that is not recoverable from anywhere.
    mv "${ROOT}/data/dmarc.db" "${ROOT}/data/dmarc-replaced-${NOW}.db"

    # The write-ahead log and shared-memory file belong to the database that
    # was just moved aside, not to the one being put back. Left behind they sit
    # beside an older database describing transactions it has never seen.
    # SQLite usually removes them on a clean shutdown, so this matters exactly
    # when the last stop was not clean - which is a common reason to be rolling
    # back in the first place.
    for sidecar in wal shm; do
        [[ -f "${ROOT}/data/dmarc.db-${sidecar}" ]] \
            && mv "${ROOT}/data/dmarc.db-${sidecar}" "${ROOT}/data/dmarc-replaced-${NOW}.db-${sidecar}"
    done

    sudo -u "$USER_NAME" cp "$OLD_DB" "${ROOT}/data/dmarc.db"
    echo "  database restored; the one replaced is at ${ROOT}/data/dmarc-replaced-${NOW}.db"
else
    echo "  application only. The database was left as it is - if the version you are"
    echo "  leaving applied a schema change, re-run with --database."
fi

systemctl start "$SERVICE"
DONE=true

# Started is not the same as running: a version that exits on a schema it does
# not understand leaves systemd reporting a failed unit, and the operator
# needs to hear that here rather than from a customer.
sleep 2
if ! systemctl is-active --quiet "$SERVICE"; then
    echo >&2
    echo "The rollback completed but ${SERVICE} is not running." >&2
    echo "  journalctl -u ${SERVICE} -n 50" >&2
    [[ "$RESTORE_DB" == false ]] \
        && echo "  If the version you left applied a schema change, re-run with --database." >&2
    exit 69
fi

echo "Done. The version rolled back FROM is at ${ROOT}/app-rolledback-${NOW}."
