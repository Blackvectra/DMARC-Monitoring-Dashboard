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
# The database is the organization's dmarc.db and the folder of client files
# beside it, dmarc-clients/ (see docs/CLIENT-FILES.md). They are restored
# together or not at all: an organization's database from one day with client
# files from another disagrees about who owns what.
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

DATA="${ROOT}/data"
OLD_APP="${ROOT}/app-${STAMP}"
OLD_DB="${DATA}/dmarc-${STAMP}.db"

# Where update.sh put the copy of every client's file taken with that database.
# A backup from before each client had a file of its own has none, and needs
# none: that database still holds every client's reports itself.
OLD_CLIENTS="${DATA}/dmarc-${STAMP}-clients"

[[ -d "$OLD_APP" ]] || { echo "no install kept at ${OLD_APP}" >&2; exit 66; }

if [[ "$RESTORE_DB" == true && ! -f "$OLD_DB" ]]; then
    # Before anything is stopped or moved. Finding this out after the service
    # is down turns a rollback into an outage.
    echo "no database backup at ${OLD_DB}" >&2
    exit 66
fi

echo "Rolling back to ${STAMP}"

NOW="$(date -u +%Y%m%d-%H%M%S)"
REPLACED="${DATA}/dmarc-replaced-${NOW}"
MOVED_AWAY=false
DB_MOVED=false
COPYING_CLIENTS=false
DONE=false

# The recovery tool needs its own recovery. Between the two moves below there
# is no ${ROOT}/app at all, and if the second one fails - a full disk, a
# permission, anything - the previous behavior was to exit with the service
# stopped and no application present. That leaves the operator worse off than
# before they ran it, which is the one thing a rollback must never do.
#
# The same goes for the database. Moved aside and not yet copied back, there
# is no dmarc.db at all, and the application started on that would make a new,
# empty one - a dashboard with no customers, and a restore that looks like it
# lost everything. So the database that was running is put back too. What had
# been copied in over it is only a copy of the backup, which is still where
# it was; it is set aside rather than deleted all the same.
restore() {
    [[ "$MOVED_AWAY" == true && "$DONE" == false ]] || return 0
    echo "The rollback did not complete. Putting back what was running." >&2

    if [[ "$DB_MOVED" == true ]]; then
        if [[ -e "${DATA}/dmarc.db" ]]; then
            mv "${DATA}/dmarc.db" "${DATA}/dmarc-partial-${NOW}.db" 2>/dev/null || true
        fi
        if [[ -d "${DATA}/dmarc-clients" && ( -d "${REPLACED}-clients" || "$COPYING_CLIENTS" == true ) ]]; then
            mv "${DATA}/dmarc-clients" "${DATA}/dmarc-partial-${NOW}-clients" 2>/dev/null || true
        fi
        mv "${REPLACED}.db" "${DATA}/dmarc.db" 2>/dev/null || true
        for sidecar in wal shm; do
            if [[ -f "${REPLACED}.db-${sidecar}" ]]; then
                mv "${REPLACED}.db-${sidecar}" "${DATA}/dmarc.db-${sidecar}" 2>/dev/null || true
            fi
        done
        if [[ -d "${REPLACED}-clients" ]]; then
            mv "${REPLACED}-clients" "${DATA}/dmarc-clients" 2>/dev/null || true
        fi
        echo "The database that was running was put back as it was." >&2
    fi

    # What is at ${ROOT}/app now is the kept install being rolled back to,
    # if it got that far. It goes back where it was kept rather than being
    # deleted, so the rollback can be run again once whatever stopped it is
    # fixed - deleting it threw away the one copy the retry needs.
    if [[ -d "${ROOT}/app" && ! -e "$OLD_APP" ]]; then
        mv "${ROOT}/app" "$OLD_APP" 2>/dev/null || true
    fi
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
    mv "${DATA}/dmarc.db" "${REPLACED}.db"
    DB_MOVED=true

    # The write-ahead log and shared-memory file belong to the database that
    # was just moved aside, not to the one being put back. Left behind they sit
    # beside an older database describing transactions it has never seen.
    # SQLite usually removes them on a clean shutdown, so this matters exactly
    # when the last stop was not clean - which is a common reason to be rolling
    # back in the first place.
    for sidecar in wal shm; do
        [[ -f "${DATA}/dmarc.db-${sidecar}" ]] \
            && mv "${DATA}/dmarc.db-${sidecar}" "${REPLACED}.db-${sidecar}"
    done

    # And every client's file with it. Each file's own journals are inside the
    # folder, so they go with it.
    if [[ -d "${DATA}/dmarc-clients" ]]; then
        mv "${DATA}/dmarc-clients" "${REPLACED}-clients"
    fi

    sudo -u "$USER_NAME" cp "$OLD_DB" "${DATA}/dmarc.db"
    if [[ -d "$OLD_CLIENTS" ]]; then
        COPYING_CLIENTS=true
        sudo -u "$USER_NAME" cp -a "$OLD_CLIENTS" "${DATA}/dmarc-clients"
    fi

    echo "  database restored; the one replaced is at ${REPLACED}.db"
    if [[ -d "${REPLACED}-clients" ]]; then
        echo "  with its client files at ${REPLACED}-clients/"
    fi
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
