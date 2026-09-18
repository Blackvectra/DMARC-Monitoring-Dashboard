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

STAMP="${1:-}"
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

echo "Rolling back to ${STAMP}"
systemctl stop "$SERVICE"

NOW="$(date -u +%Y%m%d-%H%M%S)"
mv "${ROOT}/app" "${ROOT}/app-rolledback-${NOW}"
mv "$OLD_APP" "${ROOT}/app"
chown -R "${USER_NAME}:${USER_NAME}" "${ROOT}/app"

if [[ "${2:-}" == "--database" ]]; then
    [[ -f "$OLD_DB" ]] || { echo "no database backup at ${OLD_DB}" >&2; exit 66; }

    # The current one is kept rather than overwritten: it holds everything
    # collected since the update, and that is not recoverable from anywhere.
    mv "${ROOT}/data/dmarc.db" "${ROOT}/data/dmarc-replaced-${NOW}.db"
    sudo -u "$USER_NAME" cp "$OLD_DB" "${ROOT}/data/dmarc.db"
    echo "  database restored; the one replaced is at ${ROOT}/data/dmarc-replaced-${NOW}.db"
else
    echo "  application only. The database was left as it is - if the version you are"
    echo "  leaving applied a schema change, re-run with --database."
fi

systemctl start "$SERVICE"
echo "Done. The version rolled back FROM is at ${ROOT}/app-rolledback-${NOW}."
