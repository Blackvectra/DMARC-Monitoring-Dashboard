#!/usr/bin/env bash
#
# Sets up the Update button: the spool the app writes to, and the privileged
# unit that acts on it.
#
# Run once, as root, on a machine that already has the app installed per
# DEPLOYING.md.

set -euo pipefail

ROOT="${DMARC_ROOT:-/opt/dmarc}"
USER_NAME="${DMARC_USER:-dmarc}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

[[ $EUID -eq 0 ]] || { echo "run this as root" >&2; exit 1; }

echo "Installing the update agent"

# The scripts live where the unit expects them, owned by root: the app's
# account must not be able to edit what the privileged unit runs.
install -d -o root -g root -m 0755 "${ROOT}/deploy"
install -o root -g root -m 0755 "${HERE}/update.sh"        "${ROOT}/deploy/update.sh"
install -o root -g root -m 0755 "${HERE}/rollback.sh"      "${ROOT}/deploy/rollback.sh"
install -o root -g root -m 0755 "${HERE}/update-agent.sh"  "${ROOT}/deploy/update-agent.sh"

# The spool is the one directory both sides touch. The app writes requests
# and reads status; the agent reads requests and writes status.
install -d -o "${USER_NAME}" -g "${USER_NAME}" -m 0755 "${ROOT}/data/updates"

install -o root -g root -m 0644 "${HERE}/dmarc-update.service" /etc/systemd/system/

# The path unit names the spool absolutely, and everything else here honours
# DMARC_ROOT. Installed anywhere but the default that left systemd watching
# /opt/dmarc while the app wrote somewhere else, so the button did nothing at
# all and nothing anywhere said why.
sed "s|/opt/dmarc/data/updates/requested.json|${ROOT}/data/updates/requested.json|" \
    "${HERE}/dmarc-update.path" > /etc/systemd/system/dmarc-update.path
chown root:root /etc/systemd/system/dmarc-update.path
chmod 0644 /etc/systemd/system/dmarc-update.path

systemctl daemon-reload
systemctl enable --now dmarc-update.path

echo
echo "Done. The Updates page can now install releases."
echo
echo "If the repository is private, put a read-only token where only root can read it:"
echo "  printf 'GITHUB_TOKEN=%s\\n' '<token>' > /etc/dmarc-update.env"
echo "  chmod 0600 /etc/dmarc-update.env"
echo
echo "Deliberately NOT in the app's configuration: the app runs unprivileged and"
echo "does not need it. Only the agent that installs releases does."
