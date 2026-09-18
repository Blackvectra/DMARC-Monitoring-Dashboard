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

# Both units name paths absolutely, because systemd has no variables of its
# own, and everything else here honours DMARC_ROOT.
#
# The path unit was already rewritten for this. The service unit was not, and
# it carries /opt/dmarc twice: the script it runs, and the only directory it
# is permitted to write to. Installed anywhere else, the watch fired
# correctly, the service then failed on a script that was not there - and had
# it been there, ReadWritePaths would have denied every write it needed to
# make. The button did nothing, and the reason was two directories away in a
# unit file nobody was looking at.
sed -e "s|/opt/dmarc/deploy/update-agent.sh|${ROOT}/deploy/update-agent.sh|" \
    -e "s|ReadWritePaths=/opt/dmarc |ReadWritePaths=${ROOT} |" \
    "${HERE}/dmarc-update.service" > /etc/systemd/system/dmarc-update.service
chown root:root /etc/systemd/system/dmarc-update.service
chmod 0644 /etc/systemd/system/dmarc-update.service

sed "s|/opt/dmarc/data/updates/requested.json|${ROOT}/data/updates/requested.json|" \
    "${HERE}/dmarc-update.path" > /etc/systemd/system/dmarc-update.path
chown root:root /etc/systemd/system/dmarc-update.path
chmod 0644 /etc/systemd/system/dmarc-update.path

# Nothing in either installed unit may still point at the default when the
# root is somewhere else. Checked rather than assumed: this is the second time
# a hardcoded /opt/dmarc has survived a rewrite of these files, and it fails
# silently both times.
if [[ "$ROOT" != "/opt/dmarc" ]]; then
    for unit in /etc/systemd/system/dmarc-update.service /etc/systemd/system/dmarc-update.path; do
        if grep -q "/opt/dmarc" "$unit"; then
            echo "BUG: ${unit} still refers to /opt/dmarc after being rewritten for ${ROOT}:" >&2
            grep -n "/opt/dmarc" "$unit" >&2
            exit 70   # EX_SOFTWARE
        fi
    done
fi

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
