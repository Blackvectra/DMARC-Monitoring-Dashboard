#!/usr/bin/env bash
#
# First install of DMARC Monitor on a Linux server, from the two release
# artifacts. Ubuntu and Amazon Linux 2023 are the two it is written for; any
# systemd distribution with the ASP.NET Core 8 runtime should be the same.
#
# What it does, in order:
#
#   1. Checks the tools it needs are present, and says how to get them on
#      this distribution rather than assuming apt.
#   2. Creates the dmarc account and /opt/dmarc, unpacks the web app into
#      app/, installs the dmarc command, and creates the database.
#   3. Writes appsettings.Production.json and /etc/dmarc-ingest.env as
#      templates IF they do not exist - it never overwrites either.
#   4. Installs the systemd units, rewritten for DMARC_ROOT and DMARC_USER,
#      starts the web app, and checks it answers on loopback.
#
# It refuses to run over an existing install: that is update.sh's job, and it
# keeps a copy of what it replaces, which this does not.
#
# Usage, from the directory the release was downloaded to:
#   sudo ./install.sh                                   dmarc-web.zip and dmarc-linux-<arch> here
#   sudo ./install.sh --web path/to/dmarc-web.zip --cli path/to/dmarc-linux-x64
#   DMARC_ROOT=/srv/dmarc sudo -E ./install.sh          somewhere other than /opt/dmarc

set -euo pipefail

ROOT="${DMARC_ROOT:-/opt/dmarc}"
USER_NAME="${DMARC_USER:-dmarc}"
HEALTH_URL="${DMARC_HEALTH_URL:-http://127.0.0.1:5000/}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

case "$(uname -m)" in
    x86_64)  ARCH=linux-x64   ;;
    aarch64) ARCH=linux-arm64 ;;
    *)       ARCH=""          ;;
esac

WEB=""
CLI=""
while (( $# )); do
    case "$1" in
        --web) WEB="${2:-}"; shift 2 ;;
        --cli) CLI="${2:-}"; shift 2 ;;
        -h|--help)
            sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        *) echo "unknown option: $1" >&2; echo "usage: $0 [--web dmarc-web.zip] [--cli dmarc-${ARCH:-linux-x64}]" >&2; exit 64 ;;
    esac
done
[[ -n "$WEB" ]] || WEB="./dmarc-web.zip"
[[ -n "$CLI" ]] || CLI="./dmarc-${ARCH:-unknown}"

[[ $EUID -eq 0 ]] || { echo "run this as root: sudo $0" >&2; exit 77; }   # EX_NOPERM

# ---- 1. tools ---------------------------------------------------------------
#
# Named by the package manager this machine actually has. The one tool whose
# package is called something else on the two families is sqlite3: the
# package is sqlite3 on Debian and Ubuntu, sqlite on Fedora and Amazon Linux.
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
for tool in unzip sqlite3 curl python3 systemctl; do
    command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
done
if (( ${#missing[@]} )); then
    echo "missing: ${missing[*]}" >&2
    echo "install them first:  $(pkg_hint "${missing[@]}")" >&2
    exit 69   # EX_UNAVAILABLE
fi

# The web bundle is not self-contained. Checked here, because the alternative
# is a unit that fails to start with a message about a missing framework,
# three steps from now.
if ! command -v dotnet >/dev/null 2>&1 || ! dotnet --list-runtimes 2>/dev/null | grep -q '^Microsoft.AspNetCore.App 8\.'; then
    echo "the ASP.NET Core 8 runtime is not installed (dotnet --list-runtimes does not show Microsoft.AspNetCore.App 8.x)." >&2
    echo "install it first:  $(pkg_hint aspnetcore-runtime-8.0)" >&2
    echo "on Ubuntu without that package, add Microsoft's feed: https://learn.microsoft.com/dotnet/core/install/linux-ubuntu" >&2
    exit 69
fi
DOTNET="$(command -v dotnet)"

for artifact in "$WEB" "$CLI"; do
    [[ -f "$artifact" ]] || { echo "not found: ${artifact} (pass --web and --cli, or run this from the download directory)" >&2; exit 66; }
done

if [[ -e "${ROOT}/app" ]]; then
    echo "${ROOT}/app already exists. This installs from nothing; to change versions use:" >&2
    echo "  sudo ${HERE}/update.sh <version>" >&2
    exit 73   # EX_CANTCREAT
fi

echo "Installing DMARC Monitor to ${ROOT} as ${USER_NAME} (${ARCH:-$(uname -m)})"

# ---- 2. account, files, database -------------------------------------------
if ! id "$USER_NAME" >/dev/null 2>&1; then
    # A dedicated account, because the provider credentials are encrypted to
    # whichever account writes them. Its home is the install root so that
    # anything the runtime wants to write under ~ lands somewhere it owns.
    useradd --system --home-dir "$ROOT" --shell /usr/sbin/nologin "$USER_NAME"
    echo "  created account ${USER_NAME}"
fi

install -d -o "$USER_NAME" -g "$USER_NAME" -m 0750 "$ROOT"
install -d -o "$USER_NAME" -g "$USER_NAME" -m 0750 "${ROOT}/data"
# Backups default here. On this disk it protects against a bad change rather
# than a dead machine, which is why dmarc-backup.service can sync it off the
# box and the docs say to.
install -d -o "$USER_NAME" -g "$USER_NAME" -m 0750 "${ROOT}/backups"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "  unpacking the web app"
unzip -q "$WEB" -d "$WORK/unpacked"
if [[ -f "$WORK/unpacked/dmarc-web/DmarcMonitor.Web.dll" ]]; then
    mv "$WORK/unpacked/dmarc-web" "${ROOT}/app"
elif [[ -f "$WORK/unpacked/DmarcMonitor.Web.dll" ]]; then
    mv "$WORK/unpacked" "${ROOT}/app"
else
    echo "${WEB} does not contain DmarcMonitor.Web.dll - is it the release's dmarc-web.zip?" >&2
    exit 65   # EX_DATAERR
fi
chown -R "${USER_NAME}:${USER_NAME}" "${ROOT}/app"

echo "  installing the dmarc command"
install -m 0755 "$CLI" /usr/local/bin/dmarc

# As the service account, with the same extraction directory the units use,
# so the first run happens here where its output can be read.
echo "  creating the database"
sudo -u "$USER_NAME" env DOTNET_BUNDLE_EXTRACT_BASE_DIR="${ROOT}/data/.net" \
    /usr/local/bin/dmarc init-db --db "${ROOT}/data/dmarc.db"

# ---- 3. configuration, never overwritten ------------------------------------
SETTINGS="${ROOT}/app/appsettings.Production.json"
if [[ ! -f "$SETTINGS" ]]; then
    cat > "$SETTINGS" <<JSON
{
  "Database":  { "Path": "${ROOT}/data/dmarc.db" },
  "Secrets":   { "Directory": "${ROOT}/data/secrets" },

  "Reporting": {
    "ProviderName": "",
    "TlsReportAddress": ""
  },

  "MtaSts": { "PolicyHost": "" },

  "Proxy": { "Behind": true },

  "AzureAd": {
    "Instance": "https://login.microsoftonline.com/",
    "TenantId": "",
    "ClientId": "",
    "CallbackPath": "/signin-oidc"
  },

  "Updates": {
    "Repository": "Blackvectra/DMARC-Monitoring-Dashboard",
    "Channel": "stable",
    "Token": ""
  }
}
JSON
    chown "${USER_NAME}:${USER_NAME}" "$SETTINGS"
    chmod 0600 "$SETTINGS"
    echo "  wrote ${SETTINGS} (fill in AzureAd before anybody else can reach this)"
fi

INGEST_ENV=/etc/dmarc-ingest.env
if [[ ! -f "$INGEST_ENV" ]]; then
    cat > "$INGEST_ENV" <<ENV
# Read by dmarc-ingest.service, which runs: dmarc ingest --mailbox \$DMARC_MAILBOX
# and takes the rest from this environment. Fill these in, then:
#   sudo systemctl enable --now dmarc-ingest.timer
# See docs/INGEST-SETUP.md for the app registration and the certificate.
#
# COLLECTING MORE THAN ONE MAILBOX
#
# This file drives the single-mailbox unit. For several - one per organization
# is the usual shape - copy it once per mailbox and use the templated unit
# instead, which reads /etc/dmarc-ingest-<instance>.env:
#
#   sudo cp /etc/dmarc-ingest.env /etc/dmarc-ingest-acme.env
#   sudo chmod 0600 /etc/dmarc-ingest-acme.env
#   # edit DMARC_MAILBOX and DMARC_ORGANIZATION in the copy
#   sudo systemctl enable --now dmarc-ingest@acme.timer
#
# Then disable this one, so the same mailbox is not collected twice:
#   sudo systemctl disable --now dmarc-ingest.timer
#
# Give every instance its own DMARC_ORGANIZATION. Domains belong to an
# organization, so a mailbox collected under the wrong one makes a second copy
# of a customer's domain instead of filing into theirs - and says nothing,
# while the real domain stops growing. `dmarc reachability` flags a name held
# by more than one organization.
DMARC_MAILBOX=dmarc@example.com
DMARC_TENANT_ID=
DMARC_CLIENT_ID=
DMARC_CERT_PATH=${ROOT}/data/ingest.pfx
DMARC_CERT_PASSWORD=
# Optional. Reports are attributed by the one shared address every domain
# reports to (the mailbox itself, unless set here), or by per-domain
# addresses under a reporting domain such as rua.example.com.
DMARC_FALLBACK_ADDRESS=
DMARC_REPORTING_DOMAIN=
# Optional. The organization a domain nobody has seen before is filed under
# (dmarc org list). Default: local. A known domain keeps its own.
DMARC_ORGANIZATION=
ENV
    chmod 0600 "$INGEST_ENV"
    echo "  wrote ${INGEST_ENV} (fill it in, then enable dmarc-ingest.timer)"
fi

# ---- 4. units ---------------------------------------------------------------
#
# systemd has no variables of its own, so every path in the units is
# absolute and rewritten here. Then checked: this is the third time a
# hardcoded /opt/dmarc has been found surviving a rewrite of these files, and
# it fails silently every time.
render_unit() {
    sed -e "s|/opt/dmarc|${ROOT}|g" \
        -e "s|^User=dmarc$|User=${USER_NAME}|" \
        -e "s|/usr/bin/dotnet|${DOTNET}|" \
        "${HERE}/$1" > "/etc/systemd/system/$1"
    chown root:root "/etc/systemd/system/$1"
    chmod 0644 "/etc/systemd/system/$1"

    if [[ "$ROOT" != "/opt/dmarc" ]] && grep -q "/opt/dmarc" "/etc/systemd/system/$1"; then
        echo "BUG: /etc/systemd/system/$1 still refers to /opt/dmarc after being rewritten for ${ROOT}:" >&2
        grep -n "/opt/dmarc" "/etc/systemd/system/$1" >&2
        exit 70   # EX_SOFTWARE
    fi
}

render_unit dmarc-web.service
render_unit dmarc-ingest.service
render_unit dmarc-ingest.timer

# The templated pair, for an install collecting more than one mailbox - one
# instance per organization. Installed always, enabled never: which instances
# exist is the operator's decision and depends on env files only they can
# write. The non-templated unit above is left in place so an existing install
# that has it enabled keeps collecting across this upgrade.
render_unit 'dmarc-ingest@.service'
render_unit 'dmarc-ingest@.timer'
render_unit dmarc-dns.service
render_unit dmarc-dns.timer
render_unit dmarc-prune.service
render_unit dmarc-prune.timer
render_unit dmarc-backup.service
render_unit dmarc-backup.timer
render_unit dmarc-health.service
render_unit dmarc-health.timer
render_unit 'dmarc-alert@.service'

systemctl daemon-reload
echo "  starting dmarc-web"
systemctl enable --now dmarc-web >/dev/null

# Enabled here rather than left as a step for later, unlike the collector.
# The collector waits because it cannot run until somebody fills in a
# certificate and a mailbox; this needs nothing, reads only public DNS, and
# is what fills the record columns on the domains page. Left disabled it
# would be a feature nobody switched on, showing dashes forever.
echo "  enabling the nightly DNS scan"
systemctl enable --now dmarc-dns.timer >/dev/null

# Enabled from the first day on purpose. A retention window is easy to start
# with and painful to retrofit: switched on later it deletes a year of a
# customer's history in one run, which is a far bigger thing to approve than a
# weekly job that has been quietly ageing reports out all along. The window it
# uses is written in dmarc-prune.service, where an operator can read and change
# it, rather than left to a default that might move in a later release.
echo "  enabling the weekly retention prune (aggregate 400 days, forensic 30)"
systemctl enable --now dmarc-prune.timer >/dev/null

# Enabled from the first day for the same reason as the prune, and one more:
# a backup nobody turned on is the single most common way a single-machine
# install loses years of a customer's history. Local copies only until
# DMARC_BACKUP_S3 is set in /etc/dmarc-backup.env - which is worth doing,
# because a backup on the same instance does not survive losing the instance.
echo "  enabling the nightly database backup (${ROOT}/backups, 14 kept)"
systemctl enable --now dmarc-backup.timer >/dev/null

# The check that notices this install has stopped working. Enabled because
# the failure it catches - a collector that quietly stopped - is the one this
# product is worst at noticing on its own: every screen goes on showing the
# figures from before it stopped, and those look fine. It writes to the
# journal and fails the unit; wiring that to mail, Slack or SNS is a line in
# /etc/systemd/system/dmarc-alert@.service.
echo "  enabling the twice-daily health check (journal only until dmarc-alert@ is filled in)"
systemctl enable --now dmarc-health.timer >/dev/null

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
    echo >&2
    echo "dmarc-web started but did not answer at ${HEALTH_URL}. The files are in place; see why with:" >&2
    echo "  journalctl -u dmarc-web -n 50" >&2
    exit 1
fi

# Under bootstrap.sh the next steps are its job, and it says its own.
[[ -n "${DMARC_BOOTSTRAP:-}" ]] && exit 0

cat <<DONE

Installed. The web app is listening on 127.0.0.1:5000 for a reverse proxy on
this machine, and refuses everything that is not this machine until sign-in
is configured.

Next, in this order:
  1. Put Caddy (or nginx) in front of it with a certificate - docs/DEPLOYING.md, step 4.
  2. Fill in AzureAd in ${SETTINGS}, then: sudo systemctl restart dmarc-web
  3. Fill in ${INGEST_ENV}, then: sudo systemctl enable --now dmarc-ingest.timer
     Collecting several mailboxes? ${INGEST_ENV} says how; it is one instance
     of dmarc-ingest@.timer per mailbox, each with its own DMARC_ORGANIZATION.
  4. For the Updates page's Install button: sudo ${HERE}/install-update-agent.sh

Until step 2 is done, see it from your own machine through an SSH tunnel:
  ssh -L 5000:127.0.0.1:5000 <this server>   then open http://127.0.0.1:5000
DONE
