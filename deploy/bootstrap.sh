#!/usr/bin/env bash
#
# DMARC Monitor on a Linux server, in one command.
#
# From nothing - a fresh Ubuntu 24.04 or Amazon Linux 2023 machine with a DNS
# name pointing at it - to a running, TLS-terminated instance that answers on
# https://<host>. It does everything docs/DEPLOYING.md steps 1 to 4 describe,
# and can do steps 5 and 6 too when handed the Entra details:
#
#   1. Installs the ASP.NET Core 10 runtime and the tools, from the
#      distribution's own repositories (apt or dnf), or the runtime from
#      Microsoft's installer into /opt/dotnet where the distribution has none.
#   2. Installs Caddy - from apt where a package exists, as the static binary
#      with Caddy's own unit file where one does not - and writes the
#      Caddyfile for --host. Caddy then gets and renews the certificate.
#   3. Downloads the release (or takes it from --from-dir) and runs
#      deploy/install.sh: account, files, database, units, service.
#   4. Writes any configuration it was given into appsettings.Production.json
#      and /etc/dmarc-ingest.env, and enables the collector's timer once it has
#      everything the collector needs.
#   5. Installs the update agent behind the Updates page's Install button.
#
# Re-running it is safe. On a machine that is already installed it skips the
# install and only applies configuration, so Entra sign-in or the mailbox can
# be added later with the same command and a few more arguments.
#
# Usage, on the server:
#
#   curl -fsSL https://raw.githubusercontent.com/Blackvectra/DMARC-Monitoring-Dashboard/main/deploy/bootstrap.sh \
#     | sudo bash -s -- --host dmarc.example.com --email you@example.com
#
#   or from an unpacked dmarc-deploy.tar.gz:  sudo ./deploy/bootstrap.sh --host ... --email ...
#
# Options:
#   --host <fqdn>               The public name. Required unless --no-proxy.
#   --email <address>           For the certificate authority. Recommended.
#   --release <tag>             Which release to install. Default: latest.
#   --from-dir <dir>            Use dmarc-web.zip and dmarc-linux-<arch> found there
#                               instead of downloading (air-gapped machines, CI).
#   --provider-name <name>      How you are named in client reports.
#   --tls-report-address <a>    Where TLS-RPT reports are asked to be sent.
#   --tenant-id <id> --client-id <id>
#                               Entra sign-in (docs/DEPLOYING.md step 5). Until both
#                               are set the app serves nothing but this machine.
#   --master-group-id <id>      The Entra security group whose members see every
#                               organization (docs/DEPLOYING.md step 5).
#   --organization <slug>       The organization this machine's collector files new
#                               domains under. Default: local.
#   --mailbox <address> --ingest-tenant-id <id> --ingest-client-id <id>
#   --cert <path.pfx>           The collector (docs/INGEST-SETUP.md). The .pfx is
#                               copied under the install root, owned by the service
#                               account. The timer is enabled once all four are known.
#   --cert-password-file <f>    The .pfx password, read from a file. Or set
#                               DMARC_CERT_PASSWORD in the environment
#                               (sudo --preserve-env=DMARC_CERT_PASSWORD). There is a
#                               --cert-password <pw> too, but a password on a command
#                               line is visible to every account on the machine in
#                               `ps` for as long as this runs.
#   --fallback-address <a>      Optional. The one shared address every domain reports
#                               to; defaults to the mailbox itself.
#   --reporting-domain <d>      Optional. Per-domain report addresses live under
#                               this domain, e.g. rua.example.com.
#   --make-ingest-cert          Create the collector's certificate here: the .pfx
#                               goes to /opt/dmarc/data, the .cer to upload to Entra
#                               is printed, the password goes in /etc/dmarc-ingest.env.
#   --no-proxy                  Skip Caddy (you are putting something else in front).
#   --no-update-agent           Skip the root unit behind the Updates page.
#
# Honours DMARC_ROOT and DMARC_USER like every other script here.

set -euo pipefail

REPO="${DMARC_REPO:-Blackvectra/DMARC-Monitoring-Dashboard}"
ROOT="${DMARC_ROOT:-/opt/dmarc}"
USER_NAME="${DMARC_USER:-dmarc}"

HOST=""; EMAIL=""; RELEASE="latest"; FROM_DIR=""
PROVIDER_NAME=""; TLS_REPORT_ADDRESS=""
TENANT_ID=""; CLIENT_ID=""; MASTER_GROUP_ID=""; ORGANIZATION=""
MAILBOX=""; INGEST_TENANT_ID=""; INGEST_CLIENT_ID=""; CERT=""; CERT_PASSWORD="${DMARC_CERT_PASSWORD:-}"
FALLBACK_ADDRESS=""; REPORTING_DOMAIN=""
MAKE_CERT=false; PROXY=true; UPDATE_AGENT=true

usage() {
    if [[ -f "$0" ]]; then sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'
    else echo "options: see https://github.com/${REPO}/blob/main/deploy/bootstrap.sh"; fi
}

# Downloads a file, retrying the failures worth retrying.
#
# Every download here is from somebody else's CDN - Microsoft's, Caddy's,
# GitHub's - and any of them can answer 5xx for a few seconds. A single curl
# turns that into a dead install: most of the way through, then a failure at
# the proxy step and a half-built machine to work out by hand. CI hit exactly
# that, a 504 from GitHub on the WinSW download, which is what a real server
# would get on a bad afternoon.
#
# --retry covers connection failures and 5xx; --retry-all-errors would also
# retry a 404, which is an answer rather than a hiccup and should be reported
# at once.
fetch() {
    curl -fsSL --retry 3 --retry-delay 2 --retry-connrefused --connect-timeout 20 "$@"
}

need_value() { [[ -n "${2:-}" && "${2:0:2}" != "--" ]] || { echo "$1 needs a value" >&2; exit 64; }; }

# Everything below is one function, called on the last line. Piped through
# bash, the script is otherwise executed as it arrives, and a connection that
# drops half way runs half a script - packages installed, a unit downloaded,
# nothing after. Parsed whole first, it either runs or does not.
main() {

while (( $# )); do
    case "$1" in
        --host)               need_value "$1" "${2:-}"; HOST="$2"; shift 2 ;;
        --email)              need_value "$1" "${2:-}"; EMAIL="$2"; shift 2 ;;
        --release)            need_value "$1" "${2:-}"; RELEASE="$2"; shift 2 ;;
        --from-dir)           need_value "$1" "${2:-}"; FROM_DIR="$2"; shift 2 ;;
        --provider-name)      need_value "$1" "${2:-}"; PROVIDER_NAME="$2"; shift 2 ;;
        --tls-report-address) need_value "$1" "${2:-}"; TLS_REPORT_ADDRESS="$2"; shift 2 ;;
        --tenant-id)          need_value "$1" "${2:-}"; TENANT_ID="$2"; shift 2 ;;
        --client-id)          need_value "$1" "${2:-}"; CLIENT_ID="$2"; shift 2 ;;
        --master-group-id)    need_value "$1" "${2:-}"; MASTER_GROUP_ID="$2"; shift 2 ;;
        # --organisation is still taken: the older spelling appears in pages
        # and notes people have already copied commands out of.
        --organization|--organisation)
                              need_value "$1" "${2:-}"; ORGANIZATION="$2"; shift 2 ;;
        --mailbox)            need_value "$1" "${2:-}"; MAILBOX="$2"; shift 2 ;;
        --ingest-tenant-id)   need_value "$1" "${2:-}"; INGEST_TENANT_ID="$2"; shift 2 ;;
        --ingest-client-id)   need_value "$1" "${2:-}"; INGEST_CLIENT_ID="$2"; shift 2 ;;
        --cert)               need_value "$1" "${2:-}"; CERT="$2"; shift 2 ;;
        --cert-password)      need_value "$1" "${2:-}"; CERT_PASSWORD="$2"; shift 2
                              echo "note: --cert-password puts the password in this process's command line; prefer --cert-password-file or DMARC_CERT_PASSWORD" >&2 ;;
        --cert-password-file) need_value "$1" "${2:-}"
                              [[ -r "$2" ]] || { echo "--cert-password-file: cannot read $2" >&2; exit 66; }
                              IFS= read -r CERT_PASSWORD < "$2" || true; shift 2 ;;
        --fallback-address)   need_value "$1" "${2:-}"; FALLBACK_ADDRESS="$2"; shift 2 ;;
        --reporting-domain)   need_value "$1" "${2:-}"; REPORTING_DOMAIN="$2"; shift 2 ;;
        --make-ingest-cert)   MAKE_CERT=true; shift ;;
        --no-proxy)           PROXY=false; shift ;;
        --no-update-agent)    UPDATE_AGENT=false; shift ;;
        -h|--help)            usage; exit 0 ;;
        *) echo "unknown option: $1" >&2; echo "run with --help" >&2; exit 64 ;;
    esac
done

[[ $EUID -eq 0 ]] || { echo "run this as root: sudo $0 ..." >&2; exit 77; }   # EX_NOPERM

if [[ "$PROXY" == true && -z "$HOST" ]]; then
    echo "--host <fqdn> is required (it is what the certificate is for). Use --no-proxy to skip Caddy." >&2
    exit 64
fi
if [[ -n "$HOST" && ! "$HOST" =~ ^[A-Za-z0-9.-]+$ ]]; then
    echo "--host must be a bare hostname, e.g. dmarc.example.com (no scheme, no path)" >&2
    exit 64
fi
if [[ -n "$EMAIL" && ! "$EMAIL" =~ ^[^[:space:]{}\"]+@[^[:space:]{}\"]+$ ]]; then
    echo "--email must be one address, e.g. you@example.com" >&2
    exit 64
fi
if [[ -n "$TENANT_ID" && -z "$CLIENT_ID" ]] || [[ -z "$TENANT_ID" && -n "$CLIENT_ID" ]]; then
    echo "--tenant-id and --client-id go together; the app treats sign-in as configured only when both are set" >&2
    exit 64
fi

case "$(uname -m)" in
    x86_64)  ARCH=linux-x64 ;;
    aarch64) ARCH=linux-arm64 ;;
    *) echo "unsupported architecture $(uname -m)" >&2; exit 69 ;;
esac

# Where the other scripts are. From an unpacked tarball, beside this file;
# piped through bash, nowhere yet - they come with the release.
HERE=""
if [[ -n "${BASH_SOURCE[0]:-}" && -f "${BASH_SOURCE[0]}" ]]; then
    HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fi

# ---- 1. which Linux --------------------------------------------------------
PKG=""
if command -v apt-get >/dev/null 2>&1; then PKG=apt; fi
if command -v dnf >/dev/null 2>&1; then PKG=dnf; fi
[[ -n "$PKG" ]] || { echo "neither apt-get nor dnf found; this script knows Ubuntu/Debian and Amazon Linux/Fedora/RHEL" >&2; exit 69; }

# shellcheck disable=SC1091
OS_ID="$(. /etc/os-release 2>/dev/null && echo "${ID:-unknown}")"
echo "DMARC Monitor bootstrap on ${OS_ID} (${PKG}, ${ARCH})"

# ---- 2. runtime and tools ---------------------------------------------------
echo "== runtime and tools"
if [[ "$PKG" == apt ]]; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    # Ubuntu carries the runtime itself. Debian does not, and this is where it
    # shows: the runtime is checked below and the fix is named there.
    apt-get install -y -qq unzip sqlite3 curl ca-certificates openssl python3 >/dev/null
    apt-get install -y -qq aspnetcore-runtime-10.0 >/dev/null 2>&1 || true
else
    dnf install -y -q unzip sqlite curl tar openssl python3
    dnf install -y -q aspnetcore-runtime-10.0 >/dev/null 2>&1 || true
fi

have_runtime() {
    command -v dotnet >/dev/null 2>&1 && dotnet --list-runtimes 2>/dev/null | grep -q '^Microsoft.AspNetCore.App 10\.'
}

# Not every distribution carries .NET 10 yet. Where the package manager did
# not provide it, Microsoft's own installer puts a private copy in
# /opt/dotnet - the same way bootstrap.ps1 does on Windows - and the symlink
# in /usr/local/bin is found ahead of any older system dotnet.
if ! have_runtime; then
    echo "   the distribution has no ASP.NET Core 10 runtime; installing Microsoft's into /opt/dotnet"
    installer="$(mktemp)"
    fetch https://dot.net/v1/dotnet-install.sh -o "$installer"
    bash "$installer" --runtime aspnetcore --channel 10.0 --install-dir /opt/dotnet >/dev/null
    rm -f "$installer"
    ln -sf /opt/dotnet/dotnet /usr/local/bin/dotnet
    hash -r
fi

if ! have_runtime; then
    echo "the ASP.NET Core 10 runtime could not be installed: neither the distribution nor Microsoft's installer provided it." >&2
    echo "Install it by hand, then run this again:" >&2
    echo "  https://learn.microsoft.com/dotnet/core/install/linux" >&2
    exit 69
fi
echo "   $(dotnet --list-runtimes | grep '^Microsoft.AspNetCore.App 10\.' | head -1)"

# ---- 3. Caddy ---------------------------------------------------------------
install_caddy_static() {
    local arch=amd64
    [[ "$ARCH" == linux-arm64 ]] && arch=arm64
    echo "   Caddy: static binary (no package in this distribution)"
    local tmp; tmp="$(mktemp)"
    fetch "https://caddyserver.com/api/download?os=linux&arch=${arch}" -o "$tmp"
    install -m 0755 "$tmp" /usr/bin/caddy
    rm -f "$tmp"
    getent group caddy >/dev/null || groupadd --system caddy
    id caddy >/dev/null 2>&1 || useradd --system --gid caddy --create-home --home-dir /var/lib/caddy \
        --shell /usr/sbin/nologin --comment "Caddy web server" caddy
    mkdir -p /etc/caddy
    fetch https://raw.githubusercontent.com/caddyserver/dist/master/init/caddy.service \
        -o /etc/systemd/system/caddy.service
    systemctl daemon-reload
}

if [[ "$PROXY" == true ]]; then
    echo "== Caddy"
    if ! command -v caddy >/dev/null 2>&1; then
        if [[ "$PKG" == apt ]] && apt-get install -y -qq caddy >/dev/null 2>&1; then
            echo "   Caddy: from apt"
        else
            install_caddy_static
        fi
    fi
    echo "   $(caddy version | head -1)"
fi

# ---- 4. the release ---------------------------------------------------------
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

WEB=""; CLI=""; DEPLOY_DIR=""
if [[ -n "$FROM_DIR" ]]; then
    WEB="${FROM_DIR}/dmarc-web.zip"
    CLI="${FROM_DIR}/dmarc-${ARCH}"
    if [[ -d "${FROM_DIR}/deploy" ]]; then DEPLOY_DIR="${FROM_DIR}/deploy"; fi
    for f in "$WEB" "$CLI"; do [[ -f "$f" ]] || { echo "not found in --from-dir: $f" >&2; exit 66; }; done
elif [[ ! -e "${ROOT}/app" ]]; then
    echo "== release ${RELEASE}"
    TAG="$RELEASE"
    if [[ "$TAG" == latest ]]; then
        TAG="$(fetch -H "Accept: application/vnd.github+json" "https://api.github.com/repos/${REPO}/releases/latest" \
            | python3 -c 'import json,sys; print(json.load(sys.stdin).get("tag_name",""))')" || TAG=""
        [[ -n "$TAG" ]] || { echo "could not find the latest release of ${REPO}. Is there one? Pass --release <tag>, or --from-dir with the files." >&2; exit 69; }
        echo "   latest is ${TAG}"
    fi
    BASE="https://github.com/${REPO}/releases/download/${TAG}"
    for name in dmarc-web.zip "dmarc-${ARCH}" dmarc-deploy.tar.gz; do
        echo "   fetching ${name}"
        fetch "${BASE}/${name}" -o "${WORK}/${name}" || {
            echo "could not download ${BASE}/${name}. If the repository is private, download the files in a browser and use --from-dir." >&2
            exit 69
        }
    done
    tar -xzf "${WORK}/dmarc-deploy.tar.gz" -C "$WORK"
    WEB="${WORK}/dmarc-web.zip"; CLI="${WORK}/dmarc-${ARCH}"; DEPLOY_DIR="${WORK}/deploy"
fi

# The scripts: beside this file, from the release, or already installed.
if [[ -z "$DEPLOY_DIR" ]]; then
    if [[ -n "$HERE" && -f "${HERE}/install.sh" ]]; then DEPLOY_DIR="$HERE"
    elif [[ -f "${ROOT}/deploy/install.sh" ]]; then DEPLOY_DIR="${ROOT}/deploy"
    fi
fi

# ---- 5. install, unless it already is ----------------------------------------
if [[ -e "${ROOT}/app" ]]; then
    echo "== already installed at ${ROOT}; applying configuration only"
    echo "   (to change versions: sudo ${ROOT}/deploy/update.sh <tag>)"
else
    [[ -n "$DEPLOY_DIR" && -f "${DEPLOY_DIR}/install.sh" ]] || { echo "install.sh not found; run this from an unpacked dmarc-deploy.tar.gz, or let it download the release" >&2; exit 66; }
    echo "== install"
    DMARC_BOOTSTRAP=1 DMARC_ROOT="$ROOT" DMARC_USER="$USER_NAME" bash "${DEPLOY_DIR}/install.sh" --web "$WEB" --cli "$CLI"
fi

SETTINGS="${ROOT}/app/appsettings.Production.json"
INGEST_ENV=/etc/dmarc-ingest.env

# ---- 6. configuration -------------------------------------------------------
# Merged into the file that is there, never written over it: a key given here
# changes, everything else stays. Both files are tiny JSON / KEY=VALUE, and
# python3 is on every machine this runs on.
settings_set() {   # settings_set Section:Key value ...
    python3 - "$SETTINGS" "$@" <<'PY'
import json, sys
path = sys.argv[1]
with open(path) as f:
    doc = json.load(f)
args = sys.argv[2:]
for key, value in zip(args[0::2], args[1::2]):
    node = doc
    parts = key.split(":")
    for part in parts[:-1]:
        node = node.setdefault(part, {})
    node[parts[-1]] = value
with open(path, "w") as f:
    json.dump(doc, f, indent=2)
    f.write("\n")
PY
}

env_set() {        # env_set KEY value  (in /etc/dmarc-ingest.env, created 0600 if missing)
    # The value goes in through the environment, not python's argv: one of
    # them is the certificate password, and argv is readable in `ps` by every
    # account on the machine for as long as the interpreter runs.
    ENV_FILE="$INGEST_ENV" ENV_KEY="$1" ENV_VALUE="$2" python3 - <<'PY'
import os, re, sys
path, key, value = os.environ["ENV_FILE"], os.environ["ENV_KEY"], os.environ["ENV_VALUE"]
if "\n" in value or "\r" in value:
    sys.exit(f"{key}: a value with a line break cannot be stored")
# Double-quoted, with the characters both systemd's EnvironmentFile= parser
# and bash treat specially escaped, so both read back exactly what was given.
quoted = '"' + re.sub(r'([\\"$`])', r'\\\1', value) + '"'
lines = open(path).read().splitlines() if os.path.exists(path) else []
out, done = [], False
for line in lines:
    if line.startswith(key + "="):
        out.append(f"{key}={quoted}"); done = True
    else:
        out.append(line)
if not done:
    out.append(f"{key}={quoted}")
# Created with its final mode rather than chmod'ed after: the file holds a
# password from its first write, and the umask would have made it 0644.
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w") as f:
    f.write("\n".join(out) + "\n")
os.chmod(path, 0o600)
PY
}

env_get() {        # env_get KEY  -> the stored value, unquoted
    local v
    v="$(grep "^$1=" "$INGEST_ENV" 2>/dev/null | head -1 | cut -d= -f2- || true)"
    v="${v%\"}"; v="${v#\"}"
    printf '%s' "$v"
}

echo "== configuration"
[[ -n "$HOST" ]]               && settings_set "MtaSts:PolicyHost" "$HOST"
[[ -n "$PROVIDER_NAME" ]]      && settings_set "Reporting:ProviderName" "$PROVIDER_NAME"
[[ -n "$TLS_REPORT_ADDRESS" ]] && settings_set "Reporting:TlsReportAddress" "$TLS_REPORT_ADDRESS"
[[ -n "$MASTER_GROUP_ID" ]]    && settings_set "Auth:MasterGroupId" "$MASTER_GROUP_ID" && echo "   master group: ${MASTER_GROUP_ID} sees every organization"
existing_tenant="$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); a=d.get("AzureAd",{}); print(a.get("TenantId","") if a.get("ClientId") else "")' "$SETTINGS" 2>/dev/null || true)"
if [[ -n "$TENANT_ID" ]]; then
    settings_set "AzureAd:TenantId" "$TENANT_ID" "AzureAd:ClientId" "$CLIENT_ID"
    echo "   sign-in: Microsoft Entra (tenant ${TENANT_ID})"
elif [[ -n "$existing_tenant" ]]; then
    echo "   sign-in: Microsoft Entra (tenant ${existing_tenant}, unchanged)"
else
    echo "   sign-in: not configured - the app serves only this machine until --tenant-id/--client-id are given"
fi
chown "${USER_NAME}:${USER_NAME}" "$SETTINGS"; chmod 0600 "$SETTINGS"

# The service read its configuration when install.sh started it, before any of
# the above was written. Restarted here, always: it is cheap, and the
# alternative is an instance that says "local trial mode" until somebody
# remembers.
systemctl restart dmarc-web
ok=false
for _ in $(seq 1 30); do
    sleep 1
    if curl -fsS -o /dev/null -w '%{http_code}' http://127.0.0.1:5000/ 2>/dev/null | grep -qE '^(2|3|4)'; then ok=true; break; fi
done
if [[ "$ok" != true ]]; then
    echo "dmarc-web was restarted but does not answer on 127.0.0.1:5000. See why with: journalctl -u dmarc-web -n 50" >&2
    echo "(a wrong --tenant-id/--client-id pair, or a broken appsettings.Production.json, are the usual causes)" >&2
    exit 1
fi

# ---- 7. the collector -------------------------------------------------------
if [[ "$MAKE_CERT" == true ]]; then
    echo "== collector certificate"
    PFX="${ROOT}/data/ingest.pfx"
    if [[ -f "$PFX" ]]; then
        echo "   ${PFX} already exists; not replacing it (delete it first to make a new one)"
    else
        CERT_PASSWORD="$(openssl rand -base64 24)"
        openssl req -x509 -newkey rsa:2048 -sha256 -days 730 -nodes \
            -subj "/CN=DMARC Monitor ingest" \
            -keyout "${WORK}/ingest.key" -out "${WORK}/ingest.crt" 2>/dev/null
        # The password reaches openssl through the environment (env:NAME),
        # never its command line; umask keeps the .pfx private from the moment
        # it exists, and the owner is set before anything else can happen.
        ( umask 077 && CERT_PASSWORD="$CERT_PASSWORD" openssl pkcs12 -export \
            -inkey "${WORK}/ingest.key" -in "${WORK}/ingest.crt" -out "$PFX" -passout env:CERT_PASSWORD )
        chown "${USER_NAME}:${USER_NAME}" "$PFX"; chmod 0600 "$PFX"
        # Recorded first. Everything after this can fail without leaving a
        # .pfx whose password nobody has.
        env_set DMARC_CERT_PATH "$PFX"
        env_set DMARC_CERT_PASSWORD "$CERT_PASSWORD"
        CERT="$PFX"
        # The public half, where the person who ran this can pick it up.
        openssl x509 -in "${WORK}/ingest.crt" -outform der -out "${WORK}/ingest.cer"
        CER_DIR="${SUDO_USER:+$(getent passwd "$SUDO_USER" | cut -d: -f6)}"
        CER="${CER_DIR:-/root}/dmarc-ingest.cer"
        if cp "${WORK}/ingest.cer" "$CER" 2>/dev/null; then
            [[ -n "${SUDO_USER:-}" ]] && chown "$SUDO_USER" "$CER"
        else
            CER="${ROOT}/dmarc-ingest.cer"; cp "${WORK}/ingest.cer" "$CER"
        fi
        echo "   private half: ${PFX} (owned by ${USER_NAME}, password in ${INGEST_ENV})"
        echo "   public half:  ${CER}  <- upload this under the ingest app registration, Certificates & secrets"
        echo "   expires:      $(openssl x509 -in "${WORK}/ingest.crt" -noout -enddate | cut -d= -f2)"
    fi
fi

# A certificate handed in from elsewhere goes where the service can read it,
# owned by the service, and the recorded path is that copy: a path in
# somebody's home directory works today and fails the day that account goes.
if [[ -n "$CERT" && "$CERT" != "${ROOT}/data/ingest.pfx" ]]; then
    [[ -f "$CERT" ]] || { echo "--cert: no such file: ${CERT}" >&2; exit 66; }
    install -o "$USER_NAME" -g "$USER_NAME" -m 0600 "$CERT" "${ROOT}/data/ingest.pfx"
    echo "   copied ${CERT} to ${ROOT}/data/ingest.pfx (owned by ${USER_NAME}, mode 0600)"
    CERT="${ROOT}/data/ingest.pfx"
fi

if [[ -n "$MAILBOX$INGEST_TENANT_ID$INGEST_CLIENT_ID$CERT$CERT_PASSWORD$FALLBACK_ADDRESS$REPORTING_DOMAIN$ORGANIZATION" ]]; then
    echo "== collector"
    [[ -n "$MAILBOX" ]]          && env_set DMARC_MAILBOX "$MAILBOX"
    [[ -n "$INGEST_TENANT_ID" ]] && env_set DMARC_TENANT_ID "$INGEST_TENANT_ID"
    [[ -n "$INGEST_CLIENT_ID" ]] && env_set DMARC_CLIENT_ID "$INGEST_CLIENT_ID"
    [[ -n "$CERT" ]]             && env_set DMARC_CERT_PATH "$CERT"
    [[ -n "$CERT_PASSWORD" ]]    && env_set DMARC_CERT_PASSWORD "$CERT_PASSWORD"
    [[ -n "$FALLBACK_ADDRESS" ]] && env_set DMARC_FALLBACK_ADDRESS "$FALLBACK_ADDRESS"
    [[ -n "$REPORTING_DOMAIN" ]] && env_set DMARC_REPORTING_DOMAIN "$REPORTING_DOMAIN"
    [[ -n "$ORGANIZATION" ]]     && env_set DMARC_ORGANIZATION "$ORGANIZATION"
    chmod 0600 "$INGEST_ENV"

    # Enabled only when everything it needs is known; a timer firing a
    # collector with no tenant is an hourly error in the journal.
    missing=()
    for key in DMARC_MAILBOX DMARC_TENANT_ID DMARC_CLIENT_ID DMARC_CERT_PATH; do
        v="$(env_get "$key")"
        [[ -n "$v" ]] || { missing+=("$key"); continue; }
        # The template's placeholder counts as unset - unless that exact
        # address was given on this run, in which case it is the mailbox.
        [[ "$key" == DMARC_MAILBOX && -z "$MAILBOX" && "$v" == "dmarc@example.com" ]] && missing+=("$key")
    done
    pfx_path="$(env_get DMARC_CERT_PATH)"
    if [[ -n "$pfx_path" ]] && ! sudo -u "$USER_NAME" test -r "$pfx_path"; then
        echo "   ${pfx_path} is not readable by ${USER_NAME}; the collector will fail until it is" >&2
        missing+=("a readable DMARC_CERT_PATH")
    fi
    if (( ${#missing[@]} == 0 )); then
        systemctl enable --now dmarc-ingest.timer >/dev/null
        echo "   dmarc-ingest.timer enabled (hourly). Dry-run first:"
        echo "     sudo bash -c 'set -a; . ${INGEST_ENV}; exec sudo -E -H -u ${USER_NAME} dmarc ingest --db ${ROOT}/data/dmarc.db --mailbox \"\$DMARC_MAILBOX\" --dry-run'"
    else
        echo "   timer not enabled yet; still missing in ${INGEST_ENV}: ${missing[*]}"
    fi
fi

# ---- 8. Caddy in front -----------------------------------------------------
if [[ "$PROXY" == true ]]; then
    echo "== proxy"
    CADDYFILE=/etc/caddy/Caddyfile
    mkdir -p /etc/caddy
    # Rendered and validated aside, then installed: a Caddyfile that fails
    # validation must not have replaced one that was serving.
    {
        if [[ -n "$EMAIL" ]]; then printf '{\n    email %s\n}\n\n' "$EMAIL"; fi
        printf '%s {\n    reverse_proxy 127.0.0.1:5000\n}\n' "$HOST"
    } > "${WORK}/Caddyfile"
    caddy validate --config "${WORK}/Caddyfile" --adapter caddyfile >/dev/null
    install -m 0644 "${WORK}/Caddyfile" "$CADDYFILE"
    systemctl enable --now caddy >/dev/null
    systemctl reload caddy 2>/dev/null || true
    sleep 2
    # Through the proxy, as a visitor would arrive. Local trial mode refuses a
    # proxied request (403); with sign-in configured it redirects to Entra (302).
    code="$(curl -sk -o /dev/null -w '%{http_code}' --resolve "${HOST}:443:127.0.0.1" "https://${HOST}/" || true)"
    case "$code" in
        403) echo "   https://${HOST}/ answers 403: TLS and the proxy work; sign-in is not configured yet, so only this machine is served" ;;
        302) echo "   https://${HOST}/ redirects to sign-in: TLS, the proxy and Entra are all wired" ;;
        *)   echo "   https://${HOST}/ answered '${code}'. Caddy may still be getting the certificate; watch: journalctl -u caddy -f" ;;
    esac
fi

# ---- 9. the update agent -----------------------------------------------------
if [[ "$UPDATE_AGENT" == true ]]; then
    if [[ -n "$DEPLOY_DIR" && -f "${DEPLOY_DIR}/install-update-agent.sh" ]]; then
        echo "== update agent"
        DMARC_ROOT="$ROOT" DMARC_USER="$USER_NAME" bash "${DEPLOY_DIR}/install-update-agent.sh" >/dev/null
        echo "   installed; the Updates page can install releases"
    fi
fi

# ---- done -------------------------------------------------------------------
# How to run this again. A copy is kept under the install root by the update
# agent step; piped through bash there is no other copy anywhere.
if [[ -f "${ROOT}/deploy/bootstrap.sh" ]]; then
    SELF="sudo ${ROOT}/deploy/bootstrap.sh"
elif [[ -n "$HERE" && -f "${HERE}/bootstrap.sh" ]]; then
    SELF="sudo ${HERE}/bootstrap.sh"
else
    SELF="curl -fsSL https://raw.githubusercontent.com/${REPO}/main/deploy/bootstrap.sh | sudo bash -s --"
fi

cat <<DONE

Done.
DONE
if [[ -z "$TENANT_ID" && -z "$existing_tenant" ]]; then
    cat <<DONE
Next: sign-in. In Entra, App registrations -> New registration:
  name DMARC Monitor, single tenant, Redirect URI (Web) https://${HOST:-<host>}/signin-oidc
  Authentication: add Redirect URI https://${HOST:-<host>}/signout-callback-oidc,
    Front-channel logout URL https://${HOST:-<host>}/signout-oidc,
    tick "ID tokens (used for implicit and hybrid flows)", Save.
  Enterprise applications -> DMARC Monitor -> Permissions -> Grant admin consent;
    Properties -> Assignment required = Yes; Users and groups -> add who may sign in.
Then, here:
  ${SELF} --host ${HOST:-<host>} --tenant-id <directory id> --client-id <application id>
DONE
fi
if [[ ! -f "$INGEST_ENV" ]] || [[ -z "$(env_get DMARC_TENANT_ID)" ]]; then
    cat <<DONE
Mailbox collection: docs/INGEST-SETUP.md. When the ingest app registration exists:
  ${SELF} --host ${HOST:-<host>} --make-ingest-cert --mailbox dmarc@example.com \\
      --ingest-tenant-id <directory id> --ingest-client-id <ingest application id>
DONE
fi

}

main "$@"
