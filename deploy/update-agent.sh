#!/usr/bin/env bash
#
# The privileged half of the update button.
#
# The web app runs as an unprivileged account and cannot replace its own
# files. That is deliberate: it holds credentials that rewrite customers' DNS,
# and a web application that can also install software is a far larger thing
# to have compromised. So the app writes down a version it would like into a
# spool directory it owns, and this - started by a systemd path unit watching
# that file, running as root - decides whether to act on it.
#
# TWO KINDS OF HOSTILE INPUT CROSS THIS BOUNDARY, AND BOTH ARE TREATED AS SUCH.
#
# The obvious one is the version string. A file on disk is not a promise about
# what wrote it, so:
#
#   1. It must match a narrow version shape. No slashes, no spaces, nothing
#      that could climb out of a directory or be interpreted rather than
#      compared.
#   2. It must be a release that actually exists on the configured channel,
#      checked against GitHub here rather than trusted from the request. So
#      the worst an attacker who owned the web app could achieve is installing
#      a genuine release of this product.
#   3. A prerelease is refused unless this machine is on the preview channel.
#
# The less obvious one is the SPOOL DIRECTORY ITSELF. It is owned by the app
# account, so that account can put anything at the names root touches here - a
# symlink to a root-only file, a hardlink to one, a FIFO, or an entry it swaps
# out mid-run. A root process that followed any of those could be made to
# read, create, truncate, chown or delete a file of the app's choosing, which
# is a straight local privilege escalation. So every read, write and remove
# below:
#
#   - opens the spool directory once with O_NOFOLLOW and works RELATIVE to
#     that descriptor, so the directory cannot be swapped under it;
#   - opens the request with O_NOFOLLOW and checks the OPEN FILE (not the
#     name) with fstat - a regular file, owned by the app account - so a
#     symlink, a hardlink to a root-only file, or a FIFO is refused rather
#     than followed, and a name swapped in after the check cannot matter
#     because the check is on the descriptor already held;
#   - creates every file root writes with O_CREAT|O_EXCL|O_NOFOLLOW and sets
#     its owner on that descriptor, never through a name that could be a
#     symlink, then renames it into place (which replaces the directory entry
#     without following a symlink sitting there).
#
# The status file in particular is UNVALIDATED at the point the first refusal
# is written - that is the whole point of the refusal - so its values are
# encoded with json.dumps rather than pasted between quotes. Pasting a crafted
# version raw once let it close the string and add its own keys:
#
#   Version: v1.0.0", "State": "Succeeded
#
# which produced a status file with State twice, and a last-key-wins reader
# (which System.Text.Json is) showed the operator a green "Succeeded" for an
# update that had just been refused.
#
# Installed by deploy/install-update-agent.sh. See DEPLOYING.md.

set -euo pipefail

ROOT="${DMARC_ROOT:-/opt/dmarc}"
REPO="${DMARC_REPO:-Blackvectra/DMARC-Monitoring-Dashboard}"
CHANNEL="${DMARC_CHANNEL:-stable}"
USER_NAME="${DMARC_USER:-dmarc}"

SPOOL="${ROOT}/data/updates"
REQUEST="${SPOOL}/requested.json"
# status.json and last-update.log are written by the helpers below, relative
# to the spool descriptor they open; LOG is the path the failure message
# points an operator at.
LOG="${SPOOL}/last-update.log"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# update.sh writes its log through a shell redirection, which would follow a
# symlink the app planted at the log's name. So it writes to a private temp
# this unit alone can see (PrivateTmp=true in the unit hides it from every
# other account), and the result is published into the spool through the same
# no-follow create as the status. Declared here so the exit trap can remove it
# whatever happens.
LOGTMP=""
cleanup() { [[ -n "$LOGTMP" ]] && rm -f -- "$LOGTMP"; return 0; }
trap cleanup EXIT

# Writes the status the app reads back and the operator sees, into the
# app-owned spool, WITHOUT writing through anything planted at status.json or
# its temp: see the header. Encoding with json.dumps also closes the injection
# in which a crafted version closed the JSON string and added its own keys.
say() {
    DMARC_SPOOL="$SPOOL" DMARC_USER="$USER_NAME" \
    DMARC_STATE="${1-}" DMARC_VERSION="${2-}" DMARC_MESSAGE="${3-}" DMARC_STAMP="${4:-}" \
    python3 <<'PY' || true
import json, os, pwd, time

spool = os.environ["DMARC_SPOOL"]
user = os.environ["DMARC_USER"]

payload = json.dumps({
    "State":   os.environ.get("DMARC_STATE", ""),
    "Version": os.environ.get("DMARC_VERSION", ""),
    "Message": os.environ.get("DMARC_MESSAGE", ""),
    "At":      time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "Stamp":   os.environ.get("DMARC_STAMP", ""),
}, indent=2) + "\n"

try:
    # O_NOFOLLOW: if the app turned the spool into a symlink, this fails rather
    # than following it. Everything below is relative to this descriptor, so
    # the directory cannot be swapped for another after it is opened.
    dfd = os.open(spool, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
except OSError as ex:
    import sys
    sys.stderr.write(f"update-agent: cannot write status: {ex}\n")
    raise SystemExit(0)

try:
    # Clear any leftover or planted temp first; O_EXCL then guarantees we
    # create the file ourselves rather than open something already at the name.
    try:
        os.unlink("status.json.tmp", dir_fd=dfd)
    except OSError:
        pass
    fd = os.open("status.json.tmp",
                 os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644,
                 dir_fd=dfd)
    try:
        # The app reads this back, so it is owned by the app account - set on
        # the descriptor we created, never on a name that could be a symlink.
        try:
            pw = pwd.getpwnam(user)
            os.fchown(fd, pw.pw_uid, pw.pw_gid)
        except KeyError:
            pass
        os.write(fd, payload.encode("utf-8"))
    finally:
        os.close(fd)
    # rename() replaces the target's directory entry - including a symlink the
    # app may have planted there - with our file, and does not follow it.
    os.replace("status.json.tmp", "status.json", src_dir_fd=dfd, dst_dir_fd=dfd)
finally:
    os.close(dfd)
PY
}

# Publishes a root-owned temp into the spool as a file the operator (and the
# app) can read, with the same no-follow, no-truncate-through create as say().
publish_log() {
    DMARC_SPOOL="$SPOOL" DMARC_USER="$USER_NAME" DMARC_SRC="$1" \
    python3 <<'PY' || true
import os, pwd, sys

spool = os.environ["DMARC_SPOOL"]
user = os.environ["DMARC_USER"]
src = os.environ["DMARC_SRC"]

try:
    dfd = os.open(spool, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
except OSError as ex:
    sys.stderr.write(f"update-agent: cannot publish the log: {ex}\n")
    raise SystemExit(0)

try:
    try:
        os.unlink("last-update.log", dir_fd=dfd)
    except OSError:
        pass
    fd = os.open("last-update.log",
                 os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644,
                 dir_fd=dfd)
    try:
        try:
            pw = pwd.getpwnam(user)
            os.fchown(fd, pw.pw_uid, pw.pw_gid)
        except KeyError:
            pass
        with open(src, "rb") as s:
            while True:
                chunk = s.read(65536)
                if not chunk:
                    break
                os.write(fd, chunk)
    finally:
        os.close(fd)
finally:
    os.close(dfd)
PY
}

# There must be something to act on. -e follows a symlink to its target; -L
# catches a symlink whose target is missing, so a planted dangling link is
# still consumed by the reader below rather than leaving the path unit firing
# in a loop.
[[ -e "$REQUEST" || -L "$REQUEST" ]] || exit 0

# Reading the request as root, from the directory the app account owns. The
# reader opens the spool with O_NOFOLLOW and the request relative to it, also
# with O_NOFOLLOW, then judges the OPEN FILE by fstat: a regular file owned by
# the app account, or nothing is read. A symlink (to any root-only file), a
# hardlink to one (whose owner is not the app account), a FIFO or a device is
# refused, not followed. Whatever is there is removed either way, so a refusal
# does not leave the path unit retriggering forever. This also survives an
# empty, truncated, or non-JSON body without a traceback that - under set -e,
# and after the request had been consumed - once killed the agent with no
# status written, leaving the page waiting for ever.
FIELDS="$(DMARC_SPOOL="$SPOOL" DMARC_USER="$USER_NAME" python3 <<'PY' || true
import json, os, pwd, stat, sys

spool = os.environ["DMARC_SPOOL"]
user = os.environ["DMARC_USER"]

def emit(version, by, code):
    # Tab-separated, flattened and truncated: the pieces are carried back on
    # one line, and a megabyte of junk must not become the status message.
    def clean(v, fallback=""):
        if not isinstance(v, str):
            return fallback
        return v.replace("\t", " ").replace("\n", " ").replace("\r", " ")[:200]
    sys.stdout.write(clean(version) + "\t" + clean(by, "unknown") + "\t" + code + "\n")

# The expected owner has to resolve to a uid before an owner check means
# anything. If the account is gone the machine is misconfigured, and acting on
# a request that cannot be attributed to it is exactly what must not happen.
try:
    want_uid = pwd.getpwnam(user).pw_uid
except KeyError:
    emit("", "", "nouser")
    raise SystemExit(0)

try:
    dfd = os.open(spool, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
except OSError:
    # The spool is not a real directory (or is gone). Nothing safe to do, and
    # deleting by a path whose parent is a symlink could remove a file
    # elsewhere as root, so this leaves it alone.
    emit("", "", "none")
    raise SystemExit(0)

def consume():
    # Removes the request name whatever is now there. unlink() operates on the
    # directory entry relative to the pinned spool, so a symlink is removed
    # rather than followed.
    try:
        os.unlink("requested.json", dir_fd=dfd)
    except OSError:
        pass

try:
    try:
        fd = os.open("requested.json",
                     os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dfd)
    except FileNotFoundError:
        emit("", "", "none")
        raise SystemExit(0)
    except OSError:
        # ELOOP: a symlink at the name. Consume the link and refuse.
        consume()
        emit("", "", "notfile")
        raise SystemExit(0)

    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            consume()
            emit("", "", "notfile")
            raise SystemExit(0)
        if st.st_uid != want_uid:
            # A hardlink to a root-only file lands here: it is a regular file,
            # but not owned by the app account, so it is not the app's request.
            consume()
            emit("", "", "notowner")
            raise SystemExit(0)
        # A request is a few hundred bytes; cap the read so a file that is
        # large by accident or on purpose cannot be pulled in whole.
        data = os.read(fd, 65536)
    finally:
        os.close(fd)

    consume()

    try:
        request = json.loads(data.decode("utf-8", "replace"))
        if not isinstance(request, dict):
            raise ValueError("not an object")
    except Exception:
        emit("", "", "unreadable")
        raise SystemExit(0)

    emit(request.get("Version"), request.get("RequestedBy"), "ok")
finally:
    os.close(dfd)
PY
)"

VERSION="$(printf '%s' "$FIELDS" | cut -f1)"
BY="$(printf '%s' "$FIELDS" | cut -f2)"
READABLE="$(printf '%s' "$FIELDS" | cut -f3)"

case "$READABLE" in
    ok)
        ;;
    none)
        # Nothing to act on after all - consumed by a previous run, or never a
        # real file. Silent: this is a normal race with the path unit, not a
        # fault worth a status.
        exit 0
        ;;
    notowner)
        say Failed "" \
            "The update request was ignored: it is not owned by the ${USER_NAME} account the app runs as, so it was not written by the app. Nothing was installed."
        exit 1
        ;;
    notfile)
        say Failed "" \
            "The update request was ignored: it is not a regular file. Nothing was installed."
        exit 1
        ;;
    nouser)
        say Failed "" \
            "Updates cannot be processed: the ${USER_NAME} account the app runs as does not exist on this machine. Nothing was installed."
        exit 1
        ;;
    *)
        say Failed "" \
            "The update request could not be read - it is not valid JSON. Nothing was installed. Press Install again."
        exit 1
        ;;
esac

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

# update.sh writes to the private temp (see LOGTMP above), which is then
# published into the spool safely. It is never handed a name in the app-owned
# directory to open with a shell redirection.
LOGTMP="$(mktemp)"
if DMARC_ROOT="$ROOT" DMARC_REPO="$REPO" DMARC_USER="$USER_NAME" \
   "${HERE}/update.sh" "$VERSION" > "$LOGTMP" 2>&1; then
    publish_log "$LOGTMP"
    stamp="$(grep -oP 'app-\K[0-9]{8}-[0-9]{6}' "$LOGTMP" | head -1 || true)"
    say Succeeded "$VERSION" "Updated to ${VERSION}. The previous install was kept, for rolling back." "$stamp"
else
    publish_log "$LOGTMP"
    # update.sh puts the old application back itself before failing, so the
    # service is already running again by the time this is written.
    say Failed "$VERSION" \
        "Installing ${VERSION} failed and the previous version was put back. See ${LOG}."
    exit 1
fi
