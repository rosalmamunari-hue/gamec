package ops

import (
	"errors"
	"fmt"
	"regexp"
)

var (
	pubLineRe = regexp.MustCompile(`^ssh-ed25519 [A-Za-z0-9+/=]{60,120}( [A-Za-z0-9._-]{1,40})?$`)
	urlRe     = regexp.MustCompile(`^https://[A-Za-z0-9._:/-]{3,200}$`)
	fromRe    = regexp.MustCompile(`^[0-9a-fA-F:.,/*!-]{1,200}$`)
)

// PrepareScript returns a shell script an administrator runs once, as root, on a server. It creates the
// restricted account the panel logs in as, lets only the panel's key use it, installs the nodectl program
// (checked against its checksum) and allows that one program through sudo. The panel never needs a root
// password, and a leaked panel key can do no more than nodectl allows.
//
// from, if not empty, restricts the key to those source addresses (the panel's own address).
func PrepareScript(pubLine, nodectlURL, nodectlSHA, from string) (string, error) {
	steps, err := manageSteps(pubLine, nodectlURL, nodectlSHA, from)
	if err != nil {
		return "", err
	}
	return `#!/bin/sh
# Prepare this server so the gamec control panel can manage the edge node on it.
# Run once, as root. It is safe to run again. Read it first: this is everything it does.
set -eu

[ "$(id -u)" = 0 ] || { echo "run this as root" >&2; exit 1; }
command -v systemctl >/dev/null || { echo "this needs systemd" >&2; exit 1; }
command -v sudo >/dev/null || { echo "install sudo first" >&2; exit 1; }
command -v curl >/dev/null || { echo "install curl first" >&2; exit 1; }
command -v sha256sum >/dev/null || { echo "sha256sum is missing" >&2; exit 1; }
` + steps + `
echo "done. This server's SSH host keys. The panel uses the ED25519 one; compare it with what the panel shows:"
for f in /etc/ssh/ssh_host_*_key.pub; do [ -f "$f" ] && ssh-keygen -lf "$f"; done
[ -f /etc/ssh/ssh_host_ed25519_key.pub ] || echo "WARNING: this server has no ED25519 host key; the panel cannot connect until one exists (ssh-keygen -A)" >&2
`, nil
}

// manageSteps is the part of a script that sets up management by the panel (see PrepareScript).
func manageSteps(pubLine, nodectlURL, nodectlSHA, from string) (string, error) {
	if !pubLineRe.MatchString(pubLine) {
		return "", errors.New("that is not an ed25519 public key line")
	}
	if !urlRe.MatchString(nodectlURL) {
		return "", errors.New("the nodectl address must be a plain https URL")
	}
	if !shaRe.MatchString(nodectlSHA) {
		return "", errors.New("the nodectl checksum must be 64 lowercase hex characters")
	}
	opts := "restrict,no-pty"
	if from != "" {
		if !fromRe.MatchString(from) {
			return "", errors.New("the source address list contains characters that are not allowed")
		}
		opts += `,from="` + from + `"`
	}
	return fmt.Sprintf(`
# 1. a restricted account for the panel, no password
id gamec-ops >/dev/null 2>&1 || useradd --system --create-home --home-dir /var/lib/gamec-ops --shell /bin/sh gamec-ops
install -d -m 0700 -o gamec-ops -g gamec-ops /var/lib/gamec-ops/.ssh
install -d -m 0750 -o gamec-ops -g gamec-ops /var/lib/gamec-ops/incoming

# 2. only the panel's key may log in; no port forwarding, no terminal
printf '%%s
' '%s %s' > /var/lib/gamec-ops/.ssh/authorized_keys
chown gamec-ops:gamec-ops /var/lib/gamec-ops/.ssh/authorized_keys
chmod 0600 /var/lib/gamec-ops/.ssh/authorized_keys

# 3. the one program that account may run as root, checked against its checksum
tmp=$(mktemp)
curl -fsSL '%s' -o "$tmp"
echo '%s  '"$tmp" | sha256sum -c -
install -m 0755 -o root -g root "$tmp" /usr/local/sbin/gamec-nodectl
rm -f "$tmp"

# 4. sudo may run that program and nothing else
printf 'gamec-ops ALL=(root) NOPASSWD: /usr/local/sbin/gamec-nodectl
' > /etc/sudoers.d/gamec-ops.tmp
chmod 0440 /etc/sudoers.d/gamec-ops.tmp
visudo -c -f /etc/sudoers.d/gamec-ops.tmp >/dev/null
mv /etc/sudoers.d/gamec-ops.tmp /etc/sudoers.d/gamec-ops
`, opts, pubLine, nodectlURL, nodectlSHA), nil
}

// Describe is a one-line summary of what an upgrade result means, for the audit log.
func (r UpgradeResult) String() string {
	switch {
	case r.Already:
		return r.Node + ": already on " + short(r.After)
	case r.Installed:
		return fmt.Sprintf("%s: %s -> %s %s", r.Node, short(r.Before), short(r.After), r.Label)
	case r.RolledBack:
		return fmt.Sprintf("%s: ROLLED BACK (%s)", r.Node, r.Detail)
	}
	return r.Node + ": " + r.Detail
}

func short(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	if sha == "" {
		return "unknown"
	}
	return sha
}
