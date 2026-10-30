package ops

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

var targetRe = regexp.MustCompile(`^(\[[0-9a-fA-F:.]{2,45}\]|[A-Za-z0-9][A-Za-z0-9.-]{0,252}):[0-9]{1,5}$`)

// PrepareJumpScript returns a script an administrator runs once, as root, on the machine that will be the
// panel's egress (jump) host. It creates an account that cannot open a shell or run a command and whose key
// may only forward TCP connections to the listed node addresses (sshd's permitopen). The panel's real
// address then never reaches the nodes: they see this machine.
//
// targets are the host:port pairs the panel needs to reach: each node's service port and its SSH port.
// from, if not empty, restricts the key to those source addresses (the panel's own address).
func PrepareJumpScript(pubLine string, targets []string, from string) (string, error) {
	if !pubLineRe.MatchString(pubLine) {
		return "", errors.New("that is not an ed25519 public key line")
	}
	if len(targets) == 0 {
		return "", errors.New("there are no node addresses to allow yet; add nodes first")
	}
	if len(targets) > 400 {
		return "", errors.New("too many addresses")
	}
	seen := map[string]bool{}
	var uniq []string
	for _, t := range targets {
		if !targetRe.MatchString(t) {
			return "", fmt.Errorf("%q is not a host:port address", t)
		}
		if !seen[t] {
			seen[t] = true
			uniq = append(uniq, t)
		}
	}
	sort.Strings(uniq)
	opts := []string{"restrict", "port-forwarding", `command="/bin/false"`}
	if from != "" {
		if !fromRe.MatchString(from) {
			return "", errors.New("the source address list contains characters that are not allowed")
		}
		opts = append(opts, `from="`+from+`"`)
	}
	for _, t := range uniq {
		opts = append(opts, `permitopen="`+t+`"`)
	}
	return fmt.Sprintf(`#!/bin/sh
# Make this machine the gamec panel's egress (jump) host.
# Run once, as root, on the machine that will carry the panel's connections to the nodes. Safe to run again
# (run it again whenever a node is added, so the list of allowed addresses stays current). Read it first.
set -eu

[ "$(id -u)" = 0 ] || { echo "run this as root" >&2; exit 1; }

# 1. an account with no password, no shell and no commands
id gamec-jump >/dev/null 2>&1 || useradd --system --create-home --home-dir /var/lib/gamec-jump --shell /usr/sbin/nologin gamec-jump
install -d -m 0700 -o gamec-jump -g gamec-jump /var/lib/gamec-jump/.ssh

# 2. only the panel's key; it can do nothing but forward connections to these addresses
printf '%%s\n' '%s %s' > /var/lib/gamec-jump/.ssh/authorized_keys
chown gamec-jump:gamec-jump /var/lib/gamec-jump/.ssh/authorized_keys
chmod 0600 /var/lib/gamec-jump/.ssh/authorized_keys

# 3. sshd must allow forwarding for this to work
if command -v sshd >/dev/null 2>&1; then
  fwd=$(sshd -T 2>/dev/null | awk '/^allowtcpforwarding /{print $2}')
  case "$fwd" in yes|all|"") ;; *) echo "WARNING: sshd has AllowTcpForwarding $fwd; set it to yes (or add a Match User gamec-jump block) or the panel cannot use this host" >&2 ;; esac
fi

echo "done. This machine's SSH host keys. The panel uses the ED25519 one; compare it with what the panel shows:"
for f in /etc/ssh/ssh_host_*_key.pub; do [ -f "$f" ] && ssh-keygen -lf "$f"; done
[ -f /etc/ssh/ssh_host_ed25519_key.pub ] || echo "WARNING: this machine has no ED25519 host key; the panel cannot connect until one exists (ssh-keygen -A)" >&2
`, strings.Join(opts, ","), pubLine), nil
}
