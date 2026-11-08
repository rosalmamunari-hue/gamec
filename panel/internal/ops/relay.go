package ops

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"gamec/panel/internal/store"
)

// RelayParams is everything the relay installer needs; like InstallParams, every value is checked before it
// goes into the script.
type RelayParams struct {
	Port    int      // where the nodes connect
	Target  string   // host:port connections are passed to (the origin or the anti-DDoS front)
	Allow   []string // the nodes that may connect at first (IPs)
	Realip  Program
	Nodectl Program
	PubLine string // the panel's SSH public key
	From    string // where the panel connects from (empty: anywhere)
}

// RelayScript returns a script that turns a fresh Linux server into a relay: realip -pass as an unprivileged
// systemd service (gamec-relay) that passes the nodes' connections on unchanged, an allow file only the panel
// changes (through nodectl relay-allow), and the panel's restricted management account. It prints the
// server's SSH fingerprint at the end. It is safe to run again.
func RelayScript(p RelayParams) (string, error) {
	switch {
	case p.Port < 1024 || p.Port > 65535:
		return "", errors.New("the relay port must be 1024-65535")
	case checkHostPort(p.Target) != nil:
		return "", fmt.Errorf("the target %q is not host:port", p.Target)
	case !urlRe.MatchString(p.Realip.URL) || !shaRe.MatchString(p.Realip.SHA256):
		return "", errors.New("the realip download address or checksum is not valid")
	}
	allow, err := relayAllowArgs(p.Allow)
	if err != nil {
		return "", err
	}
	manage, err := manageSteps(p.PubLine, p.Nodectl.URL, p.Nodectl.SHA256, p.From)
	if err != nil {
		return "", err
	}
	r := strings.NewReplacer("@PORT@", strconv.Itoa(p.Port), "@TARGET@", p.Target, "@ALLOW@", strings.Join(allow, " "),
		"@REALIP_URL@", p.Realip.URL, "@REALIP_SHA@", p.Realip.SHA256)
	return r.Replace(relayHead) + manage + r.Replace(relayTail), nil
}

const relayHead = `#!/bin/sh
# Install a gamec relay on this server (nodes -> this relay -> origin) and let the panel manage it.
# Run once, as root, on the NEW server. It is safe to run again. Read it first: this is everything it does.
set -eu

[ "$(id -u)" = 0 ] || { echo "run this as root" >&2; exit 1; }
for c in systemctl curl sha256sum sudo visudo ssh-keygen useradd; do
  command -v "$c" >/dev/null || { echo "missing $c: install it first" >&2; exit 1; }
done
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
curl -fsSL '@REALIP_URL@' -o "$work/realip"
echo "@REALIP_SHA@  $work/realip" | sha256sum -c - >/dev/null || { echo "realip does not match its published checksum; stopping" >&2; exit 1; }
chmod 0755 "$work/realip"
"$work/realip" -h 2>&1 | grep -q -- '-pass' || { echo "this release's realip cannot relay (no -pass): pick release v0.5.5 or later" >&2; exit 1; }

# A. the relay program, run by an account that can do nothing else
id gamec-relay >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin gamec-relay
install -d -m 0755 -o root -g root /opt/gamec-relay
install -m 0755 -o root -g root "$work/realip" /opt/gamec-relay/realip
`

const relayTail = `
# B. who may connect: only the nodes the panel names (it rewrites this list when nodes come and go)
/usr/local/sbin/gamec-nodectl relay-allow @ALLOW@ >/dev/null || { echo "this release's nodectl cannot manage a relay: pick release v0.5.5 or later" >&2; exit 1; }

# C. the service
cat > /etc/systemd/system/gamec-relay.service <<'UNIT'
[Unit]
Description=gamec relay (nodes -> origin)
After=network-online.target
Wants=network-online.target

[Service]
User=gamec-relay
Group=gamec-relay
ExecStart=/opt/gamec-relay/realip -pass -listen :@PORT@ -backend @TARGET@ -allow-file /opt/gamec-relay/allow
Restart=always
RestartSec=2
LimitNOFILE=65536
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable gamec-relay >/dev/null 2>&1
systemctl restart gamec-relay
if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q 'Status: active'; then
  ufw allow '@PORT@/tcp' >/dev/null
fi

# D. check that it runs, and print what the panel compares
sleep 2
if ! systemctl is-active --quiet gamec-relay; then
  journalctl -u gamec-relay -n 30 --no-pager >&2 || true
  echo "the relay did not start; see the lines above" >&2
  exit 1
fi
echo
echo "=============================================================="
echo " Relay installed: nodes connect to port @PORT@, it passes them to @TARGET@."
if [ -f /etc/ssh/ssh_host_ed25519_key.pub ]; then
  echo "   SSH key:   $(ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub | awk '{print $2}')"
else
  echo "   SSH key:   MISSING (run ssh-keygen -A, then this script again)"
fi
echo "=============================================================="
`

// relayAllowArgs checks a list of node addresses and returns them in their plain form.
func relayAllowArgs(ips []string) ([]string, error) {
	if len(ips) > 1000 {
		return nil, errors.New("at most 1000 nodes per relay")
	}
	seen := map[string]bool{}
	var out []string
	for _, s := range ips {
		a, err := netip.ParseAddr(strings.TrimSpace(s))
		if err != nil || a.Zone() != "" {
			return nil, fmt.Errorf("%q is not an IP address", s)
		}
		if k := a.Unmap().String(); !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	return out, nil
}

// RelayAllow sets the nodes that may use a relay (all others are refused).
func (o *Ops) RelayAllow(ctx context.Context, relay store.Node, ips []string) error {
	args, err := relayAllowArgs(ips)
	if err != nil {
		return err
	}
	r, err := o.session(ctx, relay)
	if err != nil {
		return err
	}
	defer r.Close()
	_, err = call(ctx, r, "gamec-edge", append([]string{"relay-allow"}, args...)...)
	return err
}
