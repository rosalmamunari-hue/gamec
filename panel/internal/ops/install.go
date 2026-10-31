package ops

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

var (
	secretRe   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	hostnameRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)
	unitNameRe = regexp.MustCompile(`^gamec-edge[a-z0-9-]{0,40}$`)
)

// Program is one released program a script downloads: where from, and the checksum it must have.
type Program struct {
	URL    string
	SHA256 string
}

// InstallParams is everything the node installer needs. Every value ends up in a shell script that runs as
// root, so each one is checked against a strict pattern before it is used.
type InstallParams struct {
	Unit    string // systemd unit, like gamec-edge
	Host    string // the node's public IP or name, for its certificate
	Port    int    // where players connect
	Origin  string // host:port of the game server the node forwards to
	Secret  string // the cluster's token secret (64 hex characters)
	Edge    Program
	Gencert Program
	Nodectl Program
	PubLine string // the panel's SSH public key
	From    string // where the panel connects from (empty: anywhere)
}

func checkHostPort(hp string) error {
	host, port, err := net.SplitHostPort(hp)
	if err != nil {
		return err
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return errors.New("bad port")
	}
	if net.ParseIP(host) == nil && !hostnameRe.MatchString(host) {
		return errors.New("bad host")
	}
	return nil
}

// InstallScript returns a script that turns a fresh Linux server into a node of the cluster and lets the
// panel manage it: it installs the edge program (checked against its checksum), makes the node's TLS key on
// the server itself (the key never leaves it), stores the cluster secret in a file only the service can read,
// runs the node as an unprivileged systemd service, opens the port in ufw if ufw is on, sets up the panel's
// restricted management account, and finally prints the two fingerprints the administrator compares in the
// panel. Running it again keeps the TLS key, so the node's pin does not change.
func InstallScript(p InstallParams) (string, error) {
	switch {
	case !unitNameRe.MatchString(p.Unit):
		return "", errors.New("the service name must look like gamec-edge or gamec-edge-<name>")
	case net.ParseIP(p.Host) == nil && !hostnameRe.MatchString(p.Host):
		return "", fmt.Errorf("%q is not an IP address or host name", p.Host)
	case p.Port < 1 || p.Port > 65535:
		return "", errors.New("the port must be 1-65535")
	case checkHostPort(p.Origin) != nil:
		return "", fmt.Errorf("the origin %q is not host:port", p.Origin)
	case !secretRe.MatchString(p.Secret):
		return "", errors.New("the cluster secret is not 64 hex characters")
	}
	for _, prog := range []Program{p.Edge, p.Gencert} {
		if !urlRe.MatchString(prog.URL) || !shaRe.MatchString(prog.SHA256) {
			return "", errors.New("a download address or checksum is not valid")
		}
	}
	manage, err := manageSteps(p.PubLine, p.Nodectl.URL, p.Nodectl.SHA256, p.From)
	if err != nil {
		return "", err
	}
	dir := "/opt/" + p.Unit
	r := strings.NewReplacer("@UNIT@", p.Unit, "@DIR@", dir, "@HOST@", p.Host, "@PORT@", strconv.Itoa(p.Port),
		"@ORIGIN@", p.Origin, "@SECRET@", p.Secret,
		"@EDGE_URL@", p.Edge.URL, "@EDGE_SHA@", p.Edge.SHA256, "@GENCERT_URL@", p.Gencert.URL, "@GENCERT_SHA@", p.Gencert.SHA256)
	return r.Replace(installHead) + manage + r.Replace(installTail), nil
}

const installHead = `#!/bin/sh
# Install a gamec edge node on this server and let the panel manage it.
# Run once, as root, on the NEW server. It is safe to run again. Read it first: this is everything it does.
# It contains the cluster's secret: do not paste it anywhere else.
set -eu

[ "$(id -u)" = 0 ] || { echo "run this as root" >&2; exit 1; }
for c in systemctl curl sha256sum sudo visudo ssh-keygen useradd; do
  command -v "$c" >/dev/null || { echo "missing $c: install it first" >&2; exit 1; }
done
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
fetch() { # url name sha256
  curl -fsSL "$1" -o "$work/$2"
  echo "$3  $work/$2" | sha256sum -c - >/dev/null || { echo "$2 does not match its published checksum; stopping" >&2; exit 1; }
}
fetch '@EDGE_URL@' edge '@EDGE_SHA@'
fetch '@GENCERT_URL@' gencert '@GENCERT_SHA@'

# A. the node program, run by an account that can do nothing else
id gamec-edge >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin gamec-edge
install -d -m 0750 -o root -g gamec-edge '@DIR@'
install -m 0755 -o root -g root "$work/edge" '@DIR@/edge'

# B. the node's TLS key, made here and never copied anywhere (kept if it exists, so the pin stays the same)
chmod 0755 "$work/gencert"
pin=$("$work/gencert" -host '@HOST@' -out '@DIR@/tls' | sed -n 's/^pin: *//p')
chown -R root:gamec-edge '@DIR@/tls'
chmod 0750 '@DIR@/tls'
chmod 0640 '@DIR@/tls/key.pem'

# C. the cluster secret, readable by the service only
( umask 077; printf '%s' '@SECRET@' > '@DIR@/secret.new' )
chown root:gamec-edge '@DIR@/secret.new'
chmod 0640 '@DIR@/secret.new'
mv '@DIR@/secret.new' '@DIR@/secret'

# D. the service
cat > '/etc/systemd/system/@UNIT@.service' <<'UNIT'
[Unit]
Description=gamec edge node
After=network-online.target
Wants=network-online.target

[Service]
User=gamec-edge
Group=gamec-edge
ExecStart=@DIR@/edge -listen :@PORT@ -origin @ORIGIN@ -cert @DIR@/tls/cert.pem -key @DIR@/tls/key.pem -secret-file @DIR@/secret
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
systemctl enable '@UNIT@' >/dev/null 2>&1
systemctl restart '@UNIT@'
if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q 'Status: active'; then
  ufw allow '@PORT@/tcp' >/dev/null
fi
`

const installTail = `
# E. check that it runs, and print what to compare in the panel
sleep 2
if ! systemctl is-active --quiet '@UNIT@'; then
  journalctl -u '@UNIT@' -n 30 --no-pager >&2 || true
  echo "the node program did not start; see the lines above" >&2
  exit 1
fi
echo
echo "=============================================================="
echo " Installed. Compare these two lines with what the panel shows:"
echo "   node pin:  $pin"
if [ -f /etc/ssh/ssh_host_ed25519_key.pub ]; then
  echo "   SSH key:   $(ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub | awk '{print $2}')"
else
  echo "   SSH key:   MISSING (run ssh-keygen -A, then this script again)"
fi
echo "=============================================================="
`

// Checksums reads a release's SHA256SUMS.txt, without downloading the programs themselves.
func (r *Releases) Checksums(ctx context.Context, tag string) (map[string]string, error) {
	if !strings.HasPrefix(r.Base, "https://") && !strings.HasPrefix(r.Base, "http://127.0.0.1") {
		return nil, errors.New("the release address must be https")
	}
	if !tagRe.MatchString(tag) {
		return nil, fmt.Errorf("%q is not a release tag like v0.1.0", tag)
	}
	sums, err := r.get(ctx, strings.TrimRight(r.Base, "/")+"/"+tag+"/SHA256SUMS.txt", 1<<20)
	if err != nil {
		return nil, fmt.Errorf("the checksum list: %w", err)
	}
	out := map[string]string{}
	for _, line := range strings.Split(string(sums), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && shaRe.MatchString(strings.ToLower(f[0])) {
			out[strings.TrimPrefix(f[1], "*")] = strings.ToLower(f[0])
		}
	}
	return out, nil
}
