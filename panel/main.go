// panel is the control panel for the game shield: it watches the nodes, keeps each cluster's signed node
// list published in DNS, and renews it before it expires. See docs/PANEL.md.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"gamec/edge/shieldlist"
	"gamec/panel/internal/audit"
	"gamec/panel/internal/auth"
	"gamec/panel/internal/dns"
	"gamec/panel/internal/engine"
	"gamec/panel/internal/store"
	"gamec/panel/internal/vault"
	"gamec/panel/internal/web"
)

const usage = `panel <command> [flags]

  init            create the data directory and the encrypted vault
  adduser         add a user (prints the code to enrol in an authenticator app)
  serve           run the panel
  import-cluster  bring an existing signing key and token secret in as a cluster
  set-secret      store a secret in the vault (value read from the terminal or stdin)
  get-secret      print a secret from the vault (for example a cluster's token secret)
  verify-audit    check that the audit log's hash chain is intact

Every command takes -data DIR (default $PANEL_DATA or ./data).
The vault passphrase is asked for on the terminal, or read from the file named by $PANEL_PASSPHRASE_FILE.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmds := map[string]func([]string) error{
		"init": cmdInit, "adduser": cmdAddUser, "serve": cmdServe, "import-cluster": cmdImportCluster,
		"set-secret": cmdSetSecret, "get-secret": cmdGetSecret, "verify-audit": cmdVerifyAudit,
	}
	run, ok := cmds[os.Args[1]]
	if !ok {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err := run(os.Args[2:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// ---------------------------------------------------------------- shared helpers

type paths struct{ dir, vault, users, state, audit string }

func dataFlag(fs *flag.FlagSet) *string {
	def := os.Getenv("PANEL_DATA")
	if def == "" {
		def = "./data"
	}
	return fs.String("data", def, "data directory")
}

func pathsOf(dir string) paths {
	return paths{dir, filepath.Join(dir, "vault.json"), filepath.Join(dir, "users.json"),
		filepath.Join(dir, "state.json"), filepath.Join(dir, "audit.log")}
}

// one reader for the whole process: a fresh one per prompt would swallow input that was piped in
var stdin = bufio.NewReader(os.Stdin)

func prompt(label string) (string, error) {
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		fmt.Fprint(os.Stderr, label)
		b, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		return string(b), err
	}
	line, err := stdin.ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func passphrase(label string) (string, error) {
	if f := os.Getenv("PANEL_PASSPHRASE_FILE"); f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			return "", err
		}
		return strings.TrimRight(string(b), "\r\n"), nil
	}
	return prompt(label)
}

func confirmed(label string) (string, error) {
	a, err := prompt(label)
	if err != nil {
		return "", err
	}
	b, err := prompt("Again: ")
	if err != nil {
		return "", err
	}
	if a != b {
		return "", errors.New("the two entries differ")
	}
	return a, nil
}

func openVault(p paths) (*vault.Vault, error) {
	v, err := vault.Open(p.vault)
	if err != nil {
		return nil, fmt.Errorf("%w (run `panel init` first)", err)
	}
	pw, err := passphrase("Vault passphrase: ")
	if err != nil {
		return nil, err
	}
	if err := v.Unseal(pw); err != nil {
		return nil, err
	}
	return v, nil
}

// ---------------------------------------------------------------- commands

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	data := dataFlag(fs)
	fs.Parse(args)
	p := pathsOf(*data)
	if err := os.MkdirAll(p.dir, 0o700); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "The vault passphrase protects every signing key and credential. It is never stored.")
	fmt.Fprintln(os.Stderr, "Write it down somewhere safe: if it is lost the vault cannot be opened and the keys are gone.")
	pw, err := confirmed("New vault passphrase (12+ characters): ")
	if err != nil {
		return err
	}
	if _, err := vault.Create(p.vault, pw); err != nil {
		return err
	}
	fmt.Println("created", p.vault)
	fmt.Println("next: panel adduser -name <you> -role admin")
	return nil
}

func cmdAddUser(args []string) error {
	fs := flag.NewFlagSet("adduser", flag.ExitOnError)
	data := dataFlag(fs)
	name := fs.String("name", "", "user name")
	role := fs.String("role", "viewer", "admin or viewer")
	fs.Parse(args)
	p := pathsOf(*data)
	if err := os.MkdirAll(p.dir, 0o700); err != nil {
		return err
	}
	users, err := auth.OpenUsers(p.users)
	if err != nil {
		return err
	}
	pw, err := confirmed(fmt.Sprintf("Password for %s (12+ characters): ", *name))
	if err != nil {
		return err
	}
	secret, err := users.Add(*name, auth.Role(*role), pw, time.Now())
	if err != nil {
		return err
	}
	fmt.Printf("user %q (%s) created\n\n", *name, *role)
	fmt.Println("Add this to an authenticator app (Google Authenticator, Authy, 1Password, ...):")
	fmt.Println("  secret:", secret)
	fmt.Println("  link:  ", auth.TOTPURI("gamec panel", *name, secret))
	fmt.Println("\nThe code is needed at every sign-in. This is the only time the secret is shown.")
	return nil
}

func cmdImportCluster(args []string) error {
	fs := flag.NewFlagSet("import-cluster", flag.ExitOnError)
	data := dataFlag(fs)
	name := fs.String("name", "", "cluster name")
	origin := fs.String("origin", "", "origin the nodes forward to (for your notes)")
	provider := fs.String("provider", "manual", "manual | spaceship | cloudflare | aliyun")
	zone := fs.String("zone", "", "registered domain, e.g. example.com")
	dnsName := fs.String("dns-name", "", "record name, e.g. _gs.example.com")
	credRef := fs.String("cred-ref", "", "credentials name (dns/<name>/... in the vault)")
	keyFile := fs.String("signing-key-file", "", "file holding the existing signing key (signlist -gen-key output)")
	secretFile := fs.String("node-secret-file", "", "file holding the existing token secret (the nodes' -secret)")
	valid := fs.Int("valid-days", 30, "how long each signed list is valid")
	renew := fs.Int("renew-days", 10, "renew this many days before expiry")
	fs.Parse(args)
	p := pathsOf(*data)

	rawKey, err := os.ReadFile(*keyFile)
	if err != nil {
		return err
	}
	key, err := shieldlist.ParsePrivateKeyB64(string(rawKey))
	if err != nil {
		return fmt.Errorf("signing key: %w", err)
	}
	rawSecret, err := os.ReadFile(*secretFile)
	if err != nil {
		return err
	}
	secret := strings.TrimSpace(string(rawSecret))
	if secret == "" {
		return errors.New("the token secret file is empty")
	}
	v, err := openVault(p)
	if err != nil {
		return err
	}
	st, err := store.Open(p.state)
	if err != nil {
		return err
	}
	c := &store.Cluster{ID: store.NewID(), Name: *name, Origin: *origin, ValidDays: *valid, RenewBeforeDays: *renew,
		PublicKey: shieldlist.PublicKeyB64(&key.PublicKey), Created: time.Now(),
		Targets: []store.DNSTarget{{Provider: *provider, Zone: strings.ToLower(*zone), Name: strings.ToLower(*dnsName), CredRef: *credRef}}}
	if err := st.Mutate(func(s *store.State) error { s.Clusters = append(s.Clusters, c); return nil }); err != nil {
		return err
	}
	enc, _ := shieldlist.PrivateKeyB64(key)
	if err := v.Set(engine.SigningKeyName(c.ID), enc); err != nil {
		return err
	}
	if err := v.Set(engine.NodeSecretName(c.ID), secret); err != nil {
		return err
	}
	fmt.Printf("cluster %q imported (id %s)\npublic key (unchanged, so existing apps keep working): %s\n", c.Name, c.ID, c.PublicKey)
	fmt.Println("Now delete the key and secret files from this machine, add the nodes in the panel, and publish by hand once.")
	return nil
}

func cmdSetSecret(args []string) error {
	fs := flag.NewFlagSet("set-secret", flag.ExitOnError)
	data := dataFlag(fs)
	name := fs.String("name", "", "vault name, e.g. dns/main/api_token")
	fs.Parse(args)
	if *name == "" {
		return errors.New("-name is required")
	}
	v, err := openVault(pathsOf(*data))
	if err != nil {
		return err
	}
	val, err := prompt("Value (not shown): ")
	if err != nil {
		return err
	}
	if val == "" {
		return errors.New("empty value")
	}
	if err := v.Set(*name, val); err != nil {
		return err
	}
	fmt.Println("stored", *name)
	return nil
}

func cmdGetSecret(args []string) error {
	fs := flag.NewFlagSet("get-secret", flag.ExitOnError)
	data := dataFlag(fs)
	name := fs.String("name", "", "vault name, e.g. cluster/<id>/node_secret")
	fs.Parse(args)
	p := pathsOf(*data)
	v, err := openVault(p)
	if err != nil {
		return err
	}
	val, ok, err := v.Get(*name)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("no secret named %s", *name)
	}
	if al, err := audit.Open(p.audit); err == nil {
		al.Append(audit.Entry{User: "cli", Action: "get-secret", Detail: *name, OK: true})
	}
	fmt.Println(val)
	return nil
}

func cmdVerifyAudit(args []string) error {
	fs := flag.NewFlagSet("verify-audit", flag.ExitOnError)
	data := dataFlag(fs)
	fs.Parse(args)
	n, err := audit.Verify(pathsOf(*data).audit)
	if err != nil {
		return fmt.Errorf("the audit log is NOT intact: %w", err)
	}
	fmt.Printf("audit log intact: %d entries\n", n)
	return nil
}

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	data := dataFlag(fs)
	listen := fs.String("listen", "127.0.0.1:8080", "address to listen on")
	secure := fs.Bool("secure", false, "the panel is reached over HTTPS (Secure cookies, HSTS)")
	trustProxy := fs.Bool("trust-proxy", false, "take the client address from X-Forwarded-For (only behind your own proxy)")
	probeEvery := fs.Duration("probe-interval", time.Minute, "how often every node is probed")
	tick := fs.Duration("tick", 30*time.Second, "how often automatic publishing decides")
	autoUnseal := fs.Bool("unseal-at-start", false, "unseal with $PANEL_PASSPHRASE_FILE at start (otherwise unseal in the browser)")
	fs.Parse(args)
	p := pathsOf(*data)

	v, err := vault.Open(p.vault)
	if err != nil {
		return fmt.Errorf("%w (run `panel init` first)", err)
	}
	if *autoUnseal {
		pw, err := passphrase("Vault passphrase: ")
		if err != nil {
			return err
		}
		if err := v.Unseal(pw); err != nil {
			return err
		}
	}
	users, err := auth.OpenUsers(p.users)
	if err != nil {
		return err
	}
	if users.Count() == 0 {
		fmt.Fprintln(os.Stderr, "warning: there are no users yet; run `panel adduser -role admin`")
	}
	st, err := store.Open(p.state)
	if err != nil {
		return err
	}
	al, err := audit.Open(p.audit)
	if err != nil {
		return err
	}
	if host, _, err := net.SplitHostPort(*listen); err == nil {
		if ip := net.ParseIP(host); (ip == nil || !ip.IsLoopback()) && !*secure {
			fmt.Fprintln(os.Stderr, "warning: listening on a non-loopback address without -secure; put the panel behind HTTPS (see docs/PANEL.md)")
		}
	}

	creds := func(name string) (string, error) { s, _, err := v.Get(name); return s, err }
	mon := engine.NewMonitor(engine.RealProber{})
	pub := &engine.Publisher{Vault: v, Store: st, Audit: al, Verifier: engine.DefaultVerifier(),
		Provider: func(t store.DNSTarget) (dns.Provider, error) {
			return dns.New(t.Provider, t.CredRef, creds, dns.Options{})
		}}
	sched := engine.NewScheduler(pub, mon, st)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go mon.Run(ctx, func() []*store.Node { return st.Snapshot().Nodes }, *probeEvery)
	go sched.Run(ctx, *tick)

	srv := &web.Server{Users: users, Sessions: auth.NewSessions(30*time.Minute, 12*time.Hour), Vault: v, Store: st,
		Audit: al, AuditPath: p.audit, Mon: mon, Pub: pub, Sched: sched, Secure: *secure, TrustProxy: *trustProxy}
	hs := &http.Server{Addr: *listen, Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout: 30 * time.Second, WriteTimeout: 10 * time.Minute, IdleTimeout: 2 * time.Minute, MaxHeaderBytes: 16 << 10}
	go func() {
		<-ctx.Done()
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		hs.Shutdown(c)
	}()
	al.Append(audit.Entry{User: "system", Action: "start", Detail: "listening on " + *listen + fmt.Sprintf(" sealed=%v", v.Sealed()), OK: true})
	fmt.Printf("panel listening on %s (vault %s)\n", *listen, map[bool]string{true: "SEALED, unseal it in the browser", false: "unsealed"}[v.Sealed()])
	if err := hs.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
