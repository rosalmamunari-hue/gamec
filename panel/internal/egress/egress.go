// Package egress decides how the panel opens every connection to a node. If an egress (jump) host is
// configured, everything goes through it and the nodes see its address; otherwise connections are made
// directly. A configured egress is never bypassed: if it cannot be used the connection fails.
package egress

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"golang.org/x/crypto/ssh"

	"gamec/panel/internal/sshx"
	"gamec/panel/internal/store"
)

// ErrNotConfirmed: an egress host is configured but its SSH host key was never confirmed.
var ErrNotConfirmed = errors.New("the egress host is configured but its host key has not been confirmed; nothing is sent until it is")

// Jumper is what Egress needs from a jump connection (sshx.Jump satisfies it).
type Jumper interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
	Close() error
}

type Egress struct {
	Store *store.Store
	// Signer returns the panel's SSH key (it is in the vault, so this fails while the vault is sealed).
	Signer func() (ssh.Signer, error)
	// NewJump builds a jump connection; nil means sshx.NewJump. Tests replace it.
	NewJump func(sshx.Target) Jumper

	mu   sync.Mutex
	jump Jumper
	sig  string
}

// Configured says whether connections are being sent through a jump host.
func (e *Egress) Configured() bool { return e.Store.Snapshot().Egress != nil }

func (e *Egress) jumper(cfg *store.Egress) (Jumper, error) {
	sig := cfg.Addr + "|" + cfg.User + "|" + cfg.HostKey
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.jump != nil && e.sig == sig {
		return e.jump, nil
	}
	signer, err := e.Signer()
	if err != nil {
		return nil, fmt.Errorf("the panel's SSH key is not available: %w", err)
	}
	if e.jump != nil {
		e.jump.Close() // the configuration changed
	}
	mk := e.NewJump
	if mk == nil {
		mk = func(t sshx.Target) Jumper { return sshx.NewJump(t) }
	}
	e.jump = mk(sshx.Target{Addr: cfg.Addr, User: cfg.User, HostKey: cfg.HostKey, Signer: signer})
	e.sig = sig
	return e.jump, nil
}

// DialContext opens a connection to addr the way the configuration says. It is a sshx.DialFunc and a
// shieldclient.DialFunc.
func (e *Egress) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	cfg := e.Store.Snapshot().Egress
	if cfg == nil {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	if cfg.HostKey == "" {
		return nil, ErrNotConfirmed
	}
	j, err := e.jumper(cfg)
	if err != nil {
		return nil, err // never "just connect directly": that would show the panel's address
	}
	return j.DialContext(ctx, network, addr)
}

// Close drops the jump connection.
func (e *Egress) Close() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.jump != nil {
		e.jump.Close()
		e.jump, e.sig = nil, ""
	}
}
