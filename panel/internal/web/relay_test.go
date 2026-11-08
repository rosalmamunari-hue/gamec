package web

import (
	"html"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func relayForm1(a *client, password string) url.Values {
	return url.Values{"csrf": {a.csrf()}, "name": {"hk-relay"}, "host": {"198.51.100.30"}, "port": {"31000"}, "ssh_port": {"22"},
		"target": {"203.0.113.50:21443"}, "tag": {"v0.2.0"}, "from": {"198.51.100.9"}, "password": {password}}
}

func TestANodeThroughARelay(t *testing.T) {
	e, a, f, _ := autoEnv(t)
	cid := e.cl.ID

	// 1. the relay, in one click
	if st, body, _ := a.get("/cluster/" + cid + "/relay/new"); st != 200 || !strings.Contains(body, "新中转") {
		t.Fatalf("form: %d", st)
	}
	st, body, _ := a.post("/cluster/"+cid+"/relay/new", relayForm1(a, f.password), nil)
	if st != http.StatusSeeOther {
		t.Fatalf("relay install: %d %s", st, firstMsg(body))
	}
	if !strings.Contains(f.gotIn, "-pass -listen :31000 -backend 203.0.113.50:21443 -allow-file /opt/gamec-relay/allow") ||
		!strings.Contains(f.gotIn, strings.Repeat("d", 64)) || strings.Contains(f.gotIn, secretHex) {
		t.Fatal("the relay script is not what it should be")
	}
	rs := e.st.Snapshot().RelaysOf(cid)
	if len(rs) != 1 || rs[0].Addr() != "198.51.100.30:31000" || rs[0].HostKey != fp1 {
		t.Fatalf("stored: %+v", rs)
	}
	rl := rs[0]
	if e.f.count("relay-allow") != 1 { // the management account is tried at once
		t.Fatal("the relay's management was not tried")
	}

	// 2. a node through it: the node forwards to the relay, and the relay lets it in first
	if _, body, _ := a.get("/cluster/" + cid + "/node/new"); !strings.Contains(body, "经中转「hk-relay」") {
		t.Fatal("the wizard does not offer the relay")
	}
	st, body, _ = a.post("/cluster/"+cid+"/node/new/auto", with(wizardForm1(), "csrf", a.csrf(), "password", f.password, "relay", rl.ID), nil)
	if st != http.StatusSeeOther {
		t.Fatalf("node install: %d %s", st, firstMsg(body))
	}
	if !strings.Contains(f.gotIn, "-origin 198.51.100.30:31000") {
		t.Fatal("the node does not forward to the relay")
	}
	if !strings.Contains(e.f.cmds[len(e.f.cmds)-1], "relay-allow 203.0.113.21") {
		t.Fatalf("the relay was not told about the node: %v", e.f.cmds)
	}
	ns := e.st.Snapshot().NodesOf(cid)
	if len(ns) != 1 || ns[0].RelayID != rl.ID {
		t.Fatalf("stored: %+v", ns)
	}
	if c := e.st.Snapshot().Cluster(cid); c.Origin == "198.51.100.30:31000" {
		t.Error("the relay's address must not become the channel's origin")
	}
	_, page, _ := a.get("/cluster/" + cid)
	if !strings.Contains(page, "经中转「hk-relay」") || !strings.Contains(page, "198.51.100.30:31000") {
		t.Error("the channel page does not show the relay")
	}

	// 3. a relay in use cannot be deleted; deleting the node takes it off the relay's list
	if st, _, _ := a.post("/cluster/"+cid+"/relay/"+rl.ID+"/delete", url.Values{"csrf": {a.csrf()}}, nil); st != http.StatusBadRequest {
		t.Fatalf("deleted while in use: %d", st)
	}
	a.post("/cluster/"+cid+"/node/"+ns[0].ID+"/delete", url.Values{"csrf": {a.csrf()}}, nil)
	if last := e.f.cmds[len(e.f.cmds)-1]; !strings.HasSuffix(last, "relay-allow") {
		t.Fatalf("the node is still allowed: %q", last)
	}
	if st, _, _ := a.post("/cluster/"+cid+"/relay/"+rl.ID+"/delete", url.Values{"csrf": {a.csrf()}}, nil); st != http.StatusSeeOther {
		t.Fatalf("delete: %d", st)
	}
	if len(e.st.Snapshot().Relays) != 0 {
		t.Fatal("not deleted")
	}
	_, audit, _ := a.get("/audit")
	if !strings.Contains(audit, "relay-install") || strings.Contains(audit, f.password) {
		t.Error("the install is audited, without the password")
	}
}

func TestARelayIsNotSavedWhenSomethingIsWrong(t *testing.T) {
	e, a, f, _ := autoEnv(t)
	cid := e.cl.ID
	post := func(v url.Values) (int, string) {
		st, body, _ := a.post("/cluster/"+cid+"/relay/new", v, nil)
		return st, html.UnescapeString(body)
	}
	if st, _ := post(relayForm1(a, "wrong")); st != http.StatusBadGateway {
		t.Errorf("wrong password: %d", st)
	}
	if st, _ := post(with(relayForm1(a, f.password), "target", "nowhere")); st != http.StatusBadRequest {
		t.Errorf("bad target: %d", st)
	}
	f.printed = fp2
	if st, _ := post(relayForm1(a, f.password)); st != http.StatusConflict {
		t.Errorf("another machine: %d", st)
	}
	f.printed = fp1
	*e.hostKey = fp2 // the network shows another key afterwards
	if st, _ := post(relayForm1(a, f.password)); st != http.StatusConflict {
		t.Errorf("a different key over the network: %d", st)
	}
	if n := len(e.st.Snapshot().Relays); n != 0 {
		t.Fatalf("%d relays saved", n)
	}
	// a node cannot go through a relay of another channel or one that does not exist
	st, _, _ := a.post("/cluster/"+cid+"/node/new/script", with(wizardForm1(), "csrf", a.csrf(), "relay", "deadbeef"), nil)
	if st != http.StatusBadRequest {
		t.Errorf("unknown relay: %d", st)
	}
}
