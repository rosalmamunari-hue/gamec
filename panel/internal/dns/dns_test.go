package dns

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------- shared scenarios

// fakeDNS is a fake provider server: the tests seed it, call ReplaceTXT, and look at what is left.
type fakeDNS interface {
	Seed(ours, others []string)
	Ours() []string
	Others() []string
	Writes() int
}

func sorted(s []string) []string { c := append([]string(nil), s...); sort.Strings(c); return c }

func equalSets(a, b []string) bool {
	return strings.Join(sorted(a), "|") == strings.Join(sorted(b), "|")
}

func runScenarios(t *testing.T, mk func(t *testing.T) (Provider, fakeDNS)) {
	ctx := context.Background()
	const zone, name = "example.com", "_gs.example.com"
	v := func(n ...int) []string {
		var o []string
		for _, i := range n {
			o = append(o, fmt.Sprintf("gs1:%d/3:data%d", i, i))
		}
		return o
	}
	others := []string{"v=spf1 -all", "google-site-verification=abc"}

	t.Run("publishes into an empty name", func(t *testing.T) {
		p, f := mk(t)
		if err := p.ReplaceTXT(ctx, zone, name, v(1, 2, 3)); err != nil {
			t.Fatal(err)
		}
		if !equalSets(f.Ours(), v(1, 2, 3)) {
			t.Fatalf("got %v", f.Ours())
		}
	})
	t.Run("replaces a list with a different one of the same size", func(t *testing.T) {
		p, f := mk(t)
		f.Seed([]string{"gs1:1/3:old1", "gs1:2/3:old2", "gs1:3/3:old3"}, nil)
		if err := p.ReplaceTXT(ctx, zone, name, v(1, 2, 3)); err != nil {
			t.Fatal(err)
		}
		if !equalSets(f.Ours(), v(1, 2, 3)) {
			t.Fatalf("got %v", f.Ours())
		}
	})
	t.Run("shrinks 3 records to 2", func(t *testing.T) {
		p, f := mk(t)
		f.Seed(v(1, 2, 3), nil)
		want := []string{"gs1:1/2:new1", "gs1:2/2:new2"}
		if err := p.ReplaceTXT(ctx, zone, name, want); err != nil {
			t.Fatal(err)
		}
		if !equalSets(f.Ours(), want) {
			t.Fatalf("got %v", f.Ours())
		}
	})
	t.Run("grows 2 records to 3", func(t *testing.T) {
		p, f := mk(t)
		f.Seed([]string{"gs1:1/2:a", "gs1:2/2:b"}, nil)
		if err := p.ReplaceTXT(ctx, zone, name, v(1, 2, 3)); err != nil {
			t.Fatal(err)
		}
		if !equalSets(f.Ours(), v(1, 2, 3)) {
			t.Fatalf("got %v", f.Ours())
		}
	})
	t.Run("never touches other TXT records on the same name", func(t *testing.T) {
		p, f := mk(t)
		f.Seed([]string{"gs1:1/1:old"}, others)
		if err := p.ReplaceTXT(ctx, zone, name, v(1, 2, 3)); err != nil {
			t.Fatal(err)
		}
		if !equalSets(f.Others(), others) {
			t.Fatalf("other records changed: %v", f.Others())
		}
		if !equalSets(f.Ours(), v(1, 2, 3)) {
			t.Fatalf("got %v", f.Ours())
		}
	})
	t.Run("sends no writes when nothing changed", func(t *testing.T) {
		p, f := mk(t)
		f.Seed(v(1, 2, 3), others)
		before := f.Writes()
		if err := p.ReplaceTXT(ctx, zone, name, v(1, 2, 3)); err != nil {
			t.Fatal(err)
		}
		if f.Writes() != before {
			t.Fatalf("%d needless write(s)", f.Writes()-before)
		}
	})
	t.Run("rejects a name outside the zone", func(t *testing.T) {
		p, _ := mk(t)
		if err := p.ReplaceTXT(ctx, zone, "_gs.other.org", v(1)); err == nil {
			t.Fatal("accepted")
		}
	})
}

// ---------------------------------------------------------------- fake Spaceship

type ssRec struct{ Type, Name, Value string }

type fakeSpaceship struct {
	srv       *httptest.Server
	mu        sync.Mutex
	recs      []ssRec
	writes    int
	failPuts  int // fail this many PUTs before working
	badAuth   bool
	sawHeader bool
}

func newFakeSpaceship(t *testing.T) *fakeSpaceship {
	f := &fakeSpaceship{}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeSpaceship) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("X-API-Key") != "key" || r.Header.Get("X-API-Secret") != "secret" {
		f.badAuth = true
		http.Error(w, `{"detail":"unauthorized"}`, 401)
		return
	}
	f.sawHeader = true
	if !strings.HasPrefix(r.URL.Path, "/api/v1/dns/records/example.com") {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case "GET":
		take, _ := strconv.Atoi(r.URL.Query().Get("take"))
		skip, _ := strconv.Atoi(r.URL.Query().Get("skip"))
		if take > 2 {
			take = 2 // the fake serves small pages so paging is exercised
		}
		end := skip + take
		if end > len(f.recs) {
			end = len(f.recs)
		}
		items := []map[string]any{}
		if skip < len(f.recs) {
			for _, x := range f.recs[skip:end] {
				items = append(items, map[string]any{"type": x.Type, "name": x.Name, "value": x.Value, "ttl": 60})
			}
		}
		json.NewEncoder(w).Encode(map[string]any{"items": items, "total": len(f.recs)})
	case "PUT":
		if f.failPuts > 0 {
			f.failPuts--
			http.Error(w, `{"detail":"temporary failure"}`, 500)
			return
		}
		var body struct {
			Force bool
			Items []struct{ Type, Name, Value string }
		}
		json.NewDecoder(r.Body).Decode(&body)
		for _, it := range body.Items {
			f.recs = append(f.recs, ssRec{it.Type, it.Name, it.Value})
		}
		f.writes++
		w.WriteHeader(204)
	case "DELETE":
		var body []struct{ Type, Name, Value string }
		json.NewDecoder(r.Body).Decode(&body)
		for _, d := range body {
			for i, x := range f.recs {
				if x.Type == d.Type && x.Name == d.Name && x.Value == d.Value {
					f.recs = append(f.recs[:i], f.recs[i+1:]...)
					break
				}
			}
		}
		f.writes++
		w.WriteHeader(204)
	default:
		http.Error(w, "method", 405)
	}
}

func (f *fakeSpaceship) Seed(ours, others []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.recs = []ssRec{{"A", "_gs", "1.2.3.4"}, {"TXT", "elsewhere", "gs1:1/1:not-ours-by-name"}}
	for _, v := range ours {
		f.recs = append(f.recs, ssRec{"TXT", "_gs", v})
	}
	for _, v := range others {
		f.recs = append(f.recs, ssRec{"TXT", "_gs", v})
	}
}
func (f *fakeSpaceship) valuesWhere(want func(string) bool) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, x := range f.recs {
		if x.Type == "TXT" && x.Name == "_gs" && want(x.Value) {
			out = append(out, x.Value)
		}
	}
	return out
}
func (f *fakeSpaceship) Ours() []string { return f.valuesWhere(ours) }
func (f *fakeSpaceship) Others() []string {
	return f.valuesWhere(func(v string) bool { return !ours(v) })
}
func (f *fakeSpaceship) Writes() int { f.mu.Lock(); defer f.mu.Unlock(); return f.writes }

func TestSpaceship(t *testing.T) {
	runScenarios(t, func(t *testing.T) (Provider, fakeDNS) {
		f := newFakeSpaceship(t)
		return newSpaceship("key", "secret", Options{BaseURL: f.srv.URL, Sleep: func(time.Duration) {}}), f
	})
}

func TestSpaceshipSendsCredentialsAndRejectsBadOnes(t *testing.T) {
	f := newFakeSpaceship(t)
	good := newSpaceship("key", "secret", Options{BaseURL: f.srv.URL})
	if err := good.ReplaceTXT(context.Background(), "example.com", "_gs.example.com", []string{"gs1:1/1:x"}); err != nil || !f.sawHeader {
		t.Fatalf("good credentials failed: %v", err)
	}
	bad := newSpaceship("key", "WRONG", Options{BaseURL: f.srv.URL})
	if err := bad.ReplaceTXT(context.Background(), "example.com", "_gs.example.com", []string{"gs1:1/1:y"}); err == nil {
		t.Fatal("wrong secret accepted")
	}
}

func TestSpaceshipRestoresTheOldListWhenTheNewOneCannotBeWritten(t *testing.T) {
	f := newFakeSpaceship(t)
	old := []string{"gs1:1/2:old1", "gs1:2/2:old2"}
	f.Seed(old, nil)
	f.failPuts = 3 // every attempt to add the new records fails; the restore after that works
	p := newSpaceship("key", "secret", Options{BaseURL: f.srv.URL, Sleep: func(time.Duration) {}})
	err := p.ReplaceTXT(context.Background(), "example.com", "_gs.example.com", []string{"gs1:1/1:new"})
	if err == nil {
		t.Fatal("a failed write must be reported")
	}
	if !equalSets(f.Ours(), old) {
		t.Fatalf("the apps are left without a list: %v", f.Ours())
	}
}

func TestSpaceshipPagesThroughManyRecords(t *testing.T) {
	f := newFakeSpaceship(t)
	f.Seed([]string{"gs1:1/3:a", "gs1:2/3:b", "gs1:3/3:c"}, []string{"x", "y", "z"}) // 3+3+2 records, pages of 2
	p := newSpaceship("key", "secret", Options{BaseURL: f.srv.URL})
	if err := p.ReplaceTXT(context.Background(), "example.com", "_gs.example.com", []string{"gs1:1/1:only"}); err != nil {
		t.Fatal(err)
	}
	if !equalSets(f.Ours(), []string{"gs1:1/1:only"}) || len(f.Others()) != 3 {
		t.Fatalf("ours=%v others=%v", f.Ours(), f.Others())
	}
}

// ---------------------------------------------------------------- fake Cloudflare

type cfRec struct {
	ID, Type, Name, Content string
}

type fakeCloudflare struct {
	srv    *httptest.Server
	mu     sync.Mutex
	recs   []cfRec
	nextID int
	writes int
	token  string
}

func newFakeCloudflare(t *testing.T) *fakeCloudflare {
	f := &fakeCloudflare{token: "tok"}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeCloudflare) reply(w http.ResponseWriter, result any) {
	json.NewEncoder(w).Encode(map[string]any{"success": true, "errors": []any{}, "result": result})
}

func (f *fakeCloudflare) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer "+f.token {
		w.WriteHeader(403)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "errors": []map[string]any{{"code": 9109, "message": "Invalid access token"}}})
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/client/v4")
	switch {
	case r.Method == "GET" && path == "/zones":
		if r.URL.Query().Get("name") == "example.com" {
			f.reply(w, []map[string]any{{"id": "zone1", "name": "example.com"}})
		} else {
			f.reply(w, []any{})
		}
	case r.Method == "GET" && path == "/zones/zone1/dns_records":
		out := []map[string]any{}
		for _, x := range f.recs {
			if x.Type == r.URL.Query().Get("type") && x.Name == r.URL.Query().Get("name") {
				out = append(out, map[string]any{"id": x.ID, "type": x.Type, "name": x.Name, "content": `"` + x.Content + `"`, "ttl": 60})
			}
		}
		f.reply(w, out)
	case r.Method == "POST" && path == "/zones/zone1/dns_records":
		var b cfRecord
		json.NewDecoder(r.Body).Decode(&b)
		f.nextID++
		f.recs = append(f.recs, cfRec{fmt.Sprintf("r%d", f.nextID), b.Type, b.Name, strings.Trim(b.Content, `"`)})
		f.writes++
		f.reply(w, map[string]any{"id": f.recs[len(f.recs)-1].ID})
	case r.Method == "PUT" && strings.HasPrefix(path, "/zones/zone1/dns_records/"):
		id := strings.TrimPrefix(path, "/zones/zone1/dns_records/")
		var b cfRecord
		json.NewDecoder(r.Body).Decode(&b)
		for i := range f.recs {
			if f.recs[i].ID == id {
				f.recs[i].Content = strings.Trim(b.Content, `"`)
			}
		}
		f.writes++
		f.reply(w, map[string]any{"id": id})
	case r.Method == "DELETE" && strings.HasPrefix(path, "/zones/zone1/dns_records/"):
		id := strings.TrimPrefix(path, "/zones/zone1/dns_records/")
		for i := range f.recs {
			if f.recs[i].ID == id {
				f.recs = append(f.recs[:i], f.recs[i+1:]...)
				break
			}
		}
		f.writes++
		f.reply(w, map[string]any{"id": id})
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeCloudflare) Seed(ours, others []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.recs = nil
	for _, v := range append(append([]string(nil), ours...), others...) {
		f.nextID++
		f.recs = append(f.recs, cfRec{fmt.Sprintf("r%d", f.nextID), "TXT", "_gs.example.com", v})
	}
}
func (f *fakeCloudflare) valuesWhere(want func(string) bool) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, x := range f.recs {
		if x.Type == "TXT" && want(x.Content) {
			out = append(out, x.Content)
		}
	}
	return out
}
func (f *fakeCloudflare) Ours() []string { return f.valuesWhere(ours) }
func (f *fakeCloudflare) Others() []string {
	return f.valuesWhere(func(v string) bool { return !ours(v) })
}
func (f *fakeCloudflare) Writes() int { f.mu.Lock(); defer f.mu.Unlock(); return f.writes }

func TestCloudflare(t *testing.T) {
	runScenarios(t, func(t *testing.T) (Provider, fakeDNS) {
		f := newFakeCloudflare(t)
		return newCloudflare("tok", Options{BaseURL: f.srv.URL + "/client/v4"}), f
	})
}

func TestCloudflareUpdatesInPlaceWhenTheCountIsUnchanged(t *testing.T) {
	f := newFakeCloudflare(t)
	f.Seed([]string{"gs1:1/2:a", "gs1:2/2:b"}, nil)
	p := newCloudflare("tok", Options{BaseURL: f.srv.URL + "/client/v4"})
	ids := []string{f.recs[0].ID, f.recs[1].ID}
	if err := p.ReplaceTXT(context.Background(), "example.com", "_gs.example.com", []string{"gs1:1/2:c", "gs1:2/2:d"}); err != nil {
		t.Fatal(err)
	}
	if f.recs[0].ID != ids[0] || f.recs[1].ID != ids[1] {
		t.Fatal("records were deleted and recreated; there would be a moment with no list")
	}
}

func TestCloudflareReportsAPIErrors(t *testing.T) {
	f := newFakeCloudflare(t)
	p := newCloudflare("WRONG", Options{BaseURL: f.srv.URL + "/client/v4"})
	err := p.ReplaceTXT(context.Background(), "example.com", "_gs.example.com", []string{"gs1:1/1:x"})
	if err == nil || !strings.Contains(err.Error(), "Invalid access token") {
		t.Fatalf("got %v", err)
	}
}

func TestCloudflareZoneThatTheTokenCannotSee(t *testing.T) {
	f := newFakeCloudflare(t)
	p := newCloudflare("tok", Options{BaseURL: f.srv.URL + "/client/v4"})
	err := p.ReplaceTXT(context.Background(), "other.org", "_gs.other.org", []string{"gs1:1/1:x"})
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("got %v", err)
	}
}

// ---------------------------------------------------------------- fake Aliyun

type aliRec struct{ ID, RR, Type, Value string }

type fakeAliyun struct {
	srv       *httptest.Server
	mu        sync.Mutex
	recs      []aliRec
	nextID    int
	writes    int
	secret    string
	badSigs   int
	nonces    map[string]bool
	reusedNon bool
}

func newFakeAliyun(t *testing.T) *fakeAliyun {
	f := &fakeAliyun{secret: "sec", nonces: map[string]bool{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	return f
}

// verify recomputes the signature with a different encoding routine than the provider uses.
func (f *fakeAliyun) verify(q url.Values) bool {
	got := q.Get("Signature")
	keys := []string{}
	for k := range q {
		if k != "Signature" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	enc := func(s string) string {
		e := url.QueryEscape(s)
		e = strings.ReplaceAll(e, "+", "%20")
		e = strings.ReplaceAll(e, "*", "%2A")
		return strings.ReplaceAll(e, "%7E", "~")
	}
	parts := []string{}
	for _, k := range keys {
		parts = append(parts, enc(k)+"="+enc(q.Get(k)))
	}
	toSign := "GET&%2F&" + enc(strings.Join(parts, "&"))
	m := hmac.New(sha1.New, []byte(f.secret+"&"))
	m.Write([]byte(toSign))
	return got == base64.StdEncoding.EncodeToString(m.Sum(nil))
}

func (f *fakeAliyun) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	q := r.URL.Query()
	if !f.verify(q) {
		f.badSigs++
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(map[string]string{"Code": "IncompleteSignature", "Message": "The request signature does not conform to Aliyun standards."})
		return
	}
	if f.nonces[q.Get("SignatureNonce")] {
		f.reusedNon = true
	}
	f.nonces[q.Get("SignatureNonce")] = true
	if _, err := time.Parse("2006-01-02T15:04:05Z", q.Get("Timestamp")); err != nil || q.Get("SignatureMethod") != "HMAC-SHA1" ||
		q.Get("SignatureVersion") != "1.0" || q.Get("Version") != "2015-01-09" || q.Get("AccessKeyId") != "id" {
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(map[string]string{"Code": "InvalidParameter", "Message": "bad common parameters"})
		return
	}
	switch q.Get("Action") {
	case "DescribeDomainRecords":
		out := []map[string]string{}
		for _, x := range f.recs {
			if x.RR == q.Get("RRKeyWord") && x.Type == q.Get("TypeKeyWord") {
				out = append(out, map[string]string{"RecordId": x.ID, "RR": x.RR, "Type": x.Type, "Value": x.Value})
			}
		}
		json.NewEncoder(w).Encode(map[string]any{"DomainRecords": map[string]any{"Record": out}})
	case "AddDomainRecord":
		f.nextID++
		f.recs = append(f.recs, aliRec{strconv.Itoa(f.nextID), q.Get("RR"), q.Get("Type"), q.Get("Value")})
		f.writes++
		json.NewEncoder(w).Encode(map[string]string{"RecordId": strconv.Itoa(f.nextID)})
	case "UpdateDomainRecord":
		for i := range f.recs {
			if f.recs[i].ID == q.Get("RecordId") {
				f.recs[i].Value = q.Get("Value")
			}
		}
		f.writes++
		json.NewEncoder(w).Encode(map[string]string{"RecordId": q.Get("RecordId")})
	case "DeleteDomainRecord":
		for i := range f.recs {
			if f.recs[i].ID == q.Get("RecordId") {
				f.recs = append(f.recs[:i], f.recs[i+1:]...)
				break
			}
		}
		f.writes++
		json.NewEncoder(w).Encode(map[string]string{"RecordId": q.Get("RecordId")})
	default:
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(map[string]string{"Code": "InvalidAction", "Message": q.Get("Action")})
	}
}

func (f *fakeAliyun) Seed(ours, others []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.recs = nil
	for _, v := range append(append([]string(nil), ours...), others...) {
		f.nextID++
		f.recs = append(f.recs, aliRec{strconv.Itoa(f.nextID), "_gs", "TXT", v})
	}
}
func (f *fakeAliyun) valuesWhere(want func(string) bool) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, x := range f.recs {
		if x.Type == "TXT" && want(x.Value) {
			out = append(out, x.Value)
		}
	}
	return out
}
func (f *fakeAliyun) Ours() []string   { return f.valuesWhere(ours) }
func (f *fakeAliyun) Others() []string { return f.valuesWhere(func(v string) bool { return !ours(v) }) }
func (f *fakeAliyun) Writes() int      { f.mu.Lock(); defer f.mu.Unlock(); return f.writes }

func TestAliyun(t *testing.T) {
	runScenarios(t, func(t *testing.T) (Provider, fakeDNS) {
		f := newFakeAliyun(t)
		return newAliyun("id", "sec", Options{BaseURL: f.srv.URL}), f
	})
}

func TestAliyunSignatureIsAcceptedAndWrongSecretIsNot(t *testing.T) {
	f := newFakeAliyun(t)
	ok := newAliyun("id", "sec", Options{BaseURL: f.srv.URL})
	if err := ok.ReplaceTXT(context.Background(), "example.com", "_gs.example.com", []string{"gs1:1/1:v=1+2*3~4 /="}); err != nil {
		t.Fatalf("a correctly signed request, with characters that need escaping, was refused: %v", err)
	}
	if f.badSigs != 0 {
		t.Fatalf("%d bad signatures", f.badSigs)
	}
	bad := newAliyun("id", "WRONG", Options{BaseURL: f.srv.URL})
	err := bad.ReplaceTXT(context.Background(), "example.com", "_gs.example.com", []string{"gs1:1/1:z"})
	if err == nil || !strings.Contains(err.Error(), "IncompleteSignature") {
		t.Fatalf("got %v", err)
	}
}

func TestAliyunNeverReusesANonce(t *testing.T) {
	f := newFakeAliyun(t)
	p := newAliyun("id", "sec", Options{BaseURL: f.srv.URL})
	for i := 0; i < 5; i++ {
		p.ReplaceTXT(context.Background(), "example.com", "_gs.example.com", []string{fmt.Sprintf("gs1:1/1:v%d", i)})
	}
	if f.reusedNon {
		t.Fatal("a nonce was reused; the service would reject replays")
	}
}

func TestAliyunPercentEncode(t *testing.T) {
	cases := map[string]string{"abc-_.~": "abc-_.~", "a b": "a%20b", "a*b": "a%2Ab", "/": "%2F", "=&+": "%3D%26%2B", "é": "%C3%A9"}
	for in, want := range cases {
		if got := percentEncode(in); got != want {
			t.Errorf("percentEncode(%q) = %q, want %q", in, got, want)
		}
	}
}

// ---------------------------------------------------------------- the rest

func TestManualProviderAlwaysAsksForHands(t *testing.T) {
	p, err := New("manual", "", nil, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.ReplaceTXT(context.Background(), "example.com", "_gs.example.com", []string{"gs1:1/1:x"}); err != ErrManual {
		t.Fatalf("got %v", err)
	}
}

func TestNewReadsCredentialsFromTheVaultNames(t *testing.T) {
	asked := []string{}
	creds := func(name string) (string, error) { asked = append(asked, name); return "v", nil }
	for prov, want := range map[string][]string{
		"spaceship":  {"dns/main/api_key", "dns/main/api_secret"},
		"cloudflare": {"dns/main/api_token"},
		"aliyun":     {"dns/main/access_key_id", "dns/main/access_key_secret"},
	} {
		asked = nil
		if _, err := New(prov, "main", creds, Options{}); err != nil {
			t.Fatalf("%s: %v", prov, err)
		}
		if strings.Join(asked, ",") != strings.Join(want, ",") {
			t.Errorf("%s asked for %v, want %v", prov, asked, want)
		}
	}
	if _, err := New("route66", "main", creds, Options{}); err == nil {
		t.Error("unknown provider accepted")
	}
	empty := func(string) (string, error) { return "", nil }
	if _, err := New("cloudflare", "main", empty, Options{}); err == nil {
		t.Error("an empty credential was accepted")
	}
}

func TestRelAndDiff(t *testing.T) {
	for _, c := range []struct {
		fqdn, zone, want string
		bad              bool
	}{
		{"_gs.example.com", "example.com", "_gs", false},
		{"example.com", "example.com", "@", false},
		{"A.B.Example.com.", "example.com", "a.b", false},
		{"_gs.other.org", "example.com", "", true},
		{"notexample.com", "example.com", "", true},
	} {
		got, err := rel(c.fqdn, c.zone)
		if (err != nil) != c.bad || got != c.want {
			t.Errorf("rel(%q,%q) = %q,%v", c.fqdn, c.zone, got, err)
		}
	}
	stale, missing := diff([]string{"a", "b", "b"}, []string{"b", "c"})
	if !equalSets(stale, []string{"a", "b"}) || !equalSets(missing, []string{"c"}) {
		t.Errorf("stale=%v missing=%v", stale, missing)
	}
}
