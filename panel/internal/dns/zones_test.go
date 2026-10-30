package dns

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCloudflareZonesListsTheDomainsATokenCanManage(t *testing.T) {
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		if r.URL.Path != "/zones" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, `{"success":true,"result":[{"name":"Example.com"},{"name":"b.uk"}]}`)
	}))
	defer srv.Close()
	zs, err := CloudflareZones(context.Background(), " tok123 \n", Options{BaseURL: srv.URL})
	if err != nil || len(zs) != 2 || zs[0] != "example.com" || zs[1] != "b.uk" {
		t.Fatalf("%v %v", zs, err)
	}
	if auth != "Bearer tok123" {
		t.Fatalf("auth header %q", auth)
	}
}

func TestCloudflareZonesReportsABadToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"success":false,"errors":[{"code":6003,"message":"Invalid request headers"}]}`)
	}))
	defer srv.Close()
	_, err := CloudflareZones(context.Background(), "nope", Options{BaseURL: srv.URL})
	if err == nil || !strings.Contains(err.Error(), "6003") {
		t.Fatalf("%v", err)
	}
}
