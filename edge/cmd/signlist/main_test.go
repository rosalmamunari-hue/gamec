package main

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
)

func TestDohHandlerShape(t *testing.T) {
	recs := []string{"gs1:1/1:abcdefghij"}
	srv := httptest.NewServer(dohHandler(recs))
	defer srv.Close()
	resp, err := srv.Client().Get(srv.URL + "/?name=x.example&type=TXT")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		Status int
		Answer []struct {
			Type int
			Data string
		}
	}
	json.NewDecoder(resp.Body).Decode(&out)
	if out.Status != 0 || len(out.Answer) != 1 || out.Answer[0].Type != 16 ||
		out.Answer[0].Data != `"gs1:1/1:a" "bcdefghij"` {
		t.Fatalf("unexpected DoH reply: %+v", out)
	}
}
