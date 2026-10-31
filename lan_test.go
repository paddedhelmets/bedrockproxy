package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/df-mc/go-nethernet/discovery"
)

func TestLanServerDataMirrorsStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/join" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"name":"Village Workshop","protocol":2225,"version":"1.26.61","level":"VillageWorkshop","players":1,"maxPlayers":2,"gameType":1}`))
	}))
	defer srv.Close()

	data, err := lanServerData(srv.URL, "online", 0, "")
	if err != nil {
		t.Fatal(err)
	}
	want := discovery.ServerData{
		ServerName:        "Village Workshop",
		Protocol:          2225,
		Version:           "1.26.61",
		LevelName:         "VillageWorkshop",
		PlayerCount:       1,
		MaxPlayerCount:    2,
		GameType:          1,
		AcceptsOnlineAuth: true,
		ConnectionType:    4,
	}
	if data != want {
		t.Fatalf("data = %+v, want %+v", data, want)
	}
}

func TestLanServerDataOverridesSkipFetch(t *testing.T) {
	data, err := lanServerData("http://127.0.0.1:1", "both", 2225, "1.26.61")
	if err != nil {
		t.Fatal(err)
	}
	if data.Protocol != 2225 || data.Version != "1.26.61" || !data.AcceptsSelfSignedAuth || !data.AcceptsOnlineAuth {
		t.Fatalf("unexpected overrides: %+v", data)
	}
}

func TestLanServerDataRejectsBadInput(t *testing.T) {
	if _, err := lanServerData("http://127.0.0.1:1", "nope", 0, ""); err == nil {
		t.Fatal("expected auth rejection")
	}
	if _, err := lanServerData("http://127.0.0.1:1", "online", 2225, ""); err == nil {
		t.Fatal("expected partial-override rejection")
	}
	unreachable := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer unreachable.Close()
	if _, err := lanServerData(unreachable.URL, "online", 0, ""); err == nil {
		t.Fatal("expected status failure")
	}
}
