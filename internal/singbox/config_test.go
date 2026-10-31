package singbox

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestRenderConfigRoutesEachUserThroughItsOwnRelayAccount(t *testing.T) {
	inst := Instance{
		Id: 7, Tag: "inbound-443", Listen: "::", Port: 443,
		Certificate: "/etc/ssl/a.crt", PrivateKey: "/etc/ssl/a.key", ServerName: "example.com",
		PaddingScheme: []string{"stop=8"},
		Users:         []User{{Email: "alice", Password: "pa"}, {Email: "bob", Password: "pb"}},
	}
	raw, err := renderConfig(inst, 63807, "relay-secret")
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("config is not JSON: %v\n%s", err, raw)
	}

	want := map[string]any{
		"log": map[string]any{"level": "warn", "timestamp": true},
		"inbounds": []any{map[string]any{
			"type": "anytls", "tag": "anytls-in", "listen": "::", "listen_port": float64(443),
			"users": []any{
				map[string]any{"name": "alice", "password": "pa"},
				map[string]any{"name": "bob", "password": "pb"},
			},
			"padding_scheme": []any{"stop=8"},
			"tls": map[string]any{
				"enabled": true, "server_name": "example.com",
				"certificate_path": "/etc/ssl/a.crt", "key_path": "/etc/ssl/a.key",
			},
		}},
		"outbounds": []any{
			relayOutbound("relay-0", "alice"),
			relayOutbound("relay-1", "bob"),
		},
		"route": map[string]any{
			"rules": []any{
				map[string]any{"auth_user": []any{"alice"}, "action": "route", "outbound": "relay-0"},
				map[string]any{"auth_user": []any{"bob"}, "action": "route", "outbound": "relay-1"},
				map[string]any{"inbound": []any{"anytls-in"}, "action": "reject"},
			},
		},
	}
	if !reflect.DeepEqual(got, want) {
		gotJSON, _ := json.MarshalIndent(got, "", "  ")
		wantJSON, _ := json.MarshalIndent(want, "", "  ")
		t.Fatalf("config mismatch\n got: %s\nwant: %s", gotJSON, wantJSON)
	}
}

func relayOutbound(tag, email string) map[string]any {
	return map[string]any{
		"type": "socks", "tag": tag, "server": "127.0.0.1", "server_port": float64(63807),
		"version": "5", "username": email, "password": "relay-secret",
	}
}

func TestRenderConfigInlinesPEMMaterial(t *testing.T) {
	inst := Instance{
		Listen: "::", Port: 443,
		Certificate: "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n",
		PrivateKey:  "-----BEGIN PRIVATE KEY-----\nBBB\n-----END PRIVATE KEY-----",
		Users:       []User{{Email: "a", Password: "p"}},
	}
	raw, err := renderConfig(inst, 63801, "x")
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Inbounds []struct {
			TLS map[string]any `json:"tls"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	tls := got.Inbounds[0].TLS
	if _, ok := tls["certificate_path"]; ok {
		t.Fatalf("PEM content must not be passed as a path: %v", tls)
	}
	wantCert := []any{"-----BEGIN CERTIFICATE-----", "AAA", "-----END CERTIFICATE-----"}
	if !reflect.DeepEqual(tls["certificate"], wantCert) {
		t.Fatalf("certificate = %#v, want %#v", tls["certificate"], wantCert)
	}
	wantKey := []any{"-----BEGIN PRIVATE KEY-----", "BBB", "-----END PRIVATE KEY-----"}
	if !reflect.DeepEqual(tls["key"], wantKey) {
		t.Fatalf("key = %#v, want %#v", tls["key"], wantKey)
	}
	if _, ok := tls["server_name"]; ok {
		t.Fatalf("an empty SNI must be omitted, got %v", tls["server_name"])
	}
}
