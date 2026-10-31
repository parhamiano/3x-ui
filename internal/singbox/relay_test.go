package singbox

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestSOCKSPortForInboundStaysInItsWindow(t *testing.T) {
	cases := []struct{ id, want int }{
		{1, 63801},
		{199, 63999},
		{200, 63801},
		{0, 63801},
	}
	for _, c := range cases {
		if got := SOCKSPortForInbound(c.id); got != c.want {
			t.Errorf("SOCKSPortForInbound(%d) = %d, want %d", c.id, got, c.want)
		}
	}
}

func TestSocksInboundSettingsKeepsXrayStatsPerEmail(t *testing.T) {
	raw, err := SocksInboundSettings([]string{"alice", "bob"}, "pw")
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"auth": "password", "udp": true,
		"accounts": []any{
			map[string]any{"user": "alice", "pass": "pw"},
			map[string]any{"user": "bob", "pass": "pw"},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("settings = %v, want %v", got, want)
	}
}
