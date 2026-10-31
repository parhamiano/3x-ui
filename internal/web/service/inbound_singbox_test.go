package service

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/singbox"
	"github.com/mhsanaei/3x-ui/v3/internal/xray"
)

const anytlsTestSettings = `{"certificate":"/etc/ssl/a.crt","private_key":"/etc/ssl/a.key","sni":"example.com","clients":[` +
	`{"email":"alice@anytls.test","password":"pa","enable":true},` +
	`{"email":"bob@anytls.test","password":"pb","enable":false}]}`

func setupSingboxDB(t *testing.T) {
	t.Helper()
	setupConflictDB(t)
	t.Setenv("XUI_BIN_FOLDER", t.TempDir())
}

// xray-core has no anytls protocol: emitting the row itself would make Xray refuse
// the whole config, so only the loopback relay may appear under its tag.
func TestGetXrayConfig_ServesAnyTLSThroughItsRelayOnly(t *testing.T) {
	setupSingboxDB(t)
	in := &model.Inbound{
		Tag: "in-8443-anytls", Enable: true, Port: 8443, Protocol: model.AnyTLS,
		Settings: anytlsTestSettings,
	}
	if _, _, err := (&InboundService{}).AddInbound(in); err != nil {
		t.Fatalf("AddInbound: %v", err)
	}

	cfg, err := (&XrayService{}).GetXrayConfig()
	if err != nil {
		t.Fatalf("GetXrayConfig: %v", err)
	}
	var relays []xray.InboundConfig
	for _, ic := range cfg.InboundConfigs {
		if ic.Tag == "in-8443-anytls" {
			relays = append(relays, ic)
		}
	}
	if len(relays) != 1 {
		t.Fatalf("inbounds tagged in-8443-anytls = %d, want exactly the relay", len(relays))
	}
	relay := relays[0]
	if relay.Protocol != "socks" || relay.Port != singbox.SOCKSPortForInbound(in.Id) || string(relay.Listen) != `"127.0.0.1"` {
		t.Fatalf("relay = %s %s:%d, want socks 127.0.0.1:%d", relay.Protocol, relay.Listen, relay.Port, singbox.SOCKSPortForInbound(in.Id))
	}
	var settings struct {
		Accounts []struct {
			User string `json:"user"`
			Pass string `json:"pass"`
		} `json:"accounts"`
	}
	if err := json.Unmarshal(relay.Settings, &settings); err != nil {
		t.Fatalf("decode relay settings: %v", err)
	}
	var users []string
	for _, a := range settings.Accounts {
		if a.Pass != singbox.SocksPassword() {
			t.Fatalf("account %q has pass %q, want the relay password", a.User, a.Pass)
		}
		users = append(users, a.User)
	}
	if want := []string{"alice@anytls.test", "bob@anytls.test"}; !reflect.DeepEqual(users, want) {
		t.Fatalf("relay accounts = %v, want %v (a disabled client keeps its account)", users, want)
	}
}

func TestDesiredSingboxInstancesDropsDepletedClients(t *testing.T) {
	setupSingboxDB(t)
	in := &model.Inbound{
		Id: 12, Tag: "in-9443-anytls", Enable: true, Port: 9443, Protocol: model.AnyTLS,
		Settings: `{"certificate":"c","private_key":"k","clients":[` +
			`{"email":"live@anytls.test","password":"p1","enable":true},` +
			`{"email":"spent@anytls.test","password":"p2","enable":true}]}`,
	}
	if err := database.GetDB().Create(in).Error; err != nil {
		t.Fatal(err)
	}
	if err := database.GetDB().Create(&xray.ClientTraffic{InboundId: 12, Email: "spent@anytls.test", Enable: false}).Error; err != nil {
		t.Fatal(err)
	}

	instances, err := (&InboundService{}).DesiredSingboxInstances()
	if err != nil {
		t.Fatalf("DesiredSingboxInstances: %v", err)
	}
	if len(instances) != 1 || instances[0].Id != 12 {
		t.Fatalf("instances = %+v, want inbound 12 only", instances)
	}
	if want := []singbox.User{{Email: "live@anytls.test", Password: "p1"}}; !reflect.DeepEqual(instances[0].Users, want) {
		t.Fatalf("served users = %+v, want %+v", instances[0].Users, want)
	}
}

func TestSingboxRelayPortConflicts(t *testing.T) {
	t.Run("two AnyTLS rows sharing a relay slot", func(t *testing.T) {
		setupSingboxDB(t)
		first := &model.Inbound{Id: 1, Tag: "anytls-1", Enable: true, Port: 443, Protocol: model.AnyTLS, Settings: anytlsTestSettings}
		wrapped := &model.Inbound{Id: 200, Tag: "anytls-200", Enable: true, Port: 444, Protocol: model.AnyTLS, Settings: anytlsTestSettings}
		for _, ib := range []*model.Inbound{first, wrapped} {
			if err := database.GetDB().Create(ib).Error; err != nil {
				t.Fatal(err)
			}
		}
		detail, err := checkPortConflictTx(database.GetDB(), wrapped, 200)
		if err != nil {
			t.Fatalf("checkPortConflictTx: %v", err)
		}
		if detail == nil || detail.InboundID != 1 || detail.Port != singbox.SOCKSPortForInbound(1) || !detail.Relay {
			t.Fatalf("detail = %+v, want relay port %d held by inbound 1", detail, singbox.SOCKSPortForInbound(1))
		}
	})
	t.Run("loopback inbound on an AnyTLS relay port", func(t *testing.T) {
		setupSingboxDB(t)
		owner := &model.Inbound{Id: 3, Tag: "anytls-3", Enable: true, Port: 443, Protocol: model.AnyTLS, Settings: anytlsTestSettings}
		if err := database.GetDB().Create(owner).Error; err != nil {
			t.Fatal(err)
		}
		squatter := &model.Inbound{Tag: "mixed", Enable: true, Listen: "127.0.0.1", Port: singbox.SOCKSPortForInbound(3), Protocol: model.Mixed}
		detail, err := checkPortConflictTx(database.GetDB(), squatter, 0)
		if err != nil {
			t.Fatalf("checkPortConflictTx: %v", err)
		}
		if detail == nil || detail.InboundID != 3 || !detail.Relay {
			t.Fatalf("detail = %+v, want inbound 3's relay", detail)
		}
	})
	t.Run("AnyTLS row whose relay port is already taken", func(t *testing.T) {
		setupSingboxDB(t)
		squatter := &model.Inbound{Id: 50, Tag: "mixed", Enable: true, Listen: "127.0.0.1", Port: singbox.SOCKSPortForInbound(4), Protocol: model.Mixed}
		owner := &model.Inbound{Id: 4, Tag: "anytls-4", Enable: true, Port: 443, Protocol: model.AnyTLS, Settings: anytlsTestSettings}
		for _, ib := range []*model.Inbound{squatter, owner} {
			if err := database.GetDB().Create(ib).Error; err != nil {
				t.Fatal(err)
			}
		}
		detail, err := checkPortConflictTx(database.GetDB(), owner, 4)
		if err != nil {
			t.Fatalf("checkPortConflictTx: %v", err)
		}
		if detail == nil || detail.InboundID != 50 {
			t.Fatalf("detail = %+v, want inbound 50 squatting on the relay port", detail)
		}
	})
	t.Run("AnyTLS listening on its own relay port", func(t *testing.T) {
		setupSingboxDB(t)
		self := &model.Inbound{Id: 5, Tag: "anytls-5", Listen: "127.0.0.1", Port: singbox.SOCKSPortForInbound(5), Protocol: model.AnyTLS, Settings: anytlsTestSettings}
		_, err := checkPortConflictTx(database.GetDB(), self, 5)
		if err == nil || !strings.Contains(err.Error(), "own SOCKS5 relay port") {
			t.Fatalf("err = %v, want the own-relay-port refusal", err)
		}
	})
}
