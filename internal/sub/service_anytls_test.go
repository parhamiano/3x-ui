package sub

import (
	"net/url"
	"strings"
	"testing"

	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
)

func TestGenAnyTLSLink(t *testing.T) {
	inbound := &model.Inbound{
		Listen:   "198.51.100.9",
		Port:     443,
		Protocol: model.AnyTLS,
		Remark:   "anytls-test",
		Settings: `{"certificate":"/c","private_key":"/k","sni":"cdn.example.com","clients":[` +
			`{"email":"other","password":"nope"},{"email":"user@test","password":"p@ss/word"}]}`,
	}

	link := (&SubService{}).GetLink(inbound, "user@test")
	u, err := url.Parse(link)
	if err != nil {
		t.Fatalf("link does not parse: %v\ngot: %s", err, link)
	}
	if u.Scheme != "anytls" || u.Host != "198.51.100.9:443" {
		t.Fatalf("link = %s, want anytls://…@198.51.100.9:443", link)
	}
	if u.User.Username() != "p@ss/word" {
		t.Fatalf("userinfo = %q, want the client's own password", u.User.Username())
	}
	if got := u.Query().Get("sni"); got != "cdn.example.com" {
		t.Fatalf("sni = %q, want cdn.example.com", got)
	}
	if u.Fragment == "" {
		t.Fatalf("link must carry a remark fragment: %s", link)
	}
	// Pinned to the frontend genAnyTLSLink output so the panel QR and the subscription agree.
	if want := "anytls://p%40ss%2Fword@198.51.100.9:443?sni=cdn.example.com#"; !strings.HasPrefix(link, want) {
		t.Fatalf("link = %s, want prefix %s", link, want)
	}

	t.Run("unknown client", func(t *testing.T) {
		if got := (&SubService{}).GetLink(inbound, "ghost"); got != "" {
			t.Fatalf("GetLink for a client not on the inbound = %q, want empty", got)
		}
	})
}

// The subscription SQL allowlist decides which inbounds a subId sees at all; left off it,
// an AnyTLS client's subscription came back 404 on a live install.
func TestGetSubsIncludesAnyTLS(t *testing.T) {
	initSubDB(t)
	db := database.GetDB()

	in := &model.Inbound{
		Listen: "198.51.100.9", Port: 443, Protocol: model.AnyTLS, Enable: true, Tag: "anytls-sub", Remark: "a",
		Settings: `{"certificate":"/c","private_key":"/k","sni":"cdn.example.com","clients":[` +
			`{"email":"u@anytls","password":"pw","subId":"subanytls","enable":true}]}`,
	}
	if err := db.Create(in).Error; err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	rec := &model.ClientRecord{Email: "u@anytls", SubID: "subanytls", Password: "pw", Enable: true}
	if err := db.Create(rec).Error; err != nil {
		t.Fatalf("create client: %v", err)
	}
	if err := db.Create(&model.ClientInbound{ClientId: rec.Id, InboundId: in.Id}).Error; err != nil {
		t.Fatalf("create link: %v", err)
	}

	links, _, _, _, err := NewSubService("").GetSubs("subanytls", "req.example.com")
	if err != nil {
		t.Fatalf("GetSubs: %v", err)
	}
	if len(links) != 1 || !strings.HasPrefix(links[0], "anytls://pw@198.51.100.9:443?sni=cdn.example.com#") {
		t.Fatalf("links = %q, want one anytls:// link", links)
	}
}
