package singbox

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
)

func TestInstanceFromInbound(t *testing.T) {
	ib := &model.Inbound{
		Id:       4,
		Tag:      "inbound-443",
		Listen:   "",
		Port:     443,
		Protocol: model.AnyTLS,
		Settings: `{"certificate":"/etc/ssl/a.crt","private_key":"/etc/ssl/a.key","sni":"example.com",` +
			`"padding_scheme":["stop=8","0=30-30"],"clients":[` +
			`{"email":"alice","password":"pa","enable":true},` +
			`{"email":"bob","password":"","enable":true},` +
			`{"email":"","password":"px","enable":true},` +
			`{"email":"carol","password":"pc","enable":false},` +
			`{"email":"dave","password":"pd"}]}`,
	}
	inst, ok := InstanceFromInbound(ib)
	if !ok {
		t.Fatal("expected a usable instance")
	}
	want := []User{{Email: "alice", Password: "pa"}, {Email: "dave", Password: "pd"}}
	if len(inst.Users) != len(want) {
		t.Fatalf("users = %+v, want %+v", inst.Users, want)
	}
	for i := range want {
		if inst.Users[i] != want[i] {
			t.Fatalf("user %d = %+v, want %+v", i, inst.Users[i], want[i])
		}
	}
	if inst.Listen != "::" {
		t.Fatalf("an empty listen must bind every family, got %q", inst.Listen)
	}
	if inst.Certificate != "/etc/ssl/a.crt" || inst.PrivateKey != "/etc/ssl/a.key" || inst.ServerName != "example.com" {
		t.Fatalf("tls fields not parsed: %+v", inst)
	}
	if len(inst.PaddingScheme) != 2 || inst.PaddingScheme[1] != "0=30-30" {
		t.Fatalf("padding scheme not parsed: %+v", inst.PaddingScheme)
	}

	t.Run("other protocol", func(t *testing.T) {
		if _, ok := InstanceFromInbound(&model.Inbound{Protocol: model.Trojan, Settings: ib.Settings}); ok {
			t.Fatal("a trojan inbound must not produce a sing-box instance")
		}
	})
	t.Run("no usable client", func(t *testing.T) {
		none := &model.Inbound{Protocol: model.AnyTLS, Settings: `{"certificate":"c","private_key":"k","clients":[{"email":"x","password":"","enable":true}]}`}
		if _, ok := InstanceFromInbound(none); ok {
			t.Fatal("an inbound with no servable client must not start a sidecar")
		}
	})
	t.Run("missing certificate", func(t *testing.T) {
		noCert := &model.Inbound{Protocol: model.AnyTLS, Settings: `{"clients":[{"email":"x","password":"p"}]}`}
		if _, ok := InstanceFromInbound(noCert); ok {
			t.Fatal("anytls without a certificate cannot start, so no instance")
		}
	})
}

func TestFingerprintTracksCertificateFileContent(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "a.crt")
	if err := os.WriteFile(cert, []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	inst := Instance{Id: 1, Listen: "::", Port: 443, Certificate: cert, PrivateKey: "k", Users: []User{{Email: "a", Password: "p"}}}
	before := inst.fingerprint([]byte("cfg"))
	if err := os.WriteFile(cert, []byte("two"), 0o600); err != nil {
		t.Fatal(err)
	}
	if after := inst.fingerprint([]byte("cfg")); after == before {
		t.Fatal("a renewed certificate file must change the fingerprint so the sidecar reloads it")
	}
}
