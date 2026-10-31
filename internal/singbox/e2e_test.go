package singbox

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"
)

// TestE2EAnyTLSRelaysEachClientAsItsEmail drives a real sing-box client through the
// rendered server config; set SINGBOX_E2E_BINARY to a sing-box executable to run it.
func TestE2EAnyTLSRelaysEachClientAsItsEmail(t *testing.T) {
	bin := os.Getenv("SINGBOX_E2E_BINARY")
	if bin == "" {
		t.Skip("SINGBOX_E2E_BINARY not set")
	}
	dir := t.TempDir()
	certPath, keyPath := writeSelfSignedCert(t, dir, "anytls.test")

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "through-the-relay")
	}))
	t.Cleanup(target.Close)

	relay := startRecordingSocks(t, "relay-pw")
	inst := Instance{
		Id: 1, Listen: "127.0.0.1", Port: freePort(t),
		Certificate: certPath, PrivateKey: keyPath, ServerName: "anytls.test",
		Users: []User{{Email: "alice@e2e", Password: "pa"}, {Email: "bob@e2e", Password: "pb"}},
	}
	cfg, err := renderConfig(inst, relay.port, "relay-pw")
	if err != nil {
		t.Fatal(err)
	}
	serverCfg := filepath.Join(dir, "server.json")
	if err := os.WriteFile(serverCfg, cfg, 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(bin, "check", "-c", serverCfg).CombinedOutput(); err != nil {
		t.Fatalf("sing-box check refused the rendered config: %v\n%s\n%s", err, out, cfg)
	}
	runSingbox(t, bin, serverCfg)
	waitListening(t, inst.Port)

	t.Run("each client reaches the relay as its own email", func(t *testing.T) {
		for _, u := range inst.Users {
			body, err := fetchThroughClient(t, bin, dir, inst.Port, u.Password, target.URL)
			if err != nil {
				t.Fatalf("%s: fetch through anytls: %v", u.Email, err)
			}
			if body != "through-the-relay" {
				t.Fatalf("%s: body = %q", u.Email, body)
			}
			if got := relay.lastUser(); got != u.Email {
				t.Fatalf("relay saw user %q, want %q", got, u.Email)
			}
		}
	})
	t.Run("a wrong password never reaches the relay", func(t *testing.T) {
		before := relay.count()
		if _, err := fetchThroughClient(t, bin, dir, inst.Port, "wrong", target.URL); err == nil {
			t.Fatal("fetch with a wrong password succeeded")
		}
		if relay.count() != before {
			t.Fatal("an unauthenticated connection was relayed into Xray")
		}
	})
}

func fetchThroughClient(t *testing.T, bin, dir string, serverPort int, password, target string) (string, error) {
	t.Helper()
	mixedPort := freePort(t)
	client := map[string]any{
		"log":      map[string]any{"level": "warn"},
		"inbounds": []any{map[string]any{"type": "mixed", "listen": "127.0.0.1", "listen_port": mixedPort}},
		"outbounds": []any{map[string]any{
			"type": "anytls", "server": "127.0.0.1", "server_port": serverPort, "password": password,
			"tls": map[string]any{"enabled": true, "server_name": "anytls.test", "insecure": true},
		}},
	}
	raw, _ := json.Marshal(client)
	path := filepath.Join(dir, "client-"+strconv.Itoa(mixedPort)+".json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	stop := runSingbox(t, bin, path)
	defer stop()
	waitListening(t, mixedPort)

	proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", mixedPort))
	hc := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	resp, err := hc.Get(target)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status %d", resp.StatusCode)
	}
	b, err := io.ReadAll(resp.Body)
	return string(b), err
}

func runSingbox(t *testing.T, bin, cfg string) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, bin, "run", "-c", cfg)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatalf("start sing-box: %v", err)
	}
	var once sync.Once
	stop := func() { once.Do(func() { cancel(); _ = cmd.Wait() }) }
	t.Cleanup(stop)
	return stop
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func waitListening(t *testing.T, port int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 200*time.Millisecond); err == nil {
			c.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("nothing listening on %d", port)
}

func writeSelfSignedCert(t *testing.T, dir, host string) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: host}, DNSNames: []string{host},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	_ = os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	_ = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600)
	return certPath, keyPath
}

// recordingSocks stands in for Xray's relay inbound: a SOCKS5 CONNECT server that
// requires the shared password and records which username each connection used.
type recordingSocks struct {
	port  int
	mu    sync.Mutex
	users []string
}

func (r *recordingSocks) lastUser() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.users) == 0 {
		return ""
	}
	return r.users[len(r.users)-1]
}

func (r *recordingSocks) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.users)
}

func startRecordingSocks(t *testing.T, password string) *recordingSocks {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	r := &recordingSocks{port: l.Addr().(*net.TCPAddr).Port}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go r.serve(c, password)
		}
	}()
	return r
}

func (r *recordingSocks) serve(c net.Conn, password string) {
	defer c.Close()
	buf := make([]byte, 512)
	if _, err := io.ReadFull(c, buf[:2]); err != nil || buf[0] != 5 {
		return
	}
	if _, err := io.ReadFull(c, buf[:buf[1]]); err != nil {
		return
	}
	_, _ = c.Write([]byte{5, 2})
	if _, err := io.ReadFull(c, buf[:2]); err != nil {
		return
	}
	user := make([]byte, buf[1])
	if _, err := io.ReadFull(c, user); err != nil {
		return
	}
	if _, err := io.ReadFull(c, buf[:1]); err != nil {
		return
	}
	pass := make([]byte, buf[0])
	if _, err := io.ReadFull(c, pass); err != nil {
		return
	}
	if string(pass) != password {
		_, _ = c.Write([]byte{1, 1})
		return
	}
	_, _ = c.Write([]byte{1, 0})
	if _, err := io.ReadFull(c, buf[:4]); err != nil || buf[1] != 1 {
		return
	}
	var host string
	switch buf[3] {
	case 1:
		if _, err := io.ReadFull(c, buf[:4]); err != nil {
			return
		}
		host = net.IP(buf[:4]).String()
	case 3:
		if _, err := io.ReadFull(c, buf[:1]); err != nil {
			return
		}
		n := int(buf[0])
		if _, err := io.ReadFull(c, buf[:n]); err != nil {
			return
		}
		host = string(buf[:n])
	default:
		return
	}
	if _, err := io.ReadFull(c, buf[:2]); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(buf[:2])
	up, err := net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(int(port))))
	if err != nil {
		_, _ = c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer up.Close()
	r.mu.Lock()
	r.users = append(r.users, string(user))
	r.mu.Unlock()
	_, _ = c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	go func() { _, _ = io.Copy(up, c) }()
	_, _ = io.Copy(c, up)
}
