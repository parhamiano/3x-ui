package singbox

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestMain re-execs the test binary as a stand-in sing-box: with SINGBOX_FAKE_CHILD=1
// it appends its argv to a spawn log and blocks until killed.
func TestMain(m *testing.M) {
	if os.Getenv("SINGBOX_FAKE_CHILD") == "1" {
		if f, err := os.OpenFile(os.Getenv("SINGBOX_FAKE_LOG"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); err == nil {
			fmt.Fprintln(f, strings.Join(os.Args[1:], " "))
			f.Close()
		}
		select {}
	}
	os.Exit(m.Run())
}

func installFakeSingbox(t *testing.T) string {
	t.Helper()
	binDir := t.TempDir()
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("locate test binary: %v", err)
	}
	payload, err := os.ReadFile(self)
	if err != nil {
		t.Fatalf("read test binary: %v", err)
	}
	if err := os.WriteFile(filepath.Join(binDir, GetBinaryName()), payload, 0o755); err != nil {
		t.Fatalf("install fake sing-box: %v", err)
	}
	spawnLog := filepath.Join(binDir, "spawns.txt")
	t.Setenv("XUI_BIN_FOLDER", binDir)
	t.Setenv("SINGBOX_FAKE_CHILD", "1")
	t.Setenv("SINGBOX_FAKE_LOG", spawnLog)
	return spawnLog
}

func waitSpawns(t *testing.T, spawnLog string, want int) []string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		data, _ := os.ReadFile(spawnLog)
		var lines []string
		for _, line := range strings.Split(string(data), "\n") {
			if line = strings.TrimSpace(line); line != "" {
				lines = append(lines, line)
			}
		}
		if len(lines) == want {
			return lines
		}
		if time.Now().After(deadline) {
			t.Fatalf("spawns = %d (%q), want %d", len(lines), data, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestManagerRestartsOnlyWhenTheConfigChanges(t *testing.T) {
	spawnLog := installFakeSingbox(t)
	m := newManager()
	t.Cleanup(m.StopAll)

	inst := Instance{
		Id: 3, Tag: "inbound-443", Listen: "::", Port: 443,
		Certificate: "/c.crt", PrivateKey: "/c.key",
		Users: []User{{Email: "alice", Password: "pa"}},
	}
	if err := m.Ensure(inst); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	spawns := waitSpawns(t, spawnLog, 1)
	cfgPath := configPathForID(3)
	if spawns[0] != "run -c "+cfgPath {
		t.Fatalf("sing-box argv = %q, want %q", spawns[0], "run -c "+cfgPath)
	}

	if err := m.Ensure(inst); err != nil {
		t.Fatalf("second Ensure: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	waitSpawns(t, spawnLog, 1)

	inst.Users = append(inst.Users, User{Email: "bob", Password: "pb"})
	if err := m.Ensure(inst); err != nil {
		t.Fatalf("Ensure after adding a user: %v", err)
	}
	waitSpawns(t, spawnLog, 2)
	cfg, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(cfg), `"name": "bob"`) {
		t.Fatalf("restarted sidecar config lacks the new user:\n%s", cfg)
	}

	m.Reconcile(nil)
	if m.HasRunning() {
		t.Fatal("Reconcile with nothing desired must stop the sidecar")
	}
	if _, err := os.Stat(cfgPath); !os.IsNotExist(err) {
		t.Fatalf("Reconcile must delete the stale config, stat err = %v", err)
	}
}

func TestManagerReconcileRestartsACrashedSidecar(t *testing.T) {
	spawnLog := installFakeSingbox(t)
	m := newManager()
	t.Cleanup(m.StopAll)

	inst := Instance{Id: 5, Listen: "::", Port: 8443, Certificate: "/c", PrivateKey: "/k", Users: []User{{Email: "a", Password: "p"}}}
	m.Reconcile([]Instance{inst})
	waitSpawns(t, spawnLog, 1)

	m.mu.Lock()
	_ = m.procs[5].proc.cmd.Process.Kill()
	m.mu.Unlock()
	deadline := time.Now().Add(5 * time.Second)
	for m.HasRunning() {
		if time.Now().After(deadline) {
			t.Fatal("killed fake sidecar still reported running")
		}
		time.Sleep(10 * time.Millisecond)
	}

	m.Reconcile([]Instance{inst})
	waitSpawns(t, spawnLog, 2)
	if !m.HasRunning() {
		t.Fatal("Reconcile must bring a crashed sidecar back")
	}
}
