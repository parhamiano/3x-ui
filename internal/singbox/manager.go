package singbox

import (
	"fmt"
	"os"
	"sync"

	"github.com/mhsanaei/3x-ui/v3/internal/logger"
)

type managed struct {
	proc        *Process
	fingerprint string
}

// Manager owns every sing-box sidecar of this panel, keyed by inbound id.
type Manager struct {
	mu    sync.Mutex
	procs map[int]*managed
	swept bool
}

var (
	managerInstance *Manager
	managerOnce     sync.Once
)

func GetManager() *Manager {
	managerOnce.Do(func() { managerInstance = newManager() })
	return managerInstance
}

func newManager() *Manager {
	return &Manager{procs: make(map[int]*managed)}
}

func (m *Manager) HasRunning() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, cur := range m.procs {
		if cur.proc.IsRunning() {
			return true
		}
	}
	return false
}

// Ensure starts the sidecar for inst, restarting it only when its config changed
// or it died; sing-box has no live user API, so a user edit costs a restart.
func (m *Manager) Ensure(inst Instance) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sweepOrphansLocked()
	return m.ensureLocked(inst)
}

func (m *Manager) sweepOrphansLocked() {
	if m.swept {
		return
	}
	m.swept = true
	if n := killStraySingboxProcesses(GetBinaryPath()); n > 0 {
		logger.Warningf("singbox: terminated %d orphaned sing-box process(es) from a previous run", n)
	}
}

func (m *Manager) ensureLocked(inst Instance) error {
	cfg, err := renderConfig(inst, SOCKSPortForInbound(inst.Id), SocksPassword())
	if err != nil {
		return err
	}
	fp := inst.fingerprint(cfg)
	if cur, ok := m.procs[inst.Id]; ok {
		if cur.fingerprint == fp && cur.proc.IsRunning() {
			return nil
		}
		_ = cur.proc.Stop()
		delete(m.procs, inst.Id)
	}
	if err := os.MkdirAll(configDir(), 0o750); err != nil {
		return err
	}
	cfgPath := configPathForID(inst.Id)
	if err := os.WriteFile(cfgPath, cfg, 0o600); err != nil {
		return err
	}
	proc := newProcess(cfgPath, fmt.Sprintf("inbound %d", inst.Id))
	if err := proc.Start(); err != nil {
		return err
	}
	m.procs[inst.Id] = &managed{proc: proc, fingerprint: fp}
	logger.Infof("singbox: started sing-box for inbound %d on %s", inst.Id, inst.bindTo())
	return nil
}

// Remove stops and forgets the sidecar of an inbound id.
func (m *Manager) Remove(id int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.removeLocked(id)
}

func (m *Manager) removeLocked(id int) {
	cur, ok := m.procs[id]
	if !ok {
		return
	}
	_ = cur.proc.Stop()
	delete(m.procs, id)
	_ = os.Remove(configPathForID(id))
	logger.Infof("singbox: stopped sing-box for inbound %d", id)
}

// Reconcile stops sidecars no longer desired and (re)starts the rest, which
// also brings back any that crashed since the last run.
func (m *Manager) Reconcile(desired []Instance) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sweepOrphansLocked()
	want := make(map[int]struct{}, len(desired))
	for _, inst := range desired {
		want[inst.Id] = struct{}{}
	}
	for id := range m.procs {
		if _, ok := want[id]; !ok {
			m.removeLocked(id)
		}
	}
	for _, inst := range desired {
		if err := m.ensureLocked(inst); err != nil {
			logger.Warningf("singbox: reconcile failed for inbound %d: %v", inst.Id, err)
		}
	}
}

// StopAll stops every sidecar; called on panel shutdown.
func (m *Manager) StopAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id := range m.procs {
		m.removeLocked(id)
	}
}
