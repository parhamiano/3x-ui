//go:build linux

package singbox

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// killStraySingboxProcesses kills sidecars left by a previous x-ui run; on Linux children
// outlive the panel, and a survivor would hold the inbound port with stale users.
func killStraySingboxProcesses(binaryPath string) int {
	base := filepath.Base(binaryPath)
	if base == "" || base == "." || base == string(filepath.Separator) {
		return 0
	}
	self := os.Getpid()
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}
	killed := 0
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == self {
			continue
		}
		if procExeBase(pid) != base && cmdlineArgv0Base(pid) != base {
			continue
		}
		if err := syscall.Kill(pid, syscall.SIGKILL); err == nil {
			killed++
		}
	}
	return killed
}

// procExeBase returns the base name of /proc/<pid>/exe, or "" if unreadable.
func procExeBase(pid int) string {
	exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return ""
	}
	return filepath.Base(exe)
}

// cmdlineArgv0Base returns the base name of argv[0] from /proc/<pid>/cmdline,
// the reliable fallback when the binary has been replaced or exe is unreadable.
func cmdlineArgv0Base(pid int) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil || len(data) == 0 {
		return ""
	}
	argv0 := data
	if i := strings.IndexByte(string(data), 0); i >= 0 {
		argv0 = data[:i]
	}
	if len(argv0) == 0 {
		return ""
	}
	return filepath.Base(string(argv0))
}
