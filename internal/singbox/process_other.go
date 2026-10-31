//go:build !windows

package singbox

import "os/exec"

func attachChildLifetime(_ *exec.Cmd) {}
