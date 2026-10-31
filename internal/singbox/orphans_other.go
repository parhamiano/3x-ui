//go:build !linux

package singbox

// killStraySingboxProcesses is a no-op off Linux: the Windows kill-on-exit job ends sidecars with the panel.
func killStraySingboxProcesses(_ string) int { return 0 }
