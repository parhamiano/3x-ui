package singbox

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"
)

// SOCKSBasePort sits between node egress (62800..63800) and TUIC relays (64001..65000).
const SOCKSBasePort = 63800

const relayPortSlots = 199

// SOCKSPortForInbound derives one inbound's loopback relay port (63801..63999) from its id.
func SOCKSPortForInbound(inboundID int) int {
	if inboundID <= 0 {
		return SOCKSBasePort + 1
	}
	return SOCKSBasePort + 1 + (inboundID-1)%relayPortSlots
}

var (
	socksPasswordOnce sync.Once
	socksPassword     string
)

// SocksPassword is the process-wide relay password; loopback-only, so it only
// has to be unguessable, and every sidecar restarts with the panel anyway.
func SocksPassword() string {
	socksPasswordOnce.Do(func() {
		var b [24]byte
		if _, err := rand.Read(b[:]); err != nil {
			socksPassword = fmt.Sprintf("singbox-fallback-%x", b)
			return
		}
		socksPassword = base64.RawURLEncoding.EncodeToString(b[:])
	})
	return socksPassword
}

// SocksInboundSettings builds the Xray SOCKS5 relay settings with one account
// per email, so Xray bills each client's traffic under its own email.
func SocksInboundSettings(emails []string, password string) ([]byte, error) {
	type account struct {
		User string `json:"user"`
		Pass string `json:"pass"`
	}
	settings := struct {
		Auth     string    `json:"auth"`
		UDP      bool      `json:"udp"`
		Accounts []account `json:"accounts"`
	}{Auth: "password", UDP: true}
	for _, email := range emails {
		settings.Accounts = append(settings.Accounts, account{User: email, Pass: password})
	}
	return json.Marshal(settings)
}
