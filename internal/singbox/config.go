package singbox

import (
	"encoding/json"
	"fmt"
	"strings"
)

const inboundTag = "anytls-in"

type sbConfig struct {
	Log       sbLog        `json:"log"`
	Inbounds  []sbInbound  `json:"inbounds"`
	Outbounds []sbOutbound `json:"outbounds"`
	Route     sbRoute      `json:"route"`
}

type sbLog struct {
	Level     string `json:"level"`
	Timestamp bool   `json:"timestamp"`
}

type sbInbound struct {
	Type          string   `json:"type"`
	Tag           string   `json:"tag"`
	Listen        string   `json:"listen"`
	ListenPort    int      `json:"listen_port"`
	Users         []sbUser `json:"users"`
	PaddingScheme []string `json:"padding_scheme,omitempty"`
	TLS           sbTLS    `json:"tls"`
}

type sbUser struct {
	Name     string `json:"name"`
	Password string `json:"password"`
}

type sbTLS struct {
	Enabled         bool     `json:"enabled"`
	ServerName      string   `json:"server_name,omitempty"`
	CertificatePath string   `json:"certificate_path,omitempty"`
	Certificate     []string `json:"certificate,omitempty"`
	KeyPath         string   `json:"key_path,omitempty"`
	Key             []string `json:"key,omitempty"`
}

type sbOutbound struct {
	Type       string `json:"type"`
	Tag        string `json:"tag"`
	Server     string `json:"server"`
	ServerPort int    `json:"server_port"`
	Version    string `json:"version"`
	Username   string `json:"username"`
	Password   string `json:"password"`
}

type sbRoute struct {
	Rules []sbRule `json:"rules"`
}

type sbRule struct {
	AuthUser []string `json:"auth_user,omitempty"`
	Inbound  []string `json:"inbound,omitempty"`
	Action   string   `json:"action"`
	Outbound string   `json:"outbound,omitempty"`
}

// renderConfig builds the sing-box config: each user's connections leave
// through a SOCKS outbound logged in as that user, and nothing else may pass.
func renderConfig(inst Instance, relayPort int, relayPassword string) ([]byte, error) {
	if len(inst.Users) == 0 {
		return nil, fmt.Errorf("singbox: inbound %d has no users", inst.Id)
	}
	in := sbInbound{
		Type:          "anytls",
		Tag:           inboundTag,
		Listen:        inst.Listen,
		ListenPort:    inst.Port,
		PaddingScheme: inst.PaddingScheme,
		TLS:           sbTLS{Enabled: true, ServerName: inst.ServerName},
	}
	if isPEM(inst.Certificate) {
		in.TLS.Certificate = pemLines(inst.Certificate)
	} else {
		in.TLS.CertificatePath = inst.Certificate
	}
	if isPEM(inst.PrivateKey) {
		in.TLS.Key = pemLines(inst.PrivateKey)
	} else {
		in.TLS.KeyPath = inst.PrivateKey
	}

	cfg := sbConfig{Log: sbLog{Level: "warn", Timestamp: true}}
	for i, u := range inst.Users {
		in.Users = append(in.Users, sbUser{Name: u.Email, Password: u.Password})
		tag := fmt.Sprintf("relay-%d", i)
		cfg.Outbounds = append(cfg.Outbounds, sbOutbound{
			Type: "socks", Tag: tag, Server: "127.0.0.1", ServerPort: relayPort,
			Version: "5", Username: u.Email, Password: relayPassword,
		})
		cfg.Route.Rules = append(cfg.Route.Rules, sbRule{AuthUser: []string{u.Email}, Action: "route", Outbound: tag})
	}
	cfg.Route.Rules = append(cfg.Route.Rules, sbRule{Inbound: []string{inboundTag}, Action: "reject"})
	cfg.Inbounds = []sbInbound{in}
	return json.MarshalIndent(cfg, "", "  ")
}

func pemLines(pem string) []string {
	lines := strings.Split(strings.TrimSpace(strings.ReplaceAll(pem, "\r\n", "\n")), "\n")
	out := lines[:0]
	for _, l := range lines {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}
