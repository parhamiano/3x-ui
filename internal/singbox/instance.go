// Package singbox runs AnyTLS inbounds as sing-box sidecars that relay into a loopback
// SOCKS5 Xray inbound logged in as each client's email, so Xray keeps routing and stats.
package singbox

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
)

// User is one client the sidecar authenticates; Email doubles as its Xray identity.
type User struct {
	Email    string
	Password string
}

// Instance is the sing-box sidecar config derived from one inbound row.
type Instance struct {
	Id            int
	Tag           string
	Listen        string
	Port          int
	Certificate   string
	PrivateKey    string
	ServerName    string
	PaddingScheme []string
	Users         []User
}

// InboundSettings is the stored settings shape of an AnyTLS inbound.
type InboundSettings struct {
	Certificate   string           `json:"certificate"`
	PrivateKey    string           `json:"private_key"`
	SNI           string           `json:"sni"`
	PaddingScheme []string         `json:"padding_scheme"`
	Clients       []ClientSettings `json:"clients"`
}

// ClientSettings is the subset of a stored client the sidecar needs.
type ClientSettings struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Enable   *bool  `json:"enable"`
}

// InstanceFromInbound derives the sidecar config, serving only enabled clients
// with an email and password; false means the inbound has nothing to run.
func InstanceFromInbound(ib *model.Inbound) (Instance, bool) {
	if ib == nil || ib.Protocol != model.AnyTLS {
		return Instance{}, false
	}
	var parsed InboundSettings
	if ib.Settings != "" {
		if err := json.Unmarshal([]byte(ib.Settings), &parsed); err != nil {
			return Instance{}, false
		}
	}
	if strings.TrimSpace(parsed.Certificate) == "" || strings.TrimSpace(parsed.PrivateKey) == "" {
		return Instance{}, false
	}
	users := make([]User, 0, len(parsed.Clients))
	for _, c := range parsed.Clients {
		if c.Enable != nil && !*c.Enable {
			continue
		}
		if c.Email == "" || c.Password == "" {
			continue
		}
		users = append(users, User{Email: c.Email, Password: c.Password})
	}
	if len(users) == 0 {
		return Instance{}, false
	}
	listen := strings.TrimSpace(ib.Listen)
	if listen == "" || listen == "0.0.0.0" {
		listen = "::"
	}
	return Instance{
		Id:            ib.Id,
		Tag:           ib.Tag,
		Listen:        listen,
		Port:          ib.Port,
		Certificate:   strings.TrimSpace(parsed.Certificate),
		PrivateKey:    strings.TrimSpace(parsed.PrivateKey),
		ServerName:    strings.TrimSpace(parsed.SNI),
		PaddingScheme: parsed.PaddingScheme,
		Users:         users,
	}, true
}

func (inst Instance) bindTo() string {
	return net.JoinHostPort(inst.Listen, strconv.Itoa(inst.Port))
}

// fingerprint covers the rendered config plus certificate file contents, since
// a renewed certificate keeps its path but sing-box only reads it at start.
func (inst Instance) fingerprint(config []byte) string {
	h := sha256.New()
	h.Write(config)
	for _, material := range []string{inst.Certificate, inst.PrivateKey} {
		if isPEM(material) {
			continue
		}
		if data, err := os.ReadFile(material); err == nil {
			h.Write(data)
		}
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

func isPEM(value string) bool {
	return strings.Contains(value, "-----BEGIN ")
}
