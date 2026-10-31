package service

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"

	"gorm.io/gorm"

	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/logger"
	"github.com/mhsanaei/3x-ui/v3/internal/singbox"
	"github.com/mhsanaei/3x-ui/v3/internal/util/common"
	"github.com/mhsanaei/3x-ui/v3/internal/util/json_util"
	"github.com/mhsanaei/3x-ui/v3/internal/xray"
)

// DesiredSingboxInstances is what the reconcile job should run: one sidecar per
// enabled local AnyTLS inbound, serving only clients the runtime push would serve.
func (s *InboundService) DesiredSingboxInstances() ([]singbox.Instance, error) {
	db := database.GetDB()
	var inbounds []*model.Inbound
	err := db.Model(model.Inbound{}).
		Where("protocol = ? AND enable = ? AND node_id IS NULL", model.AnyTLS, true).
		Find(&inbounds).Error
	if err != nil {
		return nil, err
	}
	instances := make([]singbox.Instance, 0, len(inbounds))
	for _, ib := range inbounds {
		built, err := s.buildInboundForLocalRuntime(db, ib)
		if err != nil {
			return nil, err
		}
		if inst, ok := singbox.InstanceFromInbound(built); ok {
			instances = append(instances, inst)
		}
	}
	return instances, nil
}

func (s *InboundService) applyLocalSingbox(inboundId int) {
	inbound, err := s.GetInbound(inboundId)
	if err != nil || inbound == nil || inbound.Protocol != model.AnyTLS || inbound.NodeID != nil {
		return
	}
	rt, err := s.runtimeFor(inbound)
	if err != nil {
		return
	}
	payload := inbound
	if inbound.Enable {
		if built, bErr := s.buildInboundForLocalRuntime(database.GetDB(), inbound); bErr == nil {
			payload = built
		}
	}
	if err := rt.UpdateInbound(context.Background(), inbound, payload); err != nil {
		logger.Debug("singbox: immediate client apply failed for inbound", inboundId, ":", err)
	}
}

// Keep sniffed domains available for routing without replacing the requested destination.
const singboxRelaySniffingSettings = `{"enabled":true,"destOverride":["http","tls","quic","fakedns"],"routeOnly":true}`

// injectSingboxRelay gives every enabled local AnyTLS inbound a loopback SOCKS5
// inbound under its own tag, with an account per configured client email.
func injectSingboxRelay(cfg *xray.Config, inbounds []*model.Inbound) {
	existingTags := make(map[string]struct{}, len(cfg.InboundConfigs))
	for i := range cfg.InboundConfigs {
		existingTags[cfg.InboundConfigs[i].Tag] = struct{}{}
	}
	for _, inbound := range inbounds {
		if inbound.Protocol != model.AnyTLS || !inbound.Enable || inbound.NodeID != nil {
			continue
		}
		emails := singboxRelayEmails(inbound)
		if len(emails) == 0 {
			continue
		}
		if _, taken := existingTags[inbound.Tag]; taken {
			logger.Warning("singbox relay: inbound tag [", inbound.Tag, "] already present in generated config, skipping its relay inbound")
			continue
		}
		settings, err := singbox.SocksInboundSettings(emails, singbox.SocksPassword())
		if err != nil {
			logger.Warning("singbox relay: building settings for inbound [", inbound.Tag, "]: ", err)
			continue
		}
		existingTags[inbound.Tag] = struct{}{}
		cfg.InboundConfigs = append(cfg.InboundConfigs, xray.InboundConfig{
			Listen:   json_util.RawMessage(`"127.0.0.1"`),
			Port:     singbox.SOCKSPortForInbound(inbound.Id),
			Protocol: "socks",
			Settings: json_util.RawMessage(settings),
			Sniffing: json_util.RawMessage(singboxRelaySniffingSettings),
			Tag:      inbound.Tag,
		})
	}
}

// singboxRelayEmails includes disabled clients so toggling one only restarts
// the sidecar, never the relay; the sidecar alone decides who may log in.
func singboxRelayEmails(inbound *model.Inbound) []string {
	var parsed singbox.InboundSettings
	if err := json.Unmarshal([]byte(inbound.Settings), &parsed); err != nil {
		return nil
	}
	emails := make([]string, 0, len(parsed.Clients))
	for _, c := range parsed.Clients {
		if c.Email != "" {
			emails = append(emails, c.Email)
		}
	}
	slices.Sort(emails)
	return slices.Compact(emails)
}

func checkSingboxSocksConflict(db *gorm.DB, inbound *model.Inbound, ignoreId int, newBits transportBits) (*portConflictDetail, error) {
	if newBits&transportTCP == 0 {
		return nil, nil
	}
	var candidates []*model.Inbound
	q := db.Model(model.Inbound{}).Where("protocol = ? AND node_id IS NULL", model.AnyTLS)
	if ignoreId > 0 {
		q = q.Where("id != ?", ignoreId)
	}
	if err := q.Find(&candidates).Error; err != nil {
		return nil, err
	}
	for _, c := range candidates {
		if singbox.SOCKSPortForInbound(c.Id) != inbound.Port {
			continue
		}
		return &portConflictDetail{
			InboundID:  c.Id,
			Remark:     c.Remark,
			Tag:        c.Tag,
			Listen:     "127.0.0.1",
			Port:       inbound.Port,
			Relay:      true,
			Transports: transportTCP,
		}, nil
	}
	return nil, nil
}

func checkSingboxSocksRelayCollision(db *gorm.DB, id int) (*portConflictDetail, error) {
	relayPort := singbox.SOCKSPortForInbound(id)
	var candidates []*model.Inbound
	if err := db.Model(model.Inbound{}).
		Where("protocol = ? AND node_id IS NULL AND id != ?", model.AnyTLS, id).
		Find(&candidates).Error; err != nil {
		return nil, err
	}
	for _, c := range candidates {
		if singbox.SOCKSPortForInbound(c.Id) != relayPort {
			continue
		}
		return &portConflictDetail{
			InboundID:  c.Id,
			Remark:     c.Remark,
			Tag:        c.Tag,
			Listen:     "127.0.0.1",
			Port:       relayPort,
			Relay:      true,
			Transports: transportTCP,
		}, nil
	}
	return nil, nil
}

func singboxSocksSelfConflict(inbound *model.Inbound, id int) string {
	if id <= 0 || inbound.NodeID != nil || !listenOverlaps(loopbackBind, inboundBindAddr(inbound)) {
		return ""
	}
	relayPort := singbox.SOCKSPortForInbound(id)
	if inbound.Port != relayPort {
		return ""
	}
	return fmt.Sprintf("AnyTLS port %d is inbound #%d's own SOCKS5 relay port on 127.0.0.1; choose a different port",
		relayPort, id)
}

func checkSingboxSocksReverseConflict(db *gorm.DB, id int) (*portConflictDetail, error) {
	relayPort := singbox.SOCKSPortForInbound(id)
	var candidates []*model.Inbound
	if err := db.Model(model.Inbound{}).
		Where("port = ? AND node_id IS NULL AND id != ?", relayPort, id).
		Find(&candidates).Error; err != nil {
		return nil, err
	}
	for _, c := range candidates {
		if !listenOverlaps(loopbackBind, inboundBindAddr(c)) {
			continue
		}
		if inboundTransports(c.Protocol, c.StreamSettings, c.Settings)&transportTCP == 0 {
			continue
		}
		return &portConflictDetail{
			InboundID:  c.Id,
			Remark:     c.Remark,
			Tag:        c.Tag,
			Listen:     c.Listen,
			Port:       relayPort,
			Relay:      true,
			Transports: transportTCP,
		}, nil
	}
	return nil, nil
}

// singboxRelayConflict runs the checks that need the row id: the inbound's own
// relay port, another AnyTLS row sharing it, and a loopback row already on it.
func singboxRelayConflict(db *gorm.DB, inbound *model.Inbound, id int) (*portConflictDetail, error) {
	if self := singboxSocksSelfConflict(inbound, id); self != "" {
		return nil, common.NewError(self)
	}
	conflict, err := checkSingboxSocksRelayCollision(db, id)
	if err != nil || conflict != nil {
		return conflict, err
	}
	return checkSingboxSocksReverseConflict(db, id)
}
