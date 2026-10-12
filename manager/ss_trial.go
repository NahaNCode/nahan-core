package manager

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/NahaNCode/nahan-core/api"
	"github.com/NahaNCode/nahan-core/app/xdispatcher"
	"github.com/NahaNCode/nahan-core/utility/entryprofile"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/infra/conf"
	"math/big"
	"sync"
	"time"
)

type ssTrial struct {
	sealed  entryprofile.SealedResult
	expires time.Time
	server  *core.Instance
}

var ssTrialLifetime = time.Hour

var trials = struct {
	sync.Mutex
	items map[string]ssTrial
}{items: map[string]ssTrial{}}

// Trials share the current dispatcher but never alter the source listener.
func (m *Manager) SSTrial(input json.RawMessage, coreID, jobID string) (entryprofile.SealedResult, error) {
	m.statusLock.Lock()
	defer m.statusLock.Unlock()
	trials.Lock()
	defer trials.Unlock()
	var empty entryprofile.SealedResult
	if m.Server == nil {
		return empty, errors.New("runtime unavailable")
	}
	for id, trial := range trials.items {
		if time.Now().After(trial.expires) || trial.server != m.Server {
			delete(trials.items, id)
		}
	}
	if existing, ok := trials.items[jobID]; ok {
		return existing.sealed, nil
	}
	if len(trials.items) >= 4 {
		return empty, errors.New("too many active trials")
	}
	var payload struct {
		Profile   json.RawMessage `json:"profile"`
		Address   string          `json:"address"`
		PublicKey string          `json:"publicKey"`
	}
	if json.Unmarshal(input, &payload) != nil {
		return empty, errors.New("invalid payload")
	}
	var source struct {
		Protocol string `json:"protocol"`
		Listen   string `json:"listen"`
		Settings struct {
			Method  string `json:"method"`
			Network string `json:"network"`
		} `json:"settings"`
	}
	if json.Unmarshal(payload.Profile, &source) != nil || source.Protocol != "shadowsocks" {
		return empty, errors.New("unsupported trial")
	}
	size := 32
	switch source.Settings.Method {
	case "2022-blake3-aes-128-gcm":
		size = 16
	case "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305", "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305":
	default:
		return empty, errors.New("unsupported cipher")
	}
	secret := make([]byte, size)
	if _, err := rand.Read(secret); err != nil {
		return empty, err
	}
	password := base64.StdEncoding.EncodeToString(secret)
	tag := "nahan-ss-trial-" + jobID
	for attempt := 0; attempt < 32; attempt++ {
		offset, err := rand.Int(rand.Reader, big.NewInt(10000))
		if err != nil {
			return empty, err
		}
		port := 40000 + int(offset.Int64())
		email := fmt.Sprintf("%s|trial|%d", tag, port)
		profile := map[string]any{"protocol": "shadowsocks", "listen": source.Listen, "port": port, "tag": tag, "settings": map[string]any{"method": source.Settings.Method, "password": password, "network": source.Settings.Network, "email": email}}
		raw, _ := json.Marshal(profile)
		var config conf.InboundDetourConfig
		if json.Unmarshal(raw, &config) != nil {
			return empty, errors.New("invalid trial profile")
		}
		built, err := config.Build()
		if err != nil {
			return empty, errors.New("trial rejected")
		}
		if err = core.AddInboundHandler(m.Server, built); err != nil {
			continue
		}
		payload.Profile = raw
		request, _ := json.Marshal(payload)
		sealed, err := entryprofile.SealSSConfig(request, "", coreID, jobID)
		handler := m.Server.GetFeature(inbound.ManagerType()).(inbound.Manager)
		if err != nil {
			_ = handler.RemoveHandler(context.Background(), tag)
			return empty, err
		}
		trial := ssTrial{sealed: sealed, expires: time.Now().Add(ssTrialLifetime), server: m.Server}
		dispatcher := m.Server.GetFeature(routing.DispatcherType()).(*xdispatcher.DefaultDispatcher)
		users := []api.SubscriptionInfo{{UID: port, Email: "trial", SpeedLimit: 10 * 1000000 / 8, DeviceLimit: 3}}
		if err := dispatcher.Limiter.AddInboundLimiter(tag, 0, &users, nil); err != nil {
			_ = handler.RemoveHandler(context.Background(), tag)
			return empty, err
		}
		dispatcher.LeaseUser(email, trial.expires)
		trials.items[jobID] = trial
		time.AfterFunc(ssTrialLifetime, func() {
			dispatcher.RevokeUser(email)
			_ = handler.RemoveHandler(context.Background(), tag)
			dispatcher.Limiter.RemoveUser(tag, email)
			_ = dispatcher.Limiter.DeleteInboundLimiter(tag)
			trials.Lock()
			delete(trials.items, jobID)
			trials.Unlock()
		})
		return sealed, nil
	}
	return empty, errors.New("no trial port available")
}
