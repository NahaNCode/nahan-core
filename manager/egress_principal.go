package manager

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/NahaNCode/nahan-core/app/xdispatcher"
	"github.com/NahaNCode/nahan-core/utility/egress"
	"github.com/NahaNCode/nahan-core/utility/entryprofile"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/trojan"
	"github.com/xtls/xray-core/proxy/vless"
	vlessin "github.com/xtls/xray-core/proxy/vless/inbound"
	"github.com/xtls/xray-core/proxy/vmess"
	vmessin "github.com/xtls/xray-core/proxy/vmess/inbound"
)

type PrincipalRequest struct {
	Scope     egress.CredentialScope `json:"scope"`
	Tag       string                 `json:"tag"`
	Protocol  string                 `json:"protocol"`
	Flow      string                 `json:"flow"`
	PublicKey string                 `json:"publicKey"`
	Staged    bool                   `json:"staged,omitempty"`
}

func principalKey(r PrincipalRequest) string {
	key := r.Scope.RouteID + "/" + r.Scope.SourceCoreID
	if r.Staged {
		key += fmt.Sprintf("/staged/%d", r.Scope.Revision)
	}
	return key
}

type principalLease struct {
	request    PrincipalRequest
	credential egress.PrincipalCredential
	users      proxy.UserManager
	dispatcher *xdispatcher.DefaultDispatcher
	email      string
	timer      *time.Timer
	revoked    bool
}

func principalUser(p egress.PrincipalCredential, email string) (*protocol.MemoryUser, error) {
	u := &protocol.User{Email: email}
	switch p.Protocol {
	case "vless":
		u.Account = serial.ToTypedMessage(&vless.Account{Id: p.ID, Flow: p.Flow})
	case "vmess":
		u.Account = serial.ToTypedMessage(&vmess.Account{Id: p.ID})
	case "trojan":
		u.Account = serial.ToTypedMessage(&trojan.Account{Password: p.Password})
	default:
		return nil, errors.New("unsupported infrastructure protocol")
	}
	return u.ToMemoryUser()
}

func (m *Manager) principalTarget(tag, kind string) (proxy.UserManager, error) {
	if m.Server == nil || !m.Running {
		return nil, errors.New("principal runtime unavailable")
	}
	handler, err := m.Server.GetFeature(inbound.ManagerType()).(inbound.Manager).GetHandler(context.Background(), tag)
	if err != nil {
		return nil, errors.New("principal destination unavailable")
	}
	config, err := handler.ProxySettings().GetInstance()
	if err != nil {
		return nil, errors.New("principal destination config unavailable")
	}
	switch c := config.(type) {
	case *vlessin.Config:
		if kind != "vless" || c.Decryption != "none" {
			return nil, errors.New("principal destination protocol mismatch or unsupported encryption")
		}
	case *vmessin.Config:
		if kind != "vmess" {
			return nil, errors.New("principal destination protocol mismatch")
		}
	case *trojan.ServerConfig:
		if kind != "trojan" {
			return nil, errors.New("principal destination protocol mismatch")
		}
	default:
		return nil, errors.New("unsupported principal destination")
	}
	getter, ok := handler.(proxy.GetInbound)
	if !ok {
		return nil, errors.New("principal destination cannot manage users")
	}
	users, ok := getter.GetInbound().(proxy.UserManager)
	if !ok {
		return nil, errors.New("principal destination cannot manage users")
	}
	return users, nil
}

// ProvisionEgressPrincipal changes only a dedicated user on the existing handler.
// It returns a source-sealed credential; no customer identity is read or exported.
func (m *Manager) ProvisionEgressPrincipal(coreID string, r PrincipalRequest) (entryprofile.SealedResult, error) {
	m.statusLock.Lock()
	defer m.statusLock.Unlock()
	var empty entryprofile.SealedResult
	if _, err := r.Scope.Label(); err != nil || coreID != r.Scope.TargetCoreID {
		return empty, errors.New("principal scope rejected")
	}
	users, err := m.principalTarget(r.Tag, r.Protocol)
	if err != nil {
		return empty, err
	}
	key := principalKey(r)
	previous := m.principals[key]
	if previous != nil && r.Scope.Revision < previous.request.Scope.Revision {
		return empty, errors.New("stale principal revision")
	}
	if previous != nil && r.Scope.Revision == previous.request.Scope.Revision {
		old := previous.request
		if previous.revoked || time.Now().Unix() >= old.Scope.ExpiresAt || old.Tag != r.Tag || old.Protocol != r.Protocol || old.Flow != r.Flow || old.PublicKey != r.PublicKey || old.Scope.TargetCoreID != r.Scope.TargetCoreID || users != previous.users || r.Scope.ExpiresAt < old.Scope.ExpiresAt {
			return empty, errors.New("principal identity changed or expired")
		}
		sealed, err := egress.SealPrincipal(previous.credential, r.PublicKey, coreID, r.Scope)
		if err != nil {
			return empty, err
		}
		if m.managerConfig.PrincipalStore != nil {
			if err := m.managerConfig.PrincipalStore.save(principalRecord{Request: r, Credential: previous.credential}); err != nil {
				return empty, err
			}
		}
		previous.request = r
		m.armPrincipal(key, previous)
		return sealed, nil
	}
	if m.principalInstalls >= 512 {
		return empty, errors.New("principal registry capacity reached")
	}
	credential, err := egress.NewPrincipalCredential(r.Protocol, r.Flow)
	if err != nil {
		return empty, err
	}
	if previous == nil && m.managerConfig.PrincipalStore != nil {
		saved, loadErr := m.managerConfig.PrincipalStore.load(r)
		if loadErr != nil {
			return empty, loadErr
		}
		if saved != nil {
			old := saved.Request
			if r.Scope.Revision < old.Scope.Revision {
				return empty, errors.New("stale journaled principal revision")
			}
			if r.Scope.Revision == old.Scope.Revision {
				if saved.Revoked || time.Now().Unix() >= old.Scope.ExpiresAt || old.Tag != r.Tag || old.Protocol != r.Protocol || old.Flow != r.Flow || old.PublicKey != r.PublicKey || old.Scope.TargetCoreID != r.Scope.TargetCoreID || r.Scope.ExpiresAt < old.Scope.ExpiresAt {
					return empty, errors.New("journaled principal changed or expired")
				}
				credential = saved.Credential
			}
		}
	}
	sealed, err := egress.SealPrincipal(credential, r.PublicKey, coreID, r.Scope)
	if err != nil {
		return empty, err
	}
	email := fmt.Sprintf("nahan-egress/%s/%s/%d", r.Scope.RouteID, r.Scope.SourceCoreID, r.Scope.Revision)
	if users.GetUser(context.Background(), email) != nil {
		return empty, errors.New("principal user identity already exists")
	}
	u, err := principalUser(credential, email)
	if err != nil {
		return empty, err
	}
	dispatcher := m.Server.GetFeature(routing.DispatcherType()).(*xdispatcher.DefaultDispatcher)
	if err = users.AddUser(context.Background(), u); err != nil {
		return empty, errors.New("principal install failed")
	}
	if err = dispatcher.Limiter.AddInfrastructureUser(r.Tag, email); err != nil {
		_ = users.RemoveUser(context.Background(), email)
		return empty, err
	}
	if m.managerConfig.PrincipalStore != nil {
		if err := m.managerConfig.PrincipalStore.save(principalRecord{Request: r, Credential: credential}); err != nil {
			_ = users.RemoveUser(context.Background(), email)
			dispatcher.Limiter.RemoveUser(r.Tag, email)
			return empty, err
		}
	}
	if previous != nil {
		m.removePrincipal(previous)
	}
	lease := &principalLease{request: r, credential: credential, users: users, dispatcher: dispatcher, email: email}
	if m.principals == nil {
		m.principals = map[string]*principalLease{}
	}
	m.principals[key] = lease
	m.principalInstalls++
	m.armPrincipal(key, lease)
	return sealed, nil
}

func (m *Manager) armPrincipal(key string, lease *principalLease) {
	if lease.timer != nil {
		lease.timer.Stop()
	}
	expires := lease.request.Scope.ExpiresAt
	deadline := time.Unix(expires, 0)
	lease.dispatcher.LeaseUser(lease.email, deadline)
	lease.timer = time.AfterFunc(time.Until(deadline), func() {
		m.statusLock.Lock()
		defer m.statusLock.Unlock()
		if m.principals[key] == lease && lease.request.Scope.ExpiresAt == expires {
			m.removePrincipal(lease)
		}
	})
}

func (m *Manager) removePrincipal(lease *principalLease) {
	if lease.timer != nil {
		lease.timer.Stop()
	}
	lease.dispatcher.RevokeUser(lease.email)
	_ = lease.users.RemoveUser(context.Background(), lease.email)
	lease.dispatcher.Limiter.RemoveUser(lease.request.Tag, lease.email)
	lease.credential = egress.PrincipalCredential{}
	lease.revoked = true
}

func (m *Manager) RevokeEgressPrincipal(routeID, sourceCoreID string, revision int64) error {
	m.statusLock.Lock()
	defer m.statusLock.Unlock()
	lease := m.principals[routeID+"/"+sourceCoreID]
	if lease == nil || lease.request.Scope.Revision != revision {
		lease = m.principals[fmt.Sprintf("%s/%s/staged/%d", routeID, sourceCoreID, revision)]
	}
	if lease == nil || lease.request.Scope.Revision != revision {
		return errors.New("principal revocation is stale")
	}
	if m.managerConfig.PrincipalStore != nil {
		if err := m.managerConfig.PrincipalStore.save(principalRecord{Request: lease.request, Revoked: true}); err != nil {
			return err
		}
	}
	m.removePrincipal(lease)
	return nil
}
