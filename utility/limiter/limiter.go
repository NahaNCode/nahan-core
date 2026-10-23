// Package limiter is to control the links that go into the dispatcher
package limiter

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/NahaNCode/nahan-core/api"
	"golang.org/x/time/rate"
)

type SubscriptionInfo struct {
	GlobalIPLimit bool
	UID           int
	ServiceID     int
	DeviceID      int
	SpeedLimit    uint64
	DeviceLimit   int
}

type onlineActivity struct {
	uid      int
	at       time.Time
	first    time.Time
	route    string
	revision int64
}

type presenceKey struct {
	ip, route string
	revision  int64
}

// TouchOnline refreshes activity on existing streams as well as new connections.
func (l *Limiter) TouchOnline(tag, email, ip string) {
	l.TouchOnlineRoute(tag, email, ip, "", 0)
}

func (l *Limiter) TouchOnlineRoute(tag, email, ip, route string, revision int64) {
	var valid bool
	ip, valid = canonicalIP(ip)
	if !valid {
		return
	}
	if value, ok := l.InboundInfo.Load(tag); ok {
		inbound := value.(*InboundInfo)
		if user, ok := inbound.SubscriptionInfo.Load(email); ok {
			ips, _ := inbound.SubscriptionOnlineIP.LoadOrStore(email, new(sync.Map))
			u := user.(SubscriptionInfo)
			if u.DeviceID > 0 && inbound.DeviceGate != nil {
				inbound.DeviceGate.TouchDevice(u.DeviceID)
			}
			if u.GlobalIPLimit {
				if gate, ok := inbound.DeviceGate.(api.IPGate); ok {
					gate.TouchIP(u.UID, ip)
				}
			}
			l.presenceMu.Lock()
			m := ips.(*sync.Map)
			var key interface{} = presenceKey{ip, route, revision}
			if u.DeviceID == 0 {
				key = ip
			}
			now := time.Now()
			activity := onlineActivity{uid: u.UID, at: now, first: now, route: route, revision: revision}
			if u.DeviceID > 0 && route != "" {
				blank := presenceKey{ip: ip}
				if v, exists := m.LoadAndDelete(blank); exists {
					activity.first = v.(onlineActivity).first
				}
			}
			count := 0
			var oldestKey interface{}
			oldest := now
			m.Range(func(k, v interface{}) bool {
				a := v.(onlineActivity)
				if now.Sub(a.at) >= 120*time.Second {
					m.Delete(k)
					return true
				}
				count++
				if a.at.Before(oldest) {
					oldest, oldestKey = a.at, k
				}
				return true
			})
			if v, exists := m.Load(key); exists {
				activity.first = v.(onlineActivity).first
			} else if count >= 64 && oldestKey != nil {
				m.Delete(oldestKey)
			}
			m.Store(key, activity)
			l.presenceMu.Unlock()
			if u.DeviceID == 0 {
				shared, _ := l.serviceIPs.LoadOrStore(bucketKey(email, u), new(sync.Map))
				shared.(*sync.Map).Store(ip, now)
			}
		}
	}
}

type InboundInfo struct {
	DeviceGate           api.DeviceGate
	Tag                  string
	NodeSpeedLimit       uint64
	SubscriptionInfo     *sync.Map // Key: Email value: SubscriptionInfo
	BucketHub            *sync.Map // key: Email, value: *rate.Limiter
	SubscriptionOnlineIP *sync.Map // Key: Email, value: {Key: IP, value: UID}
	GlobalIPLimit        *globalIPState
}

type Limiter struct {
	InboundInfo    *sync.Map // Key: Tag, Value: *InboundInfo
	serviceBuckets sync.Map
	serviceIPs     sync.Map
	deviceMu       sync.Mutex
	presenceMu     sync.Mutex
	rateMu         sync.Mutex
	serviceLimits  map[string]uint64
}

func bucketKey(email string, u SubscriptionInfo) string {
	if u.ServiceID > 0 {
		return fmt.Sprintf("service:%d", u.ServiceID)
	}
	return serviceKey(email)
}

// DeviceValid is a local-only traffic-path check, including user removal.
func (l *Limiter) DeviceValid(tag, email string) bool {
	v, ok := l.InboundInfo.Load(tag)
	if !ok {
		return false
	}
	inbound := v.(*InboundInfo)
	v, ok = inbound.SubscriptionInfo.Load(email)
	if !ok {
		return false
	}
	u := v.(SubscriptionInfo)
	return u.DeviceID == 0 || (inbound.DeviceGate != nil && inbound.DeviceGate.ValidDevice(u.DeviceID))
}

// ConnectionValid is local-only; distributed lease checks never perform I/O
// inside packet readers/writers. Authentication and assignment removal still win.
func (l *Limiter) ConnectionValid(tag, email, ip string) bool {
	if !l.DeviceValid(tag, email) {
		return false
	}
	value, ok := l.InboundInfo.Load(tag)
	if !ok {
		return false
	}
	inbound := value.(*InboundInfo)
	v, ok := inbound.SubscriptionInfo.Load(email)
	if !ok {
		return false
	}
	u := v.(SubscriptionInfo)
	if !u.GlobalIPLimit {
		return true
	}
	gate, ok := inbound.DeviceGate.(api.IPGate)
	return ok && gate.ValidIP(u.UID, ip)
}

func serviceKey(email string) string {
	if index := strings.IndexByte(email, '|'); index >= 0 {
		return email[index+1:]
	}
	return email
}

func New() *Limiter {
	return &Limiter{
		InboundInfo: new(sync.Map),
	}
}

func (l *Limiter) AddInboundLimiter(tag string, nodeSpeedLimit uint64, serviceList *[]api.SubscriptionInfo, globalLimit *IPLimit, gates ...api.DeviceGate) error {
	inboundInfo := &InboundInfo{
		Tag:                  tag,
		NodeSpeedLimit:       nodeSpeedLimit,
		BucketHub:            new(sync.Map),
		SubscriptionOnlineIP: new(sync.Map),
	}
	if len(gates) > 0 {
		inboundInfo.DeviceGate = gates[0]
	}

	global, err := newGlobalIP(globalLimit)
	if err != nil {
		return err
	}
	inboundInfo.GlobalIPLimit = global

	serviceMap := new(sync.Map)
	for _, u := range *serviceList {
		serviceMap.Store(fmt.Sprintf("%s|%s|%d", tag, u.Email, u.UID), SubscriptionInfo{
			GlobalIPLimit: u.GlobalIPLimit,
			UID:           u.UID,
			ServiceID:     u.ServiceID, DeviceID: u.DeviceID,
			SpeedLimit:  u.SpeedLimit,
			DeviceLimit: u.DeviceLimit,
		})
	}
	inboundInfo.SubscriptionInfo = serviceMap
	old, replaced := l.InboundInfo.Swap(tag, inboundInfo)
	if replaced && old.(*InboundInfo).GlobalIPLimit != nil {
		old.(*InboundInfo).GlobalIPLimit.client.Close()
	}
	l.refreshServiceRates()
	return nil
}

func (l *Limiter) UpdateInboundLimiter(tag string, updatedServiceList *[]api.SubscriptionInfo) error {
	if value, ok := l.InboundInfo.Load(tag); ok {
		inboundInfo := value.(*InboundInfo)
		// Update User info
		for _, u := range *updatedServiceList {
			inboundInfo.SubscriptionInfo.Store(fmt.Sprintf("%s|%s|%d", tag, u.Email, u.UID), SubscriptionInfo{
				GlobalIPLimit: u.GlobalIPLimit,
				UID:           u.UID,
				ServiceID:     u.ServiceID, DeviceID: u.DeviceID,
				SpeedLimit:  u.SpeedLimit,
				DeviceLimit: u.DeviceLimit,
			})
		}
		l.refreshServiceRates()
	} else {
		return fmt.Errorf("no such inbound in limiter: %s", tag)
	}
	return nil
}

// Infrastructure users share the node limit but never a customer's billing ID.
func (l *Limiter) AddInfrastructureUser(tag, email string) error {
	if !strings.HasPrefix(email, "nahan-egress/") || len(email) > 256 {
		return fmt.Errorf("invalid infrastructure identity")
	}
	value, ok := l.InboundInfo.Load(tag)
	if !ok {
		return fmt.Errorf("no such inbound in limiter: %s", tag)
	}
	if _, exists := value.(*InboundInfo).SubscriptionInfo.LoadOrStore(email, SubscriptionInfo{UID: 0}); exists {
		return fmt.Errorf("infrastructure limiter identity already exists")
	}
	l.refreshServiceRates()
	return nil
}

func (l *Limiter) DeleteInboundLimiter(tag string) error {
	var users []string
	if value, ok := l.InboundInfo.Load(tag); ok {
		if g := value.(*InboundInfo).GlobalIPLimit; g != nil {
			defer g.client.Close()
		}
		value.(*InboundInfo).SubscriptionInfo.Range(func(key, value interface{}) bool { users = append(users, key.(string)); return true })
	}
	for _, email := range users {
		l.RemoveUser(tag, email)
	}
	l.InboundInfo.Delete(tag)
	l.refreshServiceRates()
	return nil
}

func (l *Limiter) RemoveUser(tag, email string) {
	key := serviceKey(email)
	if value, ok := l.InboundInfo.Load(tag); ok {
		inbound := value.(*InboundInfo)
		if user, ok := inbound.SubscriptionInfo.Load(email); ok {
			key = bucketKey(email, user.(SubscriptionInfo))
		}
		inbound.SubscriptionInfo.Delete(email)
		inbound.BucketHub.Delete(email)
		inbound.SubscriptionOnlineIP.Delete(email)
	}
	remaining := false
	l.InboundInfo.Range(func(tag, value interface{}) bool {
		value.(*InboundInfo).SubscriptionInfo.Range(func(email, value interface{}) bool {
			if bucketKey(email.(string), value.(SubscriptionInfo)) == key {
				remaining = true
			}
			return !remaining
		})
		return !remaining
	})
	if !remaining {
		l.serviceBuckets.Delete(key)
		l.serviceIPs.Delete(key)
	}
	l.refreshServiceRates()
}

func (l *Limiter) GetOnlineDevice(tag string) (*[]api.OnlineIP, error) {
	var onlineIP []api.OnlineIP

	if value, ok := l.InboundInfo.Load(tag); ok {
		inboundInfo := value.(*InboundInfo)
		if inboundInfo.GlobalIPLimit != nil {
			inboundInfo.GlobalIPLimit.renew(inboundInfo)
		}
		// Clear Speed Limiter bucket for users who are not online
		inboundInfo.BucketHub.Range(func(key, value interface{}) bool {
			email := key.(string)
			if _, exists := inboundInfo.SubscriptionOnlineIP.Load(email); !exists {
				inboundInfo.BucketHub.Delete(email)
			}
			return true
		})
		inboundInfo.SubscriptionOnlineIP.Range(func(key, value interface{}) bool {
			ipMap := value.(*sync.Map)
			ipMap.Range(func(key, value interface{}) bool {
				activity := value.(onlineActivity)
				if time.Since(activity.at) > 2*time.Minute {
					ipMap.CompareAndDelete(key, value)
					return true
				}
				uid := activity.uid
				if uid <= 0 {
					return true
				}
				ip, legacy := key.(string)
				if !legacy {
					ip = key.(presenceKey).ip
				}
				onlineIP = append(onlineIP, api.OnlineIP{UID: uid, IP: ip, FirstSeen: activity.first.Unix(), LastSeen: activity.at.Unix(), RouteTag: activity.route, RouteRevision: activity.revision})
				return true
			})
			return true
		})
	} else {
		return nil, fmt.Errorf("no such inbound in limiter: %s", tag)
	}

	return &onlineIP, nil
}

func (l *Limiter) GetUserBucket(tag string, email string, ip string) (limiter *rate.Limiter, SpeedLimit bool, Reject bool) {
	if value, ok := l.InboundInfo.Load(tag); ok {
		var deviceLimit, uid int

		inboundInfo := value.(*InboundInfo)
		var user SubscriptionInfo

		if v, ok := inboundInfo.SubscriptionInfo.Load(email); ok {
			u := v.(SubscriptionInfo)
			user = u
			uid = u.UID
			deviceLimit = u.DeviceLimit
		} else {
			return nil, false, true
		}

		if user.DeviceID > 0 {
			if inboundInfo.DeviceGate == nil || !inboundInfo.DeviceGate.AdmitDevice(user.DeviceID) {
				return nil, false, true
			}
		} else {
			var valid bool
			ip, valid = canonicalIP(ip)
			if !valid {
				return nil, false, true
			}
			coordinated := false
			if user.GlobalIPLimit {
				gate, ok := inboundInfo.DeviceGate.(api.IPGate)
				if !ok || !gate.AdmitIP(user.UID, ip) {
					return nil, false, true
				}
				coordinated = true
			} else if inboundInfo.GlobalIPLimit != nil {
				allowed, shared := inboundInfo.GlobalIPLimit.admit(email, user, ip)
				if !allowed {
					return nil, false, true
				}
				coordinated = shared
			}
			// Legacy IP limits are deliberately excluded from registered-device mode.
			key := bucketKey(email, user)
			l.deviceMu.Lock()
			shared, _ := l.serviceIPs.LoadOrStore(key, new(sync.Map))
			sharedIPs := shared.(*sync.Map)
			count := 0
			sharedIPs.Range(func(k, value interface{}) bool {
				if time.Since(value.(time.Time)) > 2*time.Minute {
					sharedIPs.Delete(k)
				} else {
					count++
				}
				return true
			})
			_, known := sharedIPs.Load(ip)
			if !coordinated && !known && deviceLimit > 0 && count >= deviceLimit {
				l.deviceMu.Unlock()
				return nil, false, true
			}
			sharedIPs.Store(ip, time.Now())
			l.deviceMu.Unlock()
			ipMap := new(sync.Map)
			ipMap.Store(ip, onlineActivity{uid: uid, at: time.Now(), first: time.Now()})
			// If any device is online
			if v, ok := inboundInfo.SubscriptionOnlineIP.LoadOrStore(email, ipMap); ok {
				ipMap := v.(*sync.Map)
				// If this is a new ip
				if _, ok := ipMap.LoadOrStore(ip, onlineActivity{uid: uid, at: time.Now(), first: time.Now()}); !ok {
					counter := 0
					ipMap.Range(func(key, value interface{}) bool {
						if time.Since(value.(onlineActivity).at) > 2*time.Minute {
							ipMap.CompareAndDelete(key, value)
							return true
						}
						counter++
						return true
					})
					if !coordinated && counter > deviceLimit && deviceLimit > 0 {
						ipMap.Delete(ip)
						return nil, false, true
					}
				}
			}

		}
		if user.DeviceID > 0 {
			l.TouchOnline(tag, email, ip)
		}

		// Speed limit
		l.rateMu.Lock()
		defer l.rateMu.Unlock()
		limit := l.serviceLimits[bucketKey(email, user)]
		if limit > 0 {
			limiter := rate.NewLimiter(rate.Limit(limit), int(limit)) // Byte/s
			if v, ok := l.serviceBuckets.LoadOrStore(bucketKey(email, user), limiter); ok {
				bucket := v.(*rate.Limiter)
				return bucket, true, false
			} else {
				return limiter, true, false
			}
		} else {
			bucket, _ := l.serviceBuckets.LoadOrStore(bucketKey(email, user), rate.NewLimiter(rate.Inf, 65536))
			return bucket.(*rate.Limiter), false, false
		}
	} else {
		newError("Get Inbound Limiter information failed")
		return nil, false, true
	}
}

// determineRate returns the minimum non-zero rate
func determineRate(nodeLimit, SubscriptionLimit uint64) (limit uint64) {
	if nodeLimit == 0 {
		return SubscriptionLimit
	}
	if SubscriptionLimit == 0 || nodeLimit < SubscriptionLimit {
		return nodeLimit
	}
	return SubscriptionLimit
}
