// Package limiter is to control the links that go into the dispatcher
package limiter

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/NahaNCode/nahan-core/api"
	"github.com/eko/gocache/lib/v4/cache"
	"github.com/eko/gocache/lib/v4/marshaler"
	"github.com/eko/gocache/lib/v4/store"
	goCacheStore "github.com/eko/gocache/store/go_cache/v4"
	redisStore "github.com/eko/gocache/store/redis/v4"
	goCache "github.com/patrickmn/go-cache"
	"github.com/redis/go-redis/v9"
	"golang.org/x/time/rate"
)

type SubscriptionInfo struct {
	UID         int
	SpeedLimit  uint64
	DeviceLimit int
}

type onlineActivity struct {
	uid int
	at  time.Time
}

// TouchOnline refreshes activity on existing streams as well as new connections.
func (l *Limiter) TouchOnline(tag, email, ip string) {
	if value, ok := l.InboundInfo.Load(tag); ok {
		inbound := value.(*InboundInfo)
		if user, ok := inbound.SubscriptionInfo.Load(email); ok {
			ips, _ := inbound.SubscriptionOnlineIP.LoadOrStore(email, new(sync.Map))
			ips.(*sync.Map).Store(ip, onlineActivity{user.(SubscriptionInfo).UID, time.Now()})
			shared, _ := l.serviceIPs.LoadOrStore(serviceKey(email), new(sync.Map))
			shared.(*sync.Map).Store(ip, time.Now())
		}
	}
}

type InboundInfo struct {
	Tag                  string
	NodeSpeedLimit       uint64
	SubscriptionInfo     *sync.Map // Key: Email value: SubscriptionInfo
	BucketHub            *sync.Map // key: Email, value: *rate.Limiter
	SubscriptionOnlineIP *sync.Map // Key: Email, value: {Key: IP, value: UID}
	GlobalIPLimit        struct {
		config         *IPLimit
		globalOnlineIP *marshaler.Marshaler
	}
}

type Limiter struct {
	InboundInfo    *sync.Map // Key: Tag, Value: *InboundInfo
	serviceBuckets sync.Map
	serviceIPs     sync.Map
	deviceMu       sync.Mutex
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

func (l *Limiter) AddInboundLimiter(tag string, nodeSpeedLimit uint64, serviceList *[]api.SubscriptionInfo, globalLimit *IPLimit) error {
	inboundInfo := &InboundInfo{
		Tag:                  tag,
		NodeSpeedLimit:       nodeSpeedLimit,
		BucketHub:            new(sync.Map),
		SubscriptionOnlineIP: new(sync.Map),
	}

	if globalLimit != nil && globalLimit.Enable {
		inboundInfo.GlobalIPLimit.config = globalLimit

		// init local store
		gs := goCacheStore.NewGoCache(goCache.New(time.Duration(globalLimit.Expiry)*time.Second, 1*time.Minute))

		// init redis store
		rs := redisStore.NewRedis(redis.NewClient(
			&redis.Options{
				Network:  globalLimit.RedisNetwork,
				Addr:     globalLimit.RedisAddr,
				Username: globalLimit.RedisUsername,
				Password: globalLimit.RedisPassword,
				DB:       globalLimit.RedisDB,
			}),
			store.WithExpiration(time.Duration(globalLimit.Expiry)*time.Second))

		// init chained cache. First use local go-cache, if go-cache is nil, then use redis cache
		cacheManager := cache.NewChain[any](
			cache.New[any](gs), // go-cache is priority
			cache.New[any](rs),
		)
		inboundInfo.GlobalIPLimit.globalOnlineIP = marshaler.New(cacheManager)
	}

	serviceMap := new(sync.Map)
	for _, u := range *serviceList {
		serviceMap.Store(fmt.Sprintf("%s|%s|%d", tag, u.Email, u.UID), SubscriptionInfo{
			UID:         u.UID,
			SpeedLimit:  u.SpeedLimit,
			DeviceLimit: u.DeviceLimit,
		})
	}
	inboundInfo.SubscriptionInfo = serviceMap
	l.InboundInfo.Store(tag, inboundInfo) // Replace the old inbound info
	return nil
}

func (l *Limiter) UpdateInboundLimiter(tag string, updatedServiceList *[]api.SubscriptionInfo) error {
	if value, ok := l.InboundInfo.Load(tag); ok {
		inboundInfo := value.(*InboundInfo)
		// Update User info
		for _, u := range *updatedServiceList {
			inboundInfo.SubscriptionInfo.Store(fmt.Sprintf("%s|%s|%d", tag, u.Email, u.UID), SubscriptionInfo{
				UID:         u.UID,
				SpeedLimit:  u.SpeedLimit,
				DeviceLimit: u.DeviceLimit,
			})
			// Update old limiter bucket
			limit := determineRate(inboundInfo.NodeSpeedLimit, u.SpeedLimit)
			if limit > 0 {
				if bucket, ok := inboundInfo.BucketHub.Load(fmt.Sprintf("%s|%s|%d", tag, u.Email, u.UID)); ok {
					limiter := bucket.(*rate.Limiter)
					limiter.SetLimit(rate.Limit(limit))
					limiter.SetBurst(int(limit))
				}
			} else {
				inboundInfo.BucketHub.Delete(fmt.Sprintf("%s|%s|%d", tag, u.Email, u.UID))
			}
			key := fmt.Sprintf("%s|%d", u.Email, u.UID)
			if bucket, ok := l.serviceBuckets.Load(key); ok {
				if limit > 0 {
					bucket.(*rate.Limiter).SetLimit(rate.Limit(limit))
					bucket.(*rate.Limiter).SetBurst(int(limit))
				} else {
					l.serviceBuckets.Delete(key)
				}
			}
		}
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
	return nil
}

func (l *Limiter) DeleteInboundLimiter(tag string) error {
	var users []string
	if value, ok := l.InboundInfo.Load(tag); ok {
		value.(*InboundInfo).SubscriptionInfo.Range(func(key, value interface{}) bool { users = append(users, key.(string)); return true })
	}
	l.InboundInfo.Delete(tag)
	for _, email := range users {
		l.RemoveUser(tag, email)
	}
	return nil
}

func (l *Limiter) RemoveUser(tag, email string) {
	if value, ok := l.InboundInfo.Load(tag); ok {
		inbound := value.(*InboundInfo)
		inbound.SubscriptionInfo.Delete(email)
		inbound.BucketHub.Delete(email)
		inbound.SubscriptionOnlineIP.Delete(email)
	}
	key := serviceKey(email)
	remaining := false
	l.InboundInfo.Range(func(tag, value interface{}) bool {
		value.(*InboundInfo).SubscriptionInfo.Range(func(email, value interface{}) bool {
			if serviceKey(email.(string)) == key {
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
}

func (l *Limiter) GetOnlineDevice(tag string) (*[]api.OnlineIP, error) {
	var onlineIP []api.OnlineIP

	if value, ok := l.InboundInfo.Load(tag); ok {
		inboundInfo := value.(*InboundInfo)
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
				ip := key.(string)
				onlineIP = append(onlineIP, api.OnlineIP{UID: uid, IP: ip})
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
		var (
			SubscriptionLimit uint64 = 0
			deviceLimit, uid  int
		)

		inboundInfo := value.(*InboundInfo)
		nodeLimit := inboundInfo.NodeSpeedLimit

		if v, ok := inboundInfo.SubscriptionInfo.Load(email); ok {
			u := v.(SubscriptionInfo)
			uid = u.UID
			SubscriptionLimit = u.SpeedLimit
			deviceLimit = u.DeviceLimit
		} else {
			return nil, false, true
		}

		// Local device limit
		key := serviceKey(email)
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
		if !known && deviceLimit > 0 && count >= deviceLimit {
			l.deviceMu.Unlock()
			return nil, false, true
		}
		sharedIPs.Store(ip, time.Now())
		l.deviceMu.Unlock()
		ipMap := new(sync.Map)
		ipMap.Store(ip, onlineActivity{uid, time.Now()})
		// If any device is online
		if v, ok := inboundInfo.SubscriptionOnlineIP.LoadOrStore(email, ipMap); ok {
			ipMap := v.(*sync.Map)
			// If this is a new ip
			if _, ok := ipMap.LoadOrStore(ip, onlineActivity{uid, time.Now()}); !ok {
				counter := 0
				ipMap.Range(func(key, value interface{}) bool {
					if time.Since(value.(onlineActivity).at) > 2*time.Minute {
						ipMap.CompareAndDelete(key, value)
						return true
					}
					counter++
					return true
				})
				if counter > deviceLimit && deviceLimit > 0 {
					ipMap.Delete(ip)
					return nil, false, true
				}
			}
		}

		// GlobalLimit
		if inboundInfo.GlobalIPLimit.config != nil && inboundInfo.GlobalIPLimit.config.Enable {
			if reject := globalLimit(inboundInfo, email, uid, ip, deviceLimit); reject {
				return nil, false, true
			}
		}

		// Speed limit
		limit := determineRate(nodeLimit, SubscriptionLimit) // Determine the speed limit rate
		if limit > 0 {
			limiter := rate.NewLimiter(rate.Limit(limit), int(limit)) // Byte/s
			if v, ok := l.serviceBuckets.LoadOrStore(serviceKey(email), limiter); ok {
				bucket := v.(*rate.Limiter)
				return bucket, true, false
			} else {
				return limiter, true, false
			}
		} else {
			return nil, false, false
		}
	} else {
		newError("Get Inbound Limiter information failed").AtDebug()
		return nil, false, true
	}
}

// Global device limit
func globalLimit(inboundInfo *InboundInfo, email string, uid int, ip string, deviceLimit int) bool {

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(inboundInfo.GlobalIPLimit.config.Timeout)*time.Second)
	defer cancel()

	// reformat email for unique key
	uniqueKey := strings.Replace(email, inboundInfo.Tag, strconv.Itoa(deviceLimit), 1)

	v, err := inboundInfo.GlobalIPLimit.globalOnlineIP.Get(ctx, uniqueKey, new(map[string]int))
	if err != nil {
		if _, ok := err.(*store.NotFound); ok {
			// If the email is a new device
			go pushIP(inboundInfo, uniqueKey, &map[string]int{ip: uid})
		} else {
			newError("cache service").Base(err).AtError()
		}
		return false
	}

	ipMap := v.(*map[string]int)
	// Reject device reach limit directly
	if deviceLimit > 0 && len(*ipMap) > deviceLimit {
		return true
	}

	// If the ip is not in cache
	if _, ok := (*ipMap)[ip]; !ok {
		(*ipMap)[ip] = uid
		go pushIP(inboundInfo, uniqueKey, ipMap)
	}

	return false
}

// push the ip to cache
func pushIP(inboundInfo *InboundInfo, uniqueKey string, ipMap *map[string]int) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(inboundInfo.GlobalIPLimit.config.Timeout)*time.Second)
	defer cancel()

	if err := inboundInfo.GlobalIPLimit.globalOnlineIP.Set(ctx, uniqueKey, ipMap); err != nil {
		newError("cache service").Base(err).AtError()
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
