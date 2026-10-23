package controller

import (
	"fmt"
	"log"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/NahaNCode/nahan-core/api"
	"github.com/NahaNCode/nahan-core/app/xdispatcher"
	"github.com/NahaNCode/nahan-core/utility/limiter"
	"github.com/NahaNCode/nahan-core/utility/mylego"
	"github.com/NahaNCode/nahan-core/utility/rule"
	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	C "github.com/sagernet/sing/common"
	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/infra/conf"
)

type Controller struct {
	closed               atomic.Bool
	monitorMu            sync.Mutex
	retiredSubscriptions []api.SubscriptionInfo
	server               *core.Instance
	config               *Config
	clientInfo           api.ClientInfo
	apiClient            api.API
	nodeInfo             *api.NodeInfo
	Tag                  string
	subscriptionList     *[]api.SubscriptionInfo
	tasks                []periodicTask
	ibm                  inbound.Manager
	obm                  outbound.Manager
	stm                  stats.Manager
	dispatcher           *xdispatcher.DefaultDispatcher
	limiter              *limiter.Limiter
	ruleManager          *rule.Manager
	startAt              time.Time
	routerule            *router.Router
	RelayTag             string
	Relay                bool
	relaynodeInfo        *api.RelayNodeInfo
}

type periodicTask struct {
	tag string
	*task.Periodic
}

// New return a Controller service with default parameters.
func New(server *core.Instance, api api.API, config *Config) *Controller {
	controller := &Controller{
		server:     server,
		config:     config,
		apiClient:  api,
		ibm:        server.GetFeature(inbound.ManagerType()).(inbound.Manager),
		obm:        server.GetFeature(outbound.ManagerType()).(outbound.Manager),
		stm:        server.GetFeature(stats.ManagerType()).(stats.Manager),
		dispatcher: server.GetFeature(routing.DispatcherType()).(*xdispatcher.DefaultDispatcher),
		routerule:  server.GetFeature(routing.RouterType()).(*router.Router),
		startAt:    time.Now(),
	}
	controller.limiter = controller.dispatcher.Limiter
	controller.ruleManager = controller.dispatcher.RuleManager

	return controller
}

// Start implement the Start() function of the service interface
func (c *Controller) Start() error {
	c.clientInfo = c.apiClient.Describe()

	// First fetch Node Info
	newNodeInfo, err := c.apiClient.GetNodeInfo()
	if err != nil {
		return err
	}
	c.nodeInfo = newNodeInfo
	c.Tag = c.buildNodeTag()

	// Update Subscription
	subscriptionInfo, err := c.apiClient.GetSubscriptionList()
	if err != nil {
		return err
	}

	// sync controller subscriptionList
	c.subscriptionList = subscriptionInfo

	c.Relay = false
	// Add new Relay	tag
	if c.nodeInfo.Relay {
		newRelayNodeInfo, err := c.apiClient.GetRelayNodeInfo()
		if err != nil {
			log.Panic(err)
			return nil
		}
		c.relaynodeInfo = newRelayNodeInfo
		c.RelayTag = c.buildRNodeTag()

		err = c.addNewRelayTag(newRelayNodeInfo, subscriptionInfo)
		if err != nil {
			log.Panic(err)
			return err
		}
		c.Relay = true
	}

	// Add new tag
	err = c.addNewTag(newNodeInfo)
	if err != nil {
		log.Panic(err)
		return err
	}

	err = c.addNewSubscription(subscriptionInfo, newNodeInfo)
	if err != nil {
		return err
	}

	// Add Limiter
	if err := c.AddInboundLimiter(c.Tag, newNodeInfo.SpeedLimit, subscriptionInfo, c.config.IPLimit); err != nil {
		return err
	}
	c.applyAuthorizationLease(subscriptionInfo)

	// Add Rule Manager

	if ruleList, err := c.apiClient.GetNodeRule(); err != nil {
		return fmt.Errorf("node enforcement rules unavailable")
	} else if len(*ruleList) > 0 {
		if err := c.UpdateRule(c.Tag, *ruleList); err != nil {
			log.Print(err)
		}
	}

	// Managed authorization polls independently of configuration publication.
	interval := 60 * time.Second
	if _, ok := c.apiClient.(interface{ AuthorizationLease() time.Time }); ok {
		interval = 15 * time.Second
	}
	// Add periodic tasks
	c.tasks = append(c.tasks,
		periodicTask{
			tag: "server",
			Periodic: &task.Periodic{
				Interval: interval,
				Execute:  c.nodeInfoMonitor,
			}},
		periodicTask{
			tag: "subscriptions",
			Periodic: &task.Periodic{
				Interval: time.Duration(60) * time.Second,
				Execute:  c.userInfoMonitor,
			}},
	)

	// Check cert service in need
	if c.nodeInfo.TLSType == "tls" && c.nodeInfo.CertMode != "none" {
		c.tasks = append(c.tasks, periodicTask{
			tag: "cert renew",
			Periodic: &task.Periodic{
				Interval: time.Duration(60) * time.Second * 60,
				Execute:  c.certMonitor,
			}})
	}

	// Start periodic tasks
	for i := range c.tasks {
		log.Printf("%s Task Scheduler for %s started", c.logPrefix(), c.tasks[i].tag)
		go c.tasks[i].Start()
	}

	return nil
}

// Close implement the Close() function of the service interface
func (c *Controller) Close() error {
	if c.closed.Swap(true) {
		return nil
	}
	for i := range c.tasks {
		if c.tasks[i].Periodic != nil {
			if err := c.tasks[i].Periodic.Close(); err != nil {
				log.Panicf("%s Task Scheduler for  %s failed to close: %s", c.logPrefix(), c.tasks[i].tag, err)
			}
		}
	}

	if err := c.snapshotUserInfo(true); err != nil {
		log.Print("final traffic snapshot failed")
	}
	if sender, ok := c.apiClient.(interface{ CloseTraffic() }); ok {
		sender.CloseTraffic()
	}
	return nil
}

func (c *Controller) nodeInfoMonitor() (err error) {
	c.monitorMu.Lock()
	defer c.monitorMu.Unlock()
	if c.closed.Load() {
		return fmt.Errorf("controller stopped")
	}
	// delay to start
	_, managed := c.apiClient.(interface{ AuthorizationLease() time.Time })
	if !managed && time.Since(c.startAt) < time.Duration(60)*time.Second {
		return nil
	}

	// First fetch Node Info
	var nodeInfoChanged = true
	newNodeInfo, err := c.apiClient.GetNodeInfo()
	if err != nil {
		if err.Error() == api.NodeNotModified {
			nodeInfoChanged = false
			newNodeInfo = c.nodeInfo
		} else {
			log.Print(err)
			return nil
		}
	}

	// Update Subscription
	var subscriptionChanged = true
	newSubscriptionInfo, err := c.apiClient.GetSubscriptionList()
	if err != nil {
		if err.Error() == api.SubscriptionNotModified {
			subscriptionChanged = false
			newSubscriptionInfo = c.subscriptionList
		} else {
			log.Print(err)
			return nil
		}
	}

	var updateRelay = false

	if subscriptionChanged || nodeInfoChanged {
		updateRelay = true
	}

	if c.Relay && updateRelay {
		err := c.RemoveRule(c.RelayTag, c.subscriptionList)
		if err != nil {
			log.Print(err)
		}
	}

	// If nodeInfo changed
	if nodeInfoChanged {
		if !reflect.DeepEqual(c.nodeInfo, newNodeInfo) {
			// Remove old tag
			oldTag := c.Tag
			err := c.removeOldTag(oldTag)
			if err != nil {
				log.Print(err)
				return nil
			}
			if c.nodeInfo.NodeType == "Shadowsocks-Plugin" {
				err = c.removeOldTag(fmt.Sprintf("dokodemo-door_%s+1", c.Tag))
			}
			if err != nil {
				log.Print(err)
				return nil
			}

			// Add new tag
			c.nodeInfo = newNodeInfo
			c.Tag = c.buildNodeTag()
			err = c.addNewTag(newNodeInfo)
			if err != nil {
				log.Print(err)
				return nil
			}
			nodeInfoChanged = true
			// Remove Old limiter
			if err = c.DeleteInboundLimiter(oldTag); err != nil {
				log.Print(err)
				return nil
			}
		} else {
			nodeInfoChanged = false
		}
	}

	// Remove relay tag
	if c.Relay && updateRelay {
		err := c.removeRelayTag(c.RelayTag, c.subscriptionList)
		if err != nil {
			return err
		}
		c.Relay = false
	}

	// Update new Relay tag
	if c.nodeInfo.Relay && updateRelay {
		newRelayNodeInfo, err := c.apiClient.GetRelayNodeInfo()
		if err != nil {
			log.Panic(err)
			return nil
		}
		c.relaynodeInfo = newRelayNodeInfo
		c.RelayTag = c.buildRNodeTag()

		err = c.addNewRelayTag(newRelayNodeInfo, newSubscriptionInfo)
		if err != nil {
			log.Panic(err)
			return err
		}
		c.Relay = true
	}

	// Check Rule

	if ruleList, err := c.apiClient.GetNodeRule(); err != nil {
		if err.Error() != api.RuleNotModified {
			log.Printf("Get rule list filed: %s", err)
		}
	} else if len(*ruleList) > 0 {
		if err := c.UpdateRule(c.Tag, *ruleList); err != nil {
			log.Print(err)
		}
	}

	if nodeInfoChanged {
		err = c.addNewSubscription(newSubscriptionInfo, newNodeInfo)
		if err != nil {
			log.Print(err)
			return nil
		}

		// Add Limiter
		if err := c.AddInboundLimiter(c.Tag, newNodeInfo.SpeedLimit, newSubscriptionInfo, c.config.IPLimit); err != nil {
			log.Print(err)
			return nil
		}
	} else {
		var deleted, added []api.SubscriptionInfo
		if subscriptionChanged {
			deleted, added = compareSubscriptionList(c.subscriptionList, newSubscriptionInfo)
			if len(deleted) > 0 {
				c.retiredSubscriptions = append(c.retiredSubscriptions, deleted...)
				deletedEmail := make([]string, len(deleted))
				for i, u := range deleted {
					deletedEmail[i] = fmt.Sprintf("%s|%s|%d", c.Tag, u.Email, u.UID)
				}
				err := c.removeInboundSubscriptions(deletedEmail, c.Tag)
				if err != nil {
					return err
				}
			}
			if len(added) > 0 {
				err = c.addNewSubscription(&added, c.nodeInfo)
				if err != nil {
					return err
				}
				// Update Limiter
				if err := c.UpdateInboundLimiter(c.Tag, &added); err != nil {
					return err
				}
			}
		}
	}
	c.subscriptionList = newSubscriptionInfo
	c.applyAuthorizationLease(newSubscriptionInfo)
	return nil
}

func (c *Controller) applyAuthorizationLease(users *[]api.SubscriptionInfo) {
	if source, ok := c.apiClient.(interface {
		AuthorizationLease() time.Time
		MarkSubscriptionsApplied()
	}); ok {
		deadline := source.AuthorizationLease()
		for _, user := range *users {
			c.dispatcher.LeaseUser(c.buildUserTag(&user), deadline)
		}
		source.MarkSubscriptionsApplied()
		if reporter, ok := c.apiClient.(interface{ ReportHeartbeat() error }); ok {
			if err := reporter.ReportHeartbeat(); err != nil {
				log.Print("authorization acknowledgement failed")
			}
		}
	}
}

func (c *Controller) removeRelayTag(tag string, subscriptionInfo *[]api.SubscriptionInfo) (err error) {
	for _, subscription := range *subscriptionInfo {
		err = c.removeOutbound(fmt.Sprintf("%s_%d", tag, subscription.UID))
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *Controller) RemoveRule(tag string, subscriptionInfo *[]api.SubscriptionInfo) (err error) {
	for _, subscription := range *subscriptionInfo {
		err = c.RemoveRouterRule(fmt.Sprintf("%s_%d", tag, subscription.UID))
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *Controller) addNewRelayTag(newRelayNodeInfo *api.RelayNodeInfo, subscriptionInfo *[]api.SubscriptionInfo) (err error) {
	if newRelayNodeInfo.NodeType != "Shadowsocks-Plugin" {
		for _, subscription := range *subscriptionInfo {
			var Key string
			if C.Contains(shadowaead_2022.List, strings.ToLower(newRelayNodeInfo.CypherMethod)) {
				userKey, err := c.checkShadowsocksPassword(subscription.Passwd, newRelayNodeInfo.CypherMethod)
				if err != nil {
					newError(fmt.Errorf("[UID: %s] %s", subscription.UUID, err))
					continue
				}
				Key = fmt.Sprintf("%s:%s", newRelayNodeInfo.ServerKey, userKey)
			} else {
				Key = subscription.Passwd
			}

			RelayTagConfig, err := OutboundRelayBuilder(newRelayNodeInfo, c.RelayTag, &subscription, Key)
			if err != nil {
				return err
			}

			err = c.addOutbound(RelayTagConfig)
			if err != nil {
				return err
			}

			RouterConfig, err := RouterBuilder(c.Tag, c.RelayTag, &subscription)
			if err != nil {
				return err
			}

			err = c.AddRouterRule(RouterConfig, true)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *Controller) removeOldTag(oldTag string) (err error) {
	err = c.removeInbound(oldTag)
	if err != nil {
		return err
	}
	err = c.removeOutbound(oldTag)
	if err != nil {
		return err
	}
	return nil
}

func (c *Controller) addNewTag(newNodeInfo *api.NodeInfo) (err error) {
	if newNodeInfo.NodeType != "Shadowsocks-Plugin" {
		inboundConfig, err := InboundBuilder(c.config, newNodeInfo, c.Tag)
		if err != nil {
			return err
		}
		dispatcher := c.server.GetFeature(routing.DispatcherType()).(*xdispatcher.DefaultDispatcher)
		if dispatcher.TransitRequired(c.Tag) && !newNodeInfo.Transit {
			return fmt.Errorf("transit input role cannot be downgraded in place")
		}
		if newNodeInfo.Transit {
			if err = dispatcher.RequireTransit(c.Tag); err != nil {
				return err
			}
		}
		err = c.addInbound(inboundConfig)
		if err != nil {
			return err
		}
		outBoundConfig, err := OutboundBuilder(c.config, newNodeInfo, c.Tag)
		if err != nil {
			return err
		}
		err = c.addOutbound(outBoundConfig)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *Controller) addNewSubscription(subscriptionInfo *[]api.SubscriptionInfo, nodeInfo *api.NodeInfo) (err error) {
	// Infrastructure SS entries authenticate with their core-local shared secret,
	// not customer credentials; the panel forbids service assignments to them.
	if nodeInfo.NodeType == "Shadowsocks" && len(nodeInfo.InboundProfile) > 0 {
		if len(*subscriptionInfo) != 0 {
			return fmt.Errorf("infrastructure entry cannot accept customer subscriptions")
		}
		return nil
	}
	subscriptions := make([]*protocol.User, 0)
	switch nodeInfo.NodeType {
	case "Vless":
		subscriptions = c.buildVlessUser(subscriptionInfo, nodeInfo.Flow)
	case "Vmess":
		subscriptions = c.buildVmessUser(subscriptionInfo)
	case "Trojan":
		subscriptions = c.buildTrojanUser(subscriptionInfo)
	case "Shadowsocks":
		subscriptions = c.buildSSUser(subscriptionInfo, nodeInfo.CypherMethod)
	default:
		return fmt.Errorf("unsupported node type: %s", nodeInfo.NodeType)
	}

	err = c.addInboundSubscriptions(subscriptions, c.Tag)
	if err != nil {
		return err
	}

	return nil
}

func compareSubscriptionList(old, new *[]api.SubscriptionInfo) (deleted, added []api.SubscriptionInfo) {
	mSrc := make(map[api.SubscriptionInfo]byte)
	mAll := make(map[api.SubscriptionInfo]byte)

	var set []api.SubscriptionInfo

	for _, v := range *old {
		mSrc[v] = 0
		mAll[v] = 0
	}

	for _, v := range *new {
		l := len(mAll)
		mAll[v] = 1
		if l != len(mAll) {
			l = len(mAll)
		} else {
			set = append(set, v)
		}
	}

	for _, v := range set {
		delete(mAll, v)
	}

	for v := range mAll {
		_, exist := mSrc[v]
		if exist {
			deleted = append(deleted, v)
		} else {
			added = append(added, v)
		}
	}

	return deleted, added
}

func (c *Controller) userInfoMonitor() (err error) {
	return c.snapshotUserInfo(false)
}
func (c *Controller) snapshotUserInfo(final bool) (err error) {
	c.monitorMu.Lock()
	defer c.monitorMu.Unlock()
	if c.subscriptionList == nil {
		return nil
	}
	if c.closed.Load() && !final {
		return fmt.Errorf("controller stopped")
	}
	if source, ok := c.apiClient.(interface{ DeviceGate() api.DeviceGate }); ok && !final {
		if gate := source.DeviceGate(); gate != nil {
			if err := gate.RenewDevices(); err != nil {
				log.Print("device lease renewal failed")
			}
		}
	}
	if gate,ok:=c.apiClient.(api.IPGate);ok && !final {
		if err:=gate.RenewIPs();err!=nil {log.Print("IP lease renewal failed")}
	}
	// Get Subscription traffic
	var subscriptionTraffic []api.SubscriptionTraffic
	var snapshots []trafficSnapshot
	seen := make(map[string]bool)

	allSubscriptions := append(append([]api.SubscriptionInfo{}, (*c.subscriptionList)...), c.retiredSubscriptions...)
	for _, subscription := range allSubscriptions {
		tag := c.buildUserTag(&subscription)
		if seen[tag] {
			continue
		}
		seen[tag] = true
		up, down, upCounter, downCounter := c.getTraffic(tag)
		if up > 0 || down > 0 {
			subscriptionTraffic = append(subscriptionTraffic, api.SubscriptionTraffic{
				UID:      subscription.UID,
				Email:    subscription.Email,
				Upload:   up,
				Download: down})

			if upCounter != nil {
				snapshots = append(snapshots, trafficSnapshot{upCounter, up})
			}
			if downCounter != nil {
				snapshots = append(snapshots, trafficSnapshot{downCounter, down})
			}
		}
	}

	durable, supportsDurable := c.apiClient.(interface {
		DurableTrafficEnabled() bool
		QueueTraffic(*[]api.SubscriptionTraffic) error
		FlushTraffic() error
	})
	if supportsDurable && durable.DurableTrafficEnabled() {
		if len(subscriptionTraffic) > 0 {
			if err := durable.QueueTraffic(&subscriptionTraffic); err != nil {
				log.Print(err)
			} else {
				consumeTraffic(snapshots)
				c.retiredSubscriptions = nil
			}
		}
		if !final {
			flush := durable.FlushTraffic
			if sender, ok := c.apiClient.(interface{ ScheduleTraffic() error }); ok {
				flush = sender.ScheduleTraffic
			}
			if err := flush(); err != nil {
				log.Print(err)
			}
		}
	} else if len(subscriptionTraffic) > 0 {
		var err error // Define an empty error

		err = c.apiClient.ReportSubscriptionTraffic(&subscriptionTraffic)
		// If report traffic error, not clear the traffic
		if err != nil {
			log.Print(err)
		} else {
			consumeTraffic(snapshots)
			c.retiredSubscriptions = nil
		}
	}

	if final {
		return nil
	}
	// Report Online info
	if onlineDevice, err := c.GetOnlineDevice(c.Tag); err != nil {
		log.Print(err)
	} else {
		if err = c.apiClient.ReportNodeOnlineIPs(onlineDevice); err != nil {
			log.Print(err)
		} else {
			log.Printf("%s Report %d online IPs", c.logPrefix(), len(*onlineDevice))
		}
	}
	if reporter, ok := c.apiClient.(interface{ ReportHeartbeat() error }); ok {
		if heartbeatErr := reporter.ReportHeartbeat(); heartbeatErr != nil {
			log.Print(heartbeatErr)
		}
	}

	// Report Illegal user
	if detectResult, err := c.GetDetectResult(c.Tag); err != nil {
		log.Print(err)
	} else if len(*detectResult) > 0 {
		log.Printf("%s blocked %d access by detection rules", c.logPrefix(), len(*detectResult))
	}

	return nil
}

func (c *Controller) buildNodeTag() string {
	return fmt.Sprintf("%s_%s_%d", c.nodeInfo.NodeType, c.nodeInfo.Port, c.nodeInfo.NodeID)
}

func (c *Controller) buildRNodeTag() string {
	return fmt.Sprintf("Relay_%d_%s_%d_%d", c.nodeInfo.NodeID, c.relaynodeInfo.NodeType, c.relaynodeInfo.Port, c.relaynodeInfo.NodeID)
}

func (c *Controller) logPrefix() string {
	transportProtocol := conf.TransportProtocol(c.nodeInfo.Transport)
	networkType, err := transportProtocol.Build()
	if err != nil {
		return fmt.Sprintf("[%s] %s(NodeID=%d)", c.clientInfo.APIHost, c.nodeInfo.NodeType, c.nodeInfo.NodeID)
	}

	return fmt.Sprintf("[%s] %s(NodeID=%d) [Transport=%s]", c.clientInfo.APIHost, c.nodeInfo.NodeType, c.nodeInfo.NodeID, networkType)
}

// Check Cert
func (c *Controller) certMonitor() error {
	switch c.nodeInfo.CertMode {
	case "dns", "http":
		lego, err := mylego.New(c.config.CertConfig)
		if err != nil {
			log.Print(err)
		}
		_, _, _, err = lego.RenewCert(c.nodeInfo.CertMode, c.nodeInfo.CertDomain)
		if err != nil {
			log.Print(err)
		}
	}

	return nil
}
