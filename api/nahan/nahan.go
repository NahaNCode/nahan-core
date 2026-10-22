package nahan

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	"github.com/NahaNCode/nahan-core/api"
	"github.com/NahaNCode/nahan-core/utility/outbox"
	"github.com/NahaNCode/nahan-core/utility/paneltls"
	"github.com/bitly/go-simplejson"
	"github.com/go-resty/resty/v2"
	"github.com/google/uuid"
)

type APIClient struct {
	devices               deviceLeases
	deviceCredentials     map[int]deviceCredential
	deviceEmailSequence   uint64
	coreID                string
	secretsDir            string
	protocol              string
	configFetched         atomic.Bool
	subscriptionsFetched  atomic.Bool
	fetchedAuthorization  atomic.Int64
	appliedAuthorization  atomic.Int64
	authorizationDeadline atomic.Int64
	reportFailed          atomic.Bool
	queueFailed           atomic.Bool
	outbox                *outbox.Queue
	outboxErr             error
	traffic               trafficWorker
	client                *resty.Client
	APIHost               string
	NodeID                int
	Key                   string
	resp                  atomic.Value
	eTags                 map[string]string
	LastReportOnline      map[int]int
	access                sync.Mutex
	LocalRuleList         []api.DetectRule
}

func New(apiConfig *api.Config) *APIClient {
	client := resty.New()
	client.SetRetryCount(3)
	if apiConfig.Timeout > 0 {
		client.SetTimeout(time.Duration(apiConfig.Timeout) * time.Second)
	} else {
		client.SetTimeout(5 * time.Second)
	}
	client.OnError(func(req *resty.Request, err error) {
		if apiConfig.Protocol == "nahan-v1" {
			return
		}
		if v, ok := err.(*resty.ResponseError); ok {
			// v.Response contains the last response from the server
			// v.Err contains the original error
			log.Print(v.Err)
		}
	})
	client.SetBaseURL(apiConfig.APIHost)
	if apiConfig.Protocol == "nahan-v1" {
		// The verified transport owns retries; Resty must not replay ambiguous writes.
		client.SetRetryCount(0)
		transport, err := paneltls.Transport(apiConfig.APIHost, apiConfig.CAFile, apiConfig.ServerName)
		if err != nil {
			panic(err)
		}
		routes, err := paneltls.WithFailover(apiConfig.APIHost, transport)
		if err != nil {
			panic(err)
		}
		client.SetTransport(routes)
		client.SetTimeout(paneltls.RequestTimeout)
		if apiConfig.ServerName != "" {
			client.SetHeader("Host", apiConfig.ServerName)
		}
		client.SetRedirectPolicy(resty.NoRedirectPolicy())
	}

	if apiConfig.Protocol == "nahan-v1" {
		client.SetHeader("Authorization", "Bearer "+apiConfig.Key)
	} else {
		client.SetQueryParam("key", apiConfig.Key)
	}

	localRuleList := readLocalRuleList(apiConfig.RuleListPath)

	apiClient := &APIClient{
		protocol:         apiConfig.Protocol,
		client:           client,
		NodeID:           apiConfig.NodeID,
		Key:              apiConfig.Key,
		APIHost:          apiConfig.APIHost,
		LastReportOnline: make(map[int]int),
		eTags:            make(map[string]string),
		LocalRuleList:    localRuleList,
	}

	if apiConfig.TrafficOutboxDir != "" {
		scope := fmt.Sprintf("%x-%d", sha256.Sum256([]byte(apiConfig.APIHost)), apiConfig.NodeID)
		apiClient.outbox, apiClient.outboxErr = outbox.Open(filepath.Join(apiConfig.TrafficOutboxDir, scope))
	}
	apiClient.coreID = apiConfig.CoreID
	apiClient.secretsDir = apiConfig.SecretsDir
	return apiClient
}

func (c *APIClient) path(resource string) string {
	if c.protocol == "nahan-v1" {
		return fmt.Sprintf("/api/core/v1/nodes/%d/%s", c.NodeID, resource)
	}
	return fmt.Sprintf("/api/%s/%d", resource, c.NodeID)
}

func (c *APIClient) ReportHeartbeat() error {
	if c.protocol != "nahan-v1" {
		return nil
	}
	pending := 0
	if c.outbox != nil {
		var err error
		pending, err = c.outbox.Pending()
		if err != nil {
			return err
		}
	}
	lastError := ""
	if c.queueFailed.Load() {
		lastError = "traffic persistence failed"
	} else if c.reportFailed.Load() {
		lastError = "report delivery failed"
	}
	res, err := c.client.R().SetBody(map[string]interface{}{
		"version": "NahaN Core v1.5.0", "pendingReports": pending, "lastError": lastError,
		"configSynced": c.configFetched.Load(), "servicesSynced": c.subscriptionsFetched.Load(),
		"authorizationRevision": c.appliedAuthorization.Load(), "authorizationRuntimeVersion": 1,
		"deviceRuntimeVersion": 1,
	}).Post(c.path("heartbeat"))
	_, err = c.parseResponse(res, c.path("heartbeat"), err)
	return err
}

// readLocalRuleList reads the local rule list file
func readLocalRuleList(path string) (LocalRuleList []api.DetectRule) {

	LocalRuleList = make([]api.DetectRule, 0)
	if path != "" {
		// open the file
		file, err := os.Open(path)

		// handle errors while opening
		if err != nil {
			log.Printf("Error when opening file: %s", err)
			return LocalRuleList
		}

		fileScanner := bufio.NewScanner(file)

		// read line by line
		for fileScanner.Scan() {
			LocalRuleList = append(LocalRuleList, api.DetectRule{
				ID:      -1,
				Pattern: regexp.MustCompile(fileScanner.Text()),
			})
		}
		// handle first encountered error while reading
		if err := fileScanner.Err(); err != nil {
			log.Fatalf("Error while reading file: %s", err)
			return
		}

		file.Close()
	}

	return LocalRuleList
}

func (c *APIClient) Describe() api.ClientInfo {
	return api.ClientInfo{APIHost: c.APIHost, NodeID: c.NodeID, Key: c.Key}
}

func (c *APIClient) Debug() {
	c.client.SetDebug(true)
}

func (c *APIClient) assembleURL(path string) string {
	return c.APIHost + path
}

func (c *APIClient) parseResponse(res *resty.Response, path string, err error) (*simplejson.Json, error) {
	if err != nil {
		if c.protocol == "nahan-v1" {
			return nil, fmt.Errorf("native API unavailable: %w", err)
		}
		return nil, fmt.Errorf("request %s failed: %s", c.assembleURL(path), err)
	}

	if res.StatusCode() >= 400 {
		if c.protocol == "nahan-v1" {
			return nil, fmt.Errorf("native API status %d", res.StatusCode())
		}
		body := res.Body()
		return nil, fmt.Errorf("request %s failed: %s, %v", c.assembleURL(path), string(body), err)
	}

	rtn, err := simplejson.NewJson(res.Body())

	if err != nil {
		if c.protocol == "nahan-v1" {
			return nil, errors.New("invalid native API response")
		}
		return nil, fmt.Errorf("%s", res.String())
	}
	return rtn, nil
}

func (c *APIClient) parseSubscriptionResponse(res *resty.Response, path string, err error) (*SubscriptionResponse, error) {
	if err != nil {
		if c.protocol == "nahan-v1" {
			return nil, fmt.Errorf("native API unavailable: %w", err)
		}
		return nil, fmt.Errorf("request %s failed: %s", c.assembleURL(path), err)
	}

	if res.StatusCode() >= 400 {
		if c.protocol == "nahan-v1" {
			return nil, fmt.Errorf("native API status %d", res.StatusCode())
		}
		body := res.Body()
		return nil, fmt.Errorf("request %s failed: %s, %v", c.assembleURL(path), string(body), err)
	}

	response, ok := res.Result().(*SubscriptionResponse)
	if !ok || response == nil {
		return nil, errors.New("invalid subscription response")
	}

	return response, nil
}

func (c *APIClient) GetNodeInfo() (nodeInfo *api.NodeInfo, err error) {
	return c.GetNodeInfoContext(context.Background())
}
func (c *APIClient) GetNodeInfoContext(ctx context.Context) (nodeInfo *api.NodeInfo, err error) {
	c.configFetched.Store(false)
	server := new(serverConfig)
	path := c.path("server")
	res, err := c.client.R().
		SetContext(ctx).
		ForceContentType("application/json").
		SetHeader("If-None-Match", c.eTags["server"]).
		Get(path)

	if res != nil && res.StatusCode() == 304 {
		c.configFetched.Store(true)
		return nil, errors.New(api.NodeNotModified)
	}
	// update etag
	if res != nil && res.Header().Get("Etag") != "" && res.Header().Get("Etag") != c.eTags["server"] {
		c.eTags["server"] = res.Header().Get("Etag")
	}

	response, err := c.parseResponse(res, path, err)
	if err != nil {
		return nil, err
	}

	b, _ := response.Encode()
	json.Unmarshal(b, server)

	if server.Port == "" {
		return nil, fmt.Errorf("invalid server port range:  %s.  eg 8000-8999", server.Port)
	}

	if server.Type == "" {
		return nil, fmt.Errorf("server Type cannot be %s", server.Type)
	}

	c.resp.Store(server)

	nodeInfo, err = c.parseNodeResponse(server)
	if err != nil {
		return nil, fmt.Errorf("parse node info failed: %w", err)
	}
	c.configFetched.Store(true)
	return nodeInfo, nil
}

func (c *APIClient) GetSubscriptionList() (SubscriptionList *[]api.SubscriptionInfo, err error) {
	return c.GetSubscriptionListContext(context.Background())
}
func (c *APIClient) GetSubscriptionListContext(ctx context.Context) (SubscriptionList *[]api.SubscriptionInfo, err error) {
	c.subscriptionsFetched.Store(false)
	path := c.path("subscriptions")
	res, err := c.client.R().
		SetContext(ctx).
		SetHeader("If-None-Match", c.eTags["subscriptions"]).
		SetResult(&SubscriptionResponse{}).
		ForceContentType("application/json").
		Get(path)

	if res != nil && res.StatusCode() == 304 {
		if c.protocol == "nahan-v1" {
			return nil, errors.New("authorization snapshot must include a fresh lease")
		}
		c.subscriptionsFetched.Store(true)
		return nil, errors.New(api.SubscriptionNotModified)
	}
	// update etag
	if res != nil && res.Header().Get("Etag") != "" && res.Header().Get("Etag") != c.eTags["subscriptions"] {
		c.eTags["subscriptions"] = res.Header().Get("Etag")
	}

	response, err := c.parseSubscriptionResponse(res, path, err)
	if err != nil {
		return nil, err
	}

	subscriptionsListResponse := new([]Subscription)

	if err := json.Unmarshal(response.Data, subscriptionsListResponse); err != nil {
		return nil, fmt.Errorf("unmarshal %s failed: %s", reflect.TypeOf(subscriptionsListResponse), err)
	}

	subscriptionList, err := c.ParseSubscriptionList(subscriptionsListResponse)
	if err != nil {
		res, _ := json.Marshal(subscriptionsListResponse)
		return nil, fmt.Errorf("parse subscription list failed: %s", string(res))
	}

	if c.protocol == "nahan-v1" {
		seconds := response.LeaseSeconds
		if seconds == 0 {
			seconds = 120
		} // Compatible rolling upgrade; still bound offline access.
		if seconds < 1 || seconds > 120 || response.AuthorizationRevision < c.appliedAuthorization.Load() {
			return nil, errors.New("invalid authorization lease or stale revision")
		}
		c.fetchedAuthorization.Store(response.AuthorizationRevision)
		c.authorizationDeadline.Store(time.Now().Add(time.Duration(seconds) * time.Second).UnixNano())
	}
	return subscriptionList, nil
}

func (c *APIClient) AuthorizationLease() time.Time {
	if c.protocol != "nahan-v1" {
		return time.Time{}
	}
	return time.Unix(0, c.authorizationDeadline.Load())
}

// Only the controller may acknowledge a snapshot after users and limiters were applied.
func (c *APIClient) MarkSubscriptionsApplied() {
	c.appliedAuthorization.Store(c.fetchedAuthorization.Load())
	c.subscriptionsFetched.Store(true)
}

func (c *APIClient) ParseSubscriptionList(subscriptionResponse *[]Subscription) (*[]api.SubscriptionInfo, error) {
	c.access.Lock()
	defer func() {
		c.LastReportOnline = make(map[int]int)
		c.access.Unlock()
	}()

	var deviceLimit, onlineipcount, ipcount int = 0, 0, 0
	var speedLimit uint64 = 0

	subscriptionList := []api.SubscriptionInfo{}
	nextCredentials := make(map[int]deviceCredential)

	for _, subscription := range *subscriptionResponse {
		deviceMode := c.protocol == "nahan-v1" && subscription.DeviceID > 0
		if deviceMode && (subscription.Id != subscription.DeviceID || subscription.ServiceID <= 0 || subscription.DeviceLimit < 1 || subscription.DeviceLimit > 100) {
			return nil, errors.New("invalid registered device identity")
		}
		deviceLimit = subscription.Iplimit
		ipcount = subscription.Ipcount

		if !deviceMode && deviceLimit > 0 && ipcount > 0 {
			lastOnline := 0
			if v, ok := c.LastReportOnline[subscription.Id]; ok {
				lastOnline = v
			}
			if onlineipcount = deviceLimit - ipcount + lastOnline; onlineipcount > 0 {
				deviceLimit = onlineipcount
			} else if lastOnline > 0 {
				deviceLimit = lastOnline
			} else {
				continue
			}
		}

		speedLimit = uint64((subscription.Speedlimit * 1000000) / 8)
		serviceID, deviceID, email := 0, 0, subscription.Email
		if deviceMode {
			deviceLimit = subscription.DeviceLimit
			serviceID, deviceID = subscription.ServiceID, subscription.DeviceID
			if _, duplicate := nextCredentials[deviceID]; duplicate {
				return nil, errors.New("duplicate registered device identity")
			}
			// Auth email is a local credential generation, not just a device ID.
			// Old MemoryUsers retain their old email after same-ID rotation.
			encoded, _ := json.Marshal(struct {
				UUID, Password string
				ServiceID      int
			}{subscription.Uuid, subscription.Passwd, serviceID})
			fingerprint := sha256.Sum256(encoded)
			credential, exists := c.deviceCredentials[deviceID]
			if !exists || credential.fingerprint != fingerprint {
				c.deviceEmailSequence++
				credential = deviceCredential{fingerprint: fingerprint, email: fmt.Sprintf("device-%d-%d", deviceID, c.deviceEmailSequence)}
			}
			nextCredentials[deviceID] = credential
			email = credential.email
		}

		subscriptionList = append(subscriptionList, api.SubscriptionInfo{
			UID:         subscription.Id,
			ServiceID:   serviceID,
			DeviceID:    deviceID,
			UUID:        subscription.Uuid,
			Email:       email,
			Passwd:      subscription.Passwd,
			DeviceLimit: deviceLimit,
			SpeedLimit:  speedLimit,
		})
	}
	c.deviceCredentials = nextCredentials

	return &subscriptionList, nil
}

func (c *APIClient) GetNodeRule() (*[]api.DetectRule, error) {
	ruleList := c.LocalRuleList

	config, ok := c.resp.Load().(*serverConfig)
	if !ok || config == nil {
		return nil, fmt.Errorf("node rules unavailable")
	}
	routes := config.Routes

	for i := range routes {
		pattern, err := regexp.Compile(routes[i].Regex)
		if err != nil {
			return nil, fmt.Errorf("invalid node rule")
		}
		ruleListItem := api.DetectRule{
			ID:      routes[i].Id,
			Pattern: pattern,
		}
		ruleList = append(ruleList, ruleListItem)
	}

	return &ruleList, nil
}

func (c *APIClient) ReportSubscriptionTraffic(subscriptionTraffic *[]api.SubscriptionTraffic) error {
	return c.sendTraffic(subscriptionTraffic, uuid.NewString())
}

func (c *APIClient) DurableTrafficEnabled() bool { return c.outbox != nil || c.outboxErr != nil }

func (c *APIClient) QueueTraffic(traffic *[]api.SubscriptionTraffic) (err error) {
	defer func() { c.queueFailed.Store(err != nil) }()
	if c.outboxErr != nil {
		return c.outboxErr
	}
	if c.outbox == nil {
		return errors.New("traffic outbox unavailable")
	}
	return c.outbox.Enqueue(*traffic)
}

func (c *APIClient) FlushTraffic() error {
	if c.outboxErr != nil {
		return c.outboxErr
	}
	err := c.outbox.Flush(func(r outbox.Report) error { return c.sendTraffic(&r.Traffic, r.ID) })
	c.reportFailed.Store(err != nil)
	return err
}

func (c *APIClient) sendTraffic(subscriptionTraffic *[]api.SubscriptionTraffic, reportID string) error {
	return c.sendTrafficContext(context.Background(), subscriptionTraffic, reportID)
}
func (c *APIClient) sendTrafficContext(ctx context.Context, subscriptionTraffic *[]api.SubscriptionTraffic, reportID string) error {
	path := c.path("traffic")

	data := make([]SubscriptionTraffic, len(*subscriptionTraffic))
	for i, traffic := range *subscriptionTraffic {
		data[i] = SubscriptionTraffic{
			UID:      traffic.UID,
			Upload:   traffic.Upload,
			Download: traffic.Download,
		}
	}
	postData := &PostData{Data: data}
	res, err := c.client.R().SetContext(ctx).
		SetHeader("Idempotency-Key", reportID).
		SetBody(postData).
		ForceContentType("application/json").
		Post(path)
	_, err = c.parseResponse(res, path, err)
	if err != nil {
		return err
	}

	return nil
}

func (c *APIClient) ReportNodeOnlineIPs(onlineSubscriptionList *[]api.OnlineIP) error {
	c.access.Lock()
	defer c.access.Unlock()

	reportOnline := make(map[int]int)
	data := make([]OnlineIP, len(*onlineSubscriptionList))
	for i, subscription := range *onlineSubscriptionList {
		data[i] = OnlineIP{UID: subscription.UID, IP: subscription.IP, FirstSeen: subscription.FirstSeen, LastSeen: subscription.LastSeen, RouteTag: subscription.RouteTag, RouteRevision: subscription.RouteRevision}
		if _, ok := reportOnline[subscription.UID]; ok {
			reportOnline[subscription.UID]++
		} else {
			reportOnline[subscription.UID] = 1
		}
	}
	c.LastReportOnline = reportOnline

	postData := &PostData{Data: data}
	path := c.path("onlineip")
	res, err := c.client.R().
		SetBody(postData).
		SetResult(&Response{}).
		ForceContentType("application/json").
		Post(path)

	_, err = c.parseResponse(res, path, err)
	if err != nil {
		return err
	}

	return nil
}

func (c *APIClient) parseNodeResponse(s *serverConfig) (*api.NodeInfo, error) {
	if len(s.InboundProfile) > 0 {
		return c.parseEntryProfile(s)
	}
	if s.EntryRole != "" {
		return nil, fmt.Errorf("explicit managed entry roles require an inbound profile")
	}
	var (
		path, host, serviceName, seed, Dest, PrivateKey, MinClientVer, MaxClientVer, Flow, Authority, CurvePreferences, mode, DomainStrategy, ServerNameToVerify string
		header                                                                                                                                                   json.RawMessage
		congestion, RejectUnknownSni, Show, noSSEHeader, noGRPCHeader, TcpMptcp, SocketStatus, Insecure                                                          bool
		MaxTimeDiff, ProxyProtocol                                                                                                                               uint64 = 0, 0
		HeartbeatPeriod                                                                                                                                          uint32 = 10
		ServerNames, ShortIds                                                                                                                                    []string
		TCPWindowClamp, TCPMaxSeg, TCPUserTimeout, TCPKeepAliveIdle, TCPKeepAliveInterval                                                                        int32 = 0, 0, 0, 0, 0
	)

	if s.NetworkSettings.Flow == "xtls-rprx-vision" || s.NetworkSettings.Flow == "xtls-rprx-vision-udp443" {
		Flow = s.NetworkSettings.Flow
	}

	if s.NetworkSettings.Authority != "" {
		Authority = s.NetworkSettings.Authority
	}

	if s.Security == "tls" {
		RejectUnknownSni = s.SecuritySettings.RejectUnknownSni
		if s.SecuritySettings.ServerName == "" {
			return nil, fmt.Errorf("TLS certificate domain (ServerName) is empty: %s", s.SecuritySettings.ServerName)
		}

		CurvePreferences = "X25519"
		if s.SecuritySettings.CurvePreferences != "" {
			CurvePreferences = s.SecuritySettings.CurvePreferences
		}

		ServerNameToVerify = ""
		if s.SecuritySettings.ServerNameToVerify != "" {
			ServerNameToVerify = s.SecuritySettings.ServerNameToVerify
		}

		Insecure = s.SecuritySettings.Insecure
	}

	if s.Security == "reality" {
		Dest = s.SecuritySettings.Dest
		Show = s.SecuritySettings.Show
		PrivateKey = s.SecuritySettings.PrivateKey
		MinClientVer = s.SecuritySettings.MinClientVer
		MaxClientVer = s.SecuritySettings.MaxClientVer
		MaxTimeDiff = uint64(s.SecuritySettings.MaxTimeDiff)
		ShortIds = s.SecuritySettings.ShortIds
		ServerNames = s.SecuritySettings.ServerNames
		ProxyProtocol = uint64(s.SecuritySettings.ProxyProtocol)
	}

	transportProtocol := s.NetworkSettings.Transport

	switch transportProtocol {
	case "ws", "websocket":
		path = s.NetworkSettings.Path
		host = s.NetworkSettings.Host
		HeartbeatPeriod = uint32(s.NetworkSettings.Heartbeat)
	case "h2", "h3", "http":
		return nil, errors.New("H2/HTTP is deprecated in this version of xray-core")
	case "httpupgrade":
		path = s.NetworkSettings.Path
		host = s.NetworkSettings.Host
	case "xhttp", "splithttp":
		path = s.NetworkSettings.Path
		host = s.NetworkSettings.Host
		noSSEHeader = s.NetworkSettings.noSSEHeader
		noGRPCHeader = s.NetworkSettings.noGRPCHeader
		mode = ""
		if s.NetworkSettings.mode != "" {
			mode = s.NetworkSettings.mode
		}
	case "grpc":
		serviceName = s.NetworkSettings.ServiceName
	case "raw", "tcp":
		if s.NetworkSettings.Header == nil {
			header = json.RawMessage(`{"type":"none"}`)
			break
		}
		if httpHeader, err := s.NetworkSettings.Header.MarshalJSON(); err != nil {
			return nil, err
		} else {
			t, _ := simplejson.NewJson(httpHeader)
			htype := t.Get("type").MustString()
			if htype == "http" {
				path = t.Get("request").Get("path").MustString()
				header, _ = json.Marshal(map[string]any{
					"type": "http",
					"request": map[string]any{
						"path": path,
					}})
			} else {
				header, _ = json.Marshal(map[string]any{
					"type": "none",
				})
			}
		}
	case "quic":
		return nil, errors.New("Quic is deprecated in this version of xray-core")
	case "kcp", "mkcp":
		seed = s.NetworkSettings.Seed
		congestion = s.NetworkSettings.Congestion
		if httpHeader, err := s.NetworkSettings.Header.MarshalJSON(); err != nil {
			return nil, err
		} else {
			h, _ := simplejson.NewJson(httpHeader)
			htype := h.Get("type").MustString()
			if htype != "none" {
				header, _ = json.Marshal(map[string]any{
					"type": htype,
				})
			} else {
				header, _ = json.Marshal(map[string]any{
					"type": "none",
				})
			}
		}
	}

	NodeType := s.Type
	if NodeType == "Shadowsocks" && transportProtocol != "tcp" {
		//NodeType = "Shadowsocks-Plugin"
		return nil, errors.New("Shadowsocks-Plugin is deprecated in this version of NahaN backend")
	}

	//SocketSettings
	DomainStrategy = ""
	if s.SocketSettings.DomainStrategy != "" {
		DomainStrategy = s.SocketSettings.DomainStrategy
	}
	if s.SocketSettings.TCPKeepAliveInterval > 0 {
		TCPKeepAliveInterval = int32(s.SocketSettings.TCPKeepAliveInterval)
	}
	if s.SocketSettings.TCPKeepAliveIdle > 0 {
		TCPKeepAliveIdle = int32(s.SocketSettings.TCPKeepAliveIdle)
	}
	if s.SocketSettings.TCPUserTimeout > 0 {
		TCPUserTimeout = int32(s.SocketSettings.TCPUserTimeout)
	}
	if s.SocketSettings.TCPMaxSeg > 0 {
		TCPMaxSeg = int32(s.SocketSettings.TCPMaxSeg)
	}
	if s.SocketSettings.TCPWindowClamp > 0 {
		TCPWindowClamp = int32(s.SocketSettings.TCPWindowClamp)
	}
	if s.SocketSettings.TcpMptcp {
		TcpMptcp = s.SocketSettings.TcpMptcp
	}
	if s.SocketSettings.SocketStatus {
		SocketStatus = s.SocketSettings.SocketStatus
	}

	nodeInfo := &api.NodeInfo{
		NodeType:             NodeType,
		NodeID:               c.NodeID,
		Port:                 s.Port,
		Transport:            transportProtocol,
		TLSType:              s.Security,
		Path:                 path,
		Host:                 host,
		HeartbeatPeriod:      HeartbeatPeriod,
		ServiceName:          serviceName,
		Flow:                 Flow,
		Authority:            Authority,
		Header:               header,
		Seed:                 seed,
		Congestion:           congestion,
		Sniffing:             s.Sniffing,
		RejectUnknownSNI:     RejectUnknownSni,
		Fingerprint:          s.SecuritySettings.Fingerprint,
		CurvePreferences:     CurvePreferences,
		CypherMethod:         s.Cipher,
		Address:              s.Address,
		ListenIP:             s.Listenip,
		ProxyProtocol:        s.NetworkSettings.ProxyProtocol,
		CertMode:             s.Certmode,
		CertDomain:           s.SecuritySettings.ServerName,
		ServerKey:            s.ServerKey,
		SpeedLimit:           uint64(s.Speedlimit * 1000000 / 8),
		SendIP:               s.SendThrough,
		Dest:                 Dest,
		Show:                 Show,
		ServerNames:          ServerNames,
		PrivateKey:           PrivateKey,
		ShortIds:             ShortIds,
		MinClientVer:         MinClientVer,
		MaxClientVer:         MaxClientVer,
		MaxTimeDiff:          MaxTimeDiff,
		Xver:                 ProxyProtocol,
		Relay:                s.Relay,
		RelayNodeID:          s.Relayid,
		NoSSEHeader:          noSSEHeader,
		NoGRPCHeader:         noGRPCHeader,
		Mode:                 mode,
		TcpMptcp:             TcpMptcp,
		TCPWindowClamp:       TCPWindowClamp,
		TCPMaxSeg:            TCPMaxSeg,
		TCPUserTimeout:       TCPUserTimeout,
		TCPKeepAliveIdle:     TCPKeepAliveIdle,
		TCPKeepAliveInterval: TCPKeepAliveInterval,
		DomainStrategy:       DomainStrategy,
		SocketStatus:         SocketStatus,
		ServerNameToVerify:   ServerNameToVerify,
		Insecure:             Insecure,
	}
	return nodeInfo, nil
}

func (c *APIClient) GetRelayNodeInfo() (*api.RelayNodeInfo, error) {
	s := c.resp.Load().(*serverConfig)
	var (
		path, host, serviceName, seed, PublicKey, ShortId, SpiderX, ServerName, Flow, Authority, mode string
		header                                                                                        json.RawMessage
		congestion, Show, noSSEHeader, noGRPCHeader                                                   bool
		HeartbeatPeriod                                                                               uint32 = 10
	)

	if s.RNetworkSettings.Flow == "xtls-rprx-vision" ||
		s.RNetworkSettings.Flow == "xtls-rprx-vision-udp443" &&
			s.RNetworkSettings.Transport == "tcp" {
		Flow = "xtls-rprx-vision-udp443"
	}

	if s.RNetworkSettings.Authority != "" {
		Authority = s.RNetworkSettings.Authority
	}

	if s.RSecurity == "reality" {
		PublicKey = s.RSecuritySettings.PublicKey
		Show = s.RSecuritySettings.Show
		ShortId = s.RSecuritySettings.ShortId
		SpiderX = s.RSecuritySettings.SpiderX
		ServerName = s.RSecuritySettings.ServerName
	}

	transportProtocol := s.RNetworkSettings.Transport

	switch transportProtocol {
	case "ws", "websocket":
		path = s.RNetworkSettings.Path
		host = s.RNetworkSettings.Host
		HeartbeatPeriod = uint32(s.RNetworkSettings.Heartbeat)
	case "h2", "h3", "http":
		return nil, errors.New("H2/HTTP is deprecated in this version of xray-core")
	case "httpupgrade":
		path = s.RNetworkSettings.Path
		host = s.RNetworkSettings.Host
	case "xhttp", "splithttp":
		path = s.RNetworkSettings.Path
		host = s.RNetworkSettings.Host
		noSSEHeader = s.RNetworkSettings.noSSEHeader
		noGRPCHeader = s.RNetworkSettings.noGRPCHeader
		mode = ""
		if s.RNetworkSettings.mode != "" {
			mode = s.RNetworkSettings.mode
		}
	case "grpc":
		serviceName = s.RNetworkSettings.ServiceName
	case "raw", "tcp":
		if httpHeader, err := s.RNetworkSettings.Header.MarshalJSON(); err != nil {
			return nil, err
		} else {
			t, _ := simplejson.NewJson(httpHeader)
			htype := t.Get("type").MustString()
			if htype == "http" {
				path = t.Get("request").Get("path").MustString()
				header, _ = json.Marshal(map[string]any{
					"type": "http",
					"request": map[string]any{
						"path": path,
					}})
			} else {
				header, _ = json.Marshal(map[string]any{
					"type": "none",
				})
			}
		}
	case "quic":
		return nil, errors.New("Quic is deprecated in this version of xray-core")
	case "kcp", "mkcp":
		seed = s.RNetworkSettings.Seed
		congestion = s.RNetworkSettings.Congestion
		if httpHeader, err := s.RNetworkSettings.Header.MarshalJSON(); err != nil {
			return nil, err
		} else {
			h, _ := simplejson.NewJson(httpHeader)
			htype := h.Get("type").MustString()
			if htype != "none" {
				header, _ = json.Marshal(map[string]any{
					"type": htype,
				})
			} else {
				header, _ = json.Marshal(map[string]any{
					"type": "none",
				})
			}
		}
	}

	NodeType := s.RType
	if NodeType == "Shadowsocks" && transportProtocol != "tcp" {
		//NodeType = "Shadowsocks-Plugin"
		return nil, errors.New("Shadowsocks-Plugin is deprecated in this version of NahaN backend")
	}

	// Create GeneralNodeInfo
	nodeInfo := &api.RelayNodeInfo{
		NodeType:        NodeType,
		NodeID:          s.RServerid,
		Port:            uint32(s.RPort),
		Transport:       transportProtocol,
		TLSType:         s.RSecurity,
		Path:            path,
		Host:            host,
		HeartbeatPeriod: HeartbeatPeriod,
		Flow:            Flow,
		Authority:       Authority,
		Seed:            seed,
		Congestion:      congestion,
		ServiceName:     serviceName,
		Fingerprint:     s.RSecuritySettings.Fingerprint,
		Header:          header,
		CypherMethod:    s.RCipher,
		Address:         s.RAddress,
		ListenIP:        s.RListenip,
		ProxyProtocol:   s.RNetworkSettings.ProxyProtocol,
		ServerKey:       s.RServerKey,
		SendIP:          s.RSendThrough,
		PublicKey:       PublicKey,
		ShortId:         ShortId,
		SpiderX:         SpiderX,
		Show:            Show,
		ServerName:      ServerName,
		NoSSEHeader:     noSSEHeader,
		NoGRPCHeader:    noGRPCHeader,
		Mode:            mode,
	}
	return nodeInfo, nil
}
