package xdispatcher

//go:generate go run github.com/xtls/xray-core/common/errors/errorgen

import (
	"context"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	routingSession "github.com/xtls/xray-core/features/routing/session"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"

	"github.com/NahaNCode/nahan-core/utility/connectionpolicy"
	"github.com/NahaNCode/nahan-core/utility/egress"
	"github.com/NahaNCode/nahan-core/utility/exitroute"
	"github.com/NahaNCode/nahan-core/utility/limiter"
	"github.com/NahaNCode/nahan-core/utility/rule"
)

var errSniffingTimeout = errors.New("timeout on sniffing")

type cachedReader struct {
	sync.Mutex
	reader buf.Reader
	cache  buf.MultiBuffer
}

func (r *cachedReader) Cache(b *buf.Buffer) {
	var mb buf.MultiBuffer
	if reader, ok := r.reader.(buf.TimeoutReader); ok {
		mb, _ = reader.ReadMultiBufferTimeout(time.Millisecond * 100)
	} else {
		mb, _ = r.reader.ReadMultiBuffer()
	}
	r.Lock()
	if !mb.IsEmpty() {
		r.cache, _ = buf.MergeMulti(r.cache, mb)
	}
	b.Clear()
	rawBytes := b.Extend(buf.Size)
	n := r.cache.Copy(rawBytes)
	b.Resize(0, int32(n))
	r.Unlock()
}

func (r *cachedReader) readInternal() buf.MultiBuffer {
	r.Lock()
	defer r.Unlock()

	if r.cache != nil && !r.cache.IsEmpty() {
		mb := r.cache
		r.cache = nil
		return mb
	}

	return nil
}

func (r *cachedReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb := r.readInternal()
	if mb != nil {
		return mb, nil
	}

	return r.reader.ReadMultiBuffer()
}

func (r *cachedReader) ReadMultiBufferTimeout(timeout time.Duration) (buf.MultiBuffer, error) {
	mb := r.readInternal()
	if mb != nil {
		return mb, nil
	}

	if reader, ok := r.reader.(buf.TimeoutReader); ok {
		return reader.ReadMultiBufferTimeout(timeout)
	}
	return r.reader.ReadMultiBuffer()
}

func (r *cachedReader) Interrupt() {
	r.Lock()
	if r.cache != nil {
		r.cache = buf.ReleaseMulti(r.cache)
	}
	r.Unlock()
	if reader, ok := r.reader.(interface{ Interrupt() }); ok {
		reader.Interrupt()
	}
}

// DefaultDispatcher is a default implementation of Dispatcher.
type DefaultDispatcher struct {
	ConnectionPolicy connectionpolicy.Policy
	Egress           egress.Registry
	ExitRoutes       exitroute.Policy
	sessionMu        sync.Mutex
	sessions         map[string]map[*transport.Link]func()
	revoked          map[string]bool
	leases           map[string]time.Time
	ohm              outbound.Manager
	router           routing.Router
	policy           policy.Manager
	stats            stats.Manager
	dns              dns.Client
	fdns             dns.FakeDNSEngine
	Limiter          *limiter.Limiter
	RuleManager      *rule.Manager
}

func (d *DefaultDispatcher) trackSession(ctx context.Context, email string, link *transport.Link, closeLink func()) {
	d.sessionMu.Lock()
	if d.revoked[email] || (!d.leases[email].IsZero() && !time.Now().Before(d.leases[email])) {
		d.sessionMu.Unlock()
		closeLink()
		return
	}
	if d.sessions == nil {
		d.sessions = make(map[string]map[*transport.Link]func())
	}
	if d.sessions[email] == nil {
		d.sessions[email] = make(map[*transport.Link]func())
	}
	d.sessions[email][link] = closeLink
	d.sessionMu.Unlock()
	context.AfterFunc(ctx, func() {
		d.sessionMu.Lock()
		delete(d.sessions[email], link)
		if len(d.sessions[email]) == 0 {
			delete(d.sessions, email)
		}
		d.sessionMu.Unlock()
	})
}

func (d *DefaultDispatcher) RevokeUser(email string) {
	d.sessionMu.Lock()
	if d.revoked == nil {
		d.revoked = make(map[string]bool)
	}
	d.revoked[email] = true
	callbacks := d.sessions[email]
	delete(d.sessions, email)
	d.sessionMu.Unlock()
	for _, closeLink := range callbacks {
		closeLink()
	}
}
func (d *DefaultDispatcher) AllowUser(email string) {
	d.sessionMu.Lock()
	delete(d.revoked, email)
	d.sessionMu.Unlock()
}

func (d *DefaultDispatcher) LeaseUser(email string, deadline time.Time) {
	d.sessionMu.Lock()
	if d.leases == nil {
		d.leases = make(map[string]time.Time)
	}
	d.leases[email] = deadline
	delete(d.revoked, email)
	d.sessionMu.Unlock()
	if deadline.IsZero() {
		return
	}
	time.AfterFunc(time.Until(deadline), func() {
		d.sessionMu.Lock()
		if !d.leases[email].Equal(deadline) {
			d.sessionMu.Unlock()
			return
		}
		if d.revoked == nil {
			d.revoked = make(map[string]bool)
		}
		d.revoked[email] = true
		callbacks := d.sessions[email]
		delete(d.sessions, email)
		d.sessionMu.Unlock()
		for _, closeLink := range callbacks {
			closeLink()
		}
	})
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		d := new(DefaultDispatcher)
		if err := core.RequireFeatures(ctx, func(om outbound.Manager, router routing.Router, pm policy.Manager, sm stats.Manager, dc dns.Client) error {
			core.OptionalFeatures(ctx, func(fdns dns.FakeDNSEngine) {
				d.fdns = fdns
			})
			return d.Init(config.(*Config), om, router, pm, sm, dc)
		}); err != nil {
			return nil, err
		}
		return d, nil
	}))
}

// Init initializes DefaultDispatcher.
func (d *DefaultDispatcher) Init(config *Config, om outbound.Manager, router routing.Router, pm policy.Manager, sm stats.Manager, dns dns.Client) error {
	d.ohm = om
	d.router = router
	d.policy = pm
	d.stats = sm
	d.Limiter = limiter.New()
	d.RuleManager = rule.New()
	d.dns = dns
	return nil
}

// Type implements common.HasType.
func (*DefaultDispatcher) Type() interface{} {
	return routing.DispatcherType()
}

// Start implements common.Runnable.
func (*DefaultDispatcher) Start() error {
	return nil
}

// Close implements common.Closable.
func (*DefaultDispatcher) Close() error {
	return nil
}

func (d *DefaultDispatcher) getLink(ctx context.Context, network net.Network) (*transport.Link, *transport.Link, error) {
	opt := pipe.OptionsFromContext(ctx)
	uplinkReader, uplinkWriter := pipe.New(opt...)
	downlinkReader, downlinkWriter := pipe.New(opt...)

	inboundLink := &transport.Link{
		Reader: downlinkReader,
		Writer: uplinkWriter,
	}

	outboundLink := &transport.Link{
		Reader: uplinkReader,
		Writer: downlinkWriter,
	}

	sessionInbound := session.InboundFromContext(ctx)
	var user *protocol.MemoryUser
	if sessionInbound != nil {
		user = sessionInbound.User
	}

	if user != nil && len(user.Email) > 0 {
		// Speed Limit and Device Limit
		bucket, ok, reject := d.Limiter.GetUserBucket(sessionInbound.Tag, user.Email, sessionInbound.Source.Address.IP().String())
		if reject {
			errors.LogWarning(ctx, "Subscription ", user.Email, " has exceeded allowed IP limit")
			common.Close(outboundLink.Writer)
			common.Close(inboundLink.Writer)
			common.Interrupt(outboundLink.Reader)
			common.Interrupt(inboundLink.Reader)
			return nil, nil, errors.New("Subscription ", user.Email, " has exceeded allowed IP limit")
		}
		if ok {
			inboundLink.Writer = d.Limiter.RateWriterContext(inboundLink.Writer, bucket, ctx)
			outboundLink.Writer = d.Limiter.RateWriterContext(outboundLink.Writer, bucket, ctx)
		}
		activity := func() {
			d.Limiter.TouchOnline(sessionInbound.Tag, user.Email, sessionInbound.Source.Address.IP().String())
		}
		inboundLink.Writer = &activityWriter{Writer: inboundLink.Writer, touch: activity}
		outboundLink.Writer = &activityWriter{Writer: outboundLink.Writer, touch: activity}

		p := d.policy.ForLevel(user.Level)
		if p.Stats.UserUplink {
			name := "user>>>" + user.Email + ">>>traffic>>>uplink"
			if c, _ := d.stats.GetOrRegisterCounter(name); c != nil {
				inboundLink.Writer = &SizeStatWriter{
					Counter: c,
					Writer:  inboundLink.Writer,
				}
			}
		}
		if p.Stats.UserDownlink {
			name := "user>>>" + user.Email + ">>>traffic>>>downlink"
			if c, _ := d.stats.GetOrRegisterCounter(name); c != nil {
				outboundLink.Writer = &SizeStatWriter{
					Counter: c,
					Writer:  outboundLink.Writer,
				}
			}
		}
		d.trackSession(ctx, user.Email, outboundLink, func() {
			common.Interrupt(outboundLink.Reader)
			common.Interrupt(outboundLink.Writer)
			common.Interrupt(inboundLink.Reader)
			common.Interrupt(inboundLink.Writer)
		})
	}

	return inboundLink, outboundLink, nil
}

func (d *DefaultDispatcher) shouldOverride(ctx context.Context, result SniffResult, request session.SniffingRequest, destination net.Destination) bool {
	domain := result.Domain()
	if request.ExcludeForDomain != nil && request.ExcludeForDomain.MatchAny(domain) {
		return false
	}
	protocolString := result.Protocol()
	if resComp, ok := result.(SnifferResultComposite); ok {
		protocolString = resComp.ProtocolForDomainResult()
	}
	for _, p := range request.OverrideDestinationForProtocol {
		if strings.HasPrefix(protocolString, p) || strings.HasPrefix(p, protocolString) {
			return true
		}
		if fkr0, ok := d.fdns.(dns.FakeDNSEngineRev0); ok && protocolString != "bittorrent" && p == "fakedns" &&
			destination.Address.Family().IsIP() && fkr0.IsIPInIPPool(destination.Address) {
			errors.LogInfo(ctx, "Using sniffer ", protocolString, " since the fake DNS missed")
			return true
		}
		if resultSubset, ok := result.(SnifferIsProtoSubsetOf); ok {
			if resultSubset.IsProtoSubsetOf(p) {
				return true
			}
		}
	}

	return false
}

// Dispatch implements routing.Dispatcher.
func (d *DefaultDispatcher) Dispatch(ctx context.Context, destination net.Destination) (*transport.Link, error) {
	if !destination.IsValid() {
		panic("Dispatcher: Invalid destination.")
	}
	outbounds := session.OutboundsFromContext(ctx)
	if len(outbounds) == 0 {
		outbounds = []*session.Outbound{{}}
		ctx = session.ContextWithOutbounds(ctx, outbounds)
	}
	ob := outbounds[len(outbounds)-1]
	ob.OriginalTarget = destination
	ob.Target = destination
	content := session.ContentFromContext(ctx)
	if content == nil {
		content = new(session.Content)
		ctx = session.ContextWithContent(ctx, content)
	}

	sniffingRequest := content.SniffingRequest
	inbound, outbound, err := d.getLink(ctx, destination.Network)
	if err != nil {
		return nil, err
	}
	if !sniffingRequest.Enabled {
		go d.routedDispatch(ctx, outbound, destination)
	} else {
		go func() {
			cReader := &cachedReader{
				reader: outbound.Reader,
			}
			outbound.Reader = cReader
			result, err := sniffer(ctx, cReader, sniffingRequest.MetadataOnly, destination.Network)
			if err == nil {
				content.Protocol = result.Protocol()
			}
			if err == nil && d.shouldOverride(ctx, result, sniffingRequest, destination) {
				domain := result.Domain()
				errors.LogInfo(ctx, "sniffed domain: ", domain)
				destination.Address = net.ParseAddress(domain)
				if sniffingRequest.RouteOnly && result.Protocol() != "fakedns" {
					ob.RouteTarget = destination
				} else {
					ob.Target = destination
				}
			}
			d.routedDispatch(ctx, outbound, destination)
		}()
	}
	return inbound, nil
}

// DispatchLink implements routing.Dispatcher.
func (d *DefaultDispatcher) DispatchLink(ctx context.Context, destination net.Destination, outbound *transport.Link) error {
	if !destination.IsValid() {
		return errors.New("Dispatcher: Invalid destination.")
	}
	outbounds := session.OutboundsFromContext(ctx)
	if len(outbounds) == 0 {
		outbounds = []*session.Outbound{{}}
		ctx = session.ContextWithOutbounds(ctx, outbounds)
	}
	ob := outbounds[len(outbounds)-1]
	ob.OriginalTarget = destination
	ob.Target = destination
	content := session.ContentFromContext(ctx)
	if content == nil {
		content = new(session.Content)
		ctx = session.ContextWithContent(ctx, content)
	}
	outbound = d.wrapLink(ctx, outbound)
	sniffingRequest := content.SniffingRequest
	if !sniffingRequest.Enabled {
		d.routedDispatch(ctx, outbound, destination)
	} else {
		cReader := &cachedReader{
			reader: outbound.Reader,
		}
		outbound.Reader = cReader
		result, err := sniffer(ctx, cReader, sniffingRequest.MetadataOnly, destination.Network)
		if err == nil {
			content.Protocol = result.Protocol()
		}
		if err == nil && d.shouldOverride(ctx, result, sniffingRequest, destination) {
			domain := result.Domain()
			errors.LogInfo(ctx, "sniffed domain: ", domain)
			destination.Address = net.ParseAddress(domain)
			if sniffingRequest.RouteOnly && result.Protocol() != "fakedns" {
				ob.RouteTarget = destination
			} else {
				ob.Target = destination
			}
		}
		d.routedDispatch(ctx, outbound, destination)
	}

	return nil
}

func (d *DefaultDispatcher) wrapLink(ctx context.Context, link *transport.Link) *transport.Link {
	inbound := session.InboundFromContext(ctx)
	var user *protocol.MemoryUser
	if inbound != nil {
		user = inbound.User
	}

	reader := &buf.TimeoutWrapperReader{Reader: link.Reader}
	owned := &sessionReader{TimeoutWrapperReader: reader}
	if inbound != nil {
		owned.connection = inbound.Conn
	}
	link.Reader = owned
	if user == nil || user.Email == "" {
		return link
	}
	bucket, limited, reject := d.Limiter.GetUserBucket(inbound.Tag, user.Email, inbound.Source.Address.IP().String())
	if reject {
		owned.Interrupt()
		common.Interrupt(link.Writer)
		return link
	}
	if limited {
		reader.Reader = d.Limiter.RateReader(reader.Reader, bucket, ctx)
		link.Writer = d.Limiter.RateWriterContext(link.Writer, bucket, ctx)
	}
	activity := &activityWriter{Writer: link.Writer, touch: func() {
		d.Limiter.TouchOnline(inbound.Tag, user.Email, inbound.Source.Address.IP().String())
	}}
	activity.mark()
	reader.Reader = &activityReader{Reader: reader.Reader, activity: activity}
	link.Writer = activity

	policy := d.policy.ForLevel(user.Level)
	if policy.Stats.UserUplink {
		counter, _ := d.stats.GetOrRegisterCounter("user>>>" + user.Email + ">>>traffic>>>uplink")
		reader.Counter = counter
	}
	if policy.Stats.UserDownlink {
		counter, _ := d.stats.GetOrRegisterCounter("user>>>" + user.Email + ">>>traffic>>>downlink")
		if counter != nil {
			link.Writer = &SizeStatWriter{Counter: counter, Writer: link.Writer}
		}
	}
	if policy.Stats.UserOnline {
		if online, _ := d.stats.GetOrRegisterOnlineMap("user>>>" + user.Email + ">>>online"); online != nil {
			ip := inbound.Source.Address.String()
			online.AddIP(ip)
			context.AfterFunc(ctx, func() { online.RemoveIP(ip) })
		}
	}
	d.trackSession(ctx, user.Email, link, func() { owned.Interrupt(); common.Interrupt(link.Writer) })
	return link
}

// DispatchLink owns a physical inbound; Mux substreams use Dispatch/pipe instead.
// TimeoutWrapperReader does not forward Interrupt to its underlying reader.
type sessionReader struct {
	*buf.TimeoutWrapperReader
	connection net.Conn
	once       sync.Once
}

func (r *sessionReader) Interrupt() {
	r.once.Do(func() {
		common.Interrupt(r.Reader)
		if r.connection != nil {
			r.connection.Close()
		}
	})
}

func sniffer(ctx context.Context, cReader *cachedReader, metadataOnly bool, network net.Network) (SniffResult, error) {
	payload := buf.New()
	defer payload.Release()

	sniffer := NewSniffer(ctx)

	metaresult, metadataErr := sniffer.SniffMetadata(ctx)

	if metadataOnly {
		return metaresult, metadataErr
	}

	contentResult, contentErr := func() (SniffResult, error) {
		totalAttempt := 0
		for {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
				totalAttempt++
				if totalAttempt > 2 {
					return nil, errSniffingTimeout
				}

				cReader.Cache(payload)
				if !payload.IsEmpty() {
					result, err := sniffer.Sniff(ctx, payload.Bytes(), network)
					if err != common.ErrNoClue {
						return result, err
					}
				}
				if payload.IsFull() {
					return nil, errUnknownContent
				}
			}
		}
	}()
	if contentErr != nil && metadataErr == nil {
		return metaresult, nil
	}
	if contentErr == nil && metadataErr == nil {
		return CompositeResult(metaresult, contentResult), nil
	}
	return contentResult, contentErr
}

func (d *DefaultDispatcher) routedDispatch(ctx context.Context, link *transport.Link, destination net.Destination) {
	var handler outbound.Handler

	// Check if domain and protocol hit the rule
	sessionInbound := session.InboundFromContext(ctx)
	// Whether the inbound connection contains a user
	if sessionInbound.User != nil {
		if d.RuleManager.Detect(sessionInbound.Tag, destination.String(), sessionInbound.User.Email) {
			errors.LogInfo(ctx, "User ", sessionInbound.User.Email, " access ", destination.String(), " reject by rule")
			errors.New("destination is reject by rule")
			common.Close(link.Writer)
			common.Interrupt(link.Reader)
			return
		}
	}

	routingLink := routingSession.AsRoutingContext(ctx)
	policyIPs := make([]netip.Addr, 0, 2)
	for _, ip := range routingLink.GetTargetIPs() {
		if address, ok := netip.AddrFromSlice(ip); ok {
			policyIPs = append(policyIPs, address)
		}
	}
	if sessionInbound.User != nil && d.ConnectionPolicy.BlockedRequest(routingLink.GetTargetDomain(), policyIPs, uint16(routingLink.GetTargetPort()), routingLink.GetNetwork().SystemString()) {
		common.Close(link.Writer)
		common.Interrupt(link.Reader)
		return
	}
	inTag := routingLink.GetInboundTag()
	managedTag, managed, expired, release := d.Egress.Acquire(inTag)
	defer release()
	sourceIP, localIP := "", ""
	if sessionInbound.Source.Address != nil && sessionInbound.Source.Address.Family().IsIP() {
		sourceIP = sessionInbound.Source.Address.IP().String()
	}
	if sessionInbound.Gateway.Address != nil && sessionInbound.Gateway.Address.Family().IsIP() {
		localIP = sessionInbound.Gateway.Address.IP().String()
	}
	if sessionInbound.Local.Address != nil && sessionInbound.Local.Address.Family().IsIP() {
		localIP = sessionInbound.Local.Address.IP().String()
	}
	exitTag, exitManaged, exitExpired, exitRelease := d.ExitRoutes.Acquire(inTag, sourceIP, localIP)
	defer exitRelease()
	isPickRoute := 0
	if forcedOutboundTag := session.GetForcedOutboundTagFromContext(ctx); forcedOutboundTag != "" {
		ctx = session.SetForcedOutboundTagToContext(ctx, "")
		if h := d.ohm.GetHandler(forcedOutboundTag); h != nil {
			isPickRoute = 1
			errors.LogInfo(ctx, "taking platform initialized detour [", forcedOutboundTag, "] for [", destination, "]")
			handler = h
		} else {
			errors.LogInfo(ctx, "non existing tag for platform initialized detour: ", forcedOutboundTag)
			common.Close(link.Writer)
			common.Interrupt(link.Reader)
			return
		}
	} else if exitManaged {
		if exitExpired || d.ohm.GetHandler(exitTag) == nil {
			common.Close(link.Writer)
			common.Interrupt(link.Reader)
			return
		}
		handler = d.ohm.GetHandler(exitTag)
		isPickRoute = 2
	} else if managed {
		if expired {
			common.Close(link.Writer)
			common.Interrupt(link.Reader)
			return
		}
		handler = d.ohm.GetHandler(managedTag)
		if handler == nil {
			common.Close(link.Writer)
			common.Interrupt(link.Reader)
			return
		}
		isPickRoute = 2
	} else if d.router != nil {
		if route, err := d.router.PickRoute(routingLink); err == nil {
			outTag := route.GetOutboundTag()
			if h := d.ohm.GetHandler(outTag); h != nil {
				isPickRoute = 2
				errors.LogInfo(ctx, "taking detour [", outTag, "] for [", destination, "]")
				handler = h
			} else {
				errors.LogError(ctx, "non existing tag for platform initialized detour: ", outTag)
			}
		} else {
			errors.LogInfo(ctx, "default route for ", destination)
		}
	}

	if handler == nil {
		handler = d.ohm.GetHandler(inTag) // Default outbound handler tag should be as same as the inbound tag
	}

	// If there is no outbound with tag as same as the inbound tag
	if handler == nil {
		handler = d.ohm.GetDefaultHandler()
	}

	if handler == nil {
		errors.LogInfo(ctx, "default outbound handler not exist")
		common.Close(link.Writer)
		common.Interrupt(link.Reader)
		return
	}

	// Newer Xray outbound handlers rely on the selected tag in session context.
	ob := session.OutboundsFromContext(ctx)
	if len(ob) > 0 {
		ob[len(ob)-1].Tag = handler.Tag()
	}

	if accessMessage := log.AccessMessageFromContext(ctx); accessMessage != nil {
		if tag := handler.Tag(); tag != "" {
			if inTag == "" {
				accessMessage.Detour = tag
			} else if isPickRoute == 1 {
				accessMessage.Detour = inTag + " ==> " + tag
			} else if isPickRoute == 2 {
				accessMessage.Detour = inTag + " -> " + tag
			} else {
				accessMessage.Detour = inTag + " >> " + tag
			}
		}
		log.Record(accessMessage)
	}

	handler.Dispatch(ctx, link)
}
