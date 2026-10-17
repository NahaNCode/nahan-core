package controller

import (
	"context"
	"fmt"

	"github.com/NahaNCode/nahan-core/api"
	"github.com/NahaNCode/nahan-core/utility/limiter"
	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy"
)

func (c *Controller) removeInbound(tag string) error {
	err := c.ibm.RemoveHandler(context.Background(), tag)
	return err
}

func (c *Controller) removeOutbound(tag string) error {
	err := c.obm.RemoveHandler(context.Background(), tag)
	return err
}

func (c *Controller) addInbound(config *core.InboundHandlerConfig) error {
	rawHandler, err := core.CreateObject(c.server, config)
	if err != nil {
		return err
	}
	handler, ok := rawHandler.(inbound.Handler)
	if !ok {
		return fmt.Errorf("not an InboundHandler: %s", err)
	}
	if err := c.ibm.AddHandler(context.Background(), handler); err != nil {
		return err
	}
	return nil
}

func (c *Controller) addOutbound(config *core.OutboundHandlerConfig) error {
	rawHandler, err := core.CreateObject(c.server, config)
	if err != nil {
		return err
	}
	handler, ok := rawHandler.(outbound.Handler)
	if !ok {
		return fmt.Errorf("not an InboundHandler: %s", err)
	}
	if err := c.obm.AddHandler(context.Background(), handler); err != nil {
		return err
	}
	return nil
}

func (c *Controller) addInboundSubscriptions(users []*protocol.User, tag string) error {
	handler, err := c.ibm.GetHandler(context.Background(), tag)
	if err != nil {
		return fmt.Errorf("no such inbound tag: %s", err)
	}
	inboundInstance, ok := handler.(proxy.GetInbound)
	if !ok {
		return fmt.Errorf("handler %s has not implemented proxy.GetInbound", tag)
	}

	userManager, ok := inboundInstance.GetInbound().(proxy.UserManager)
	if !ok {
		return fmt.Errorf("handler %s has not implemented proxy.UserManager", tag)
	}
	for _, item := range users {
		c.dispatcher.AllowUser(item.Email)
		mUser, err := item.ToMemoryUser()
		if err != nil {
			return err
		}
		err = userManager.AddUser(context.Background(), mUser)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *Controller) removeInboundSubscriptions(users []string, tag string) error {
	handler, err := c.ibm.GetHandler(context.Background(), tag)
	if err != nil {
		return fmt.Errorf("no such inbound tag: %s", err)
	}
	inboundInstance, ok := handler.(proxy.GetInbound)
	if !ok {
		return fmt.Errorf("handler %s is not implement proxy.GetInbound", tag)
	}

	userManager, ok := inboundInstance.GetInbound().(proxy.UserManager)
	if !ok {
		return fmt.Errorf("handler %s is not implement proxy.UserManager", err)
	}
	for _, email := range users {
		c.dispatcher.RevokeUser(email)
		c.limiter.RemoveUser(tag, email)
		err = userManager.RemoveUser(context.Background(), email)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *Controller) getTraffic(email string) (up int64, down int64, upCounter stats.Counter, downCounter stats.Counter) {
	upName := "user>>>" + email + ">>>traffic>>>uplink"
	downName := "user>>>" + email + ">>>traffic>>>downlink"
	upCounter = c.stm.GetCounter(upName)
	downCounter = c.stm.GetCounter(downName)
	if upCounter != nil {
		up = upCounter.Value()
	} else {
		upCounter = nil
	}
	if downCounter != nil {
		down = downCounter.Value()
	} else {
		downCounter = nil
	}
	return up, down, upCounter, downCounter
}

type trafficSnapshot struct {
	counter stats.Counter
	value   int64
}

func consumeTraffic(snapshots []trafficSnapshot) {
	for _, snapshot := range snapshots {
		snapshot.counter.Add(-snapshot.value)
	}
}

func (c *Controller) AddInboundLimiter(tag string, nodeSpeedLimit uint64, userList *[]api.SubscriptionInfo, globalIPLimit *limiter.IPLimit) error {
	var gate api.DeviceGate
	if source, ok := c.apiClient.(interface{ DeviceGate() api.DeviceGate }); ok {
		gate = source.DeviceGate()
	}
	err := c.limiter.AddInboundLimiter(tag, nodeSpeedLimit, userList, globalIPLimit, gate)
	return err
}

func (c *Controller) UpdateInboundLimiter(tag string, updatedUserList *[]api.SubscriptionInfo) error {
	err := c.limiter.UpdateInboundLimiter(tag, updatedUserList)
	return err
}

func (c *Controller) DeleteInboundLimiter(tag string) error {
	err := c.limiter.DeleteInboundLimiter(tag)
	return err
}

func (c *Controller) GetOnlineDevice(tag string) (*[]api.OnlineIP, error) {
	return c.limiter.GetOnlineDevice(tag)
}

func (c *Controller) UpdateRule(tag string, newRuleList []api.DetectRule) error {
	err := c.ruleManager.UpdateRule(tag, newRuleList)
	return err
}

func (c *Controller) GetDetectResult(tag string) (*[]api.DetectResult, error) {
	return c.ruleManager.GetDetectResult(tag)
}

func (c *Controller) AddRouterRule(config *router.Config, shouldAppend bool) error {
	err := c.routerule.AddRule(serial.ToTypedMessage(config), shouldAppend)
	return err
}

func (c *Controller) RemoveRouterRule(tag string) error {
	err := c.routerule.RemoveRule(tag)
	return err
}
