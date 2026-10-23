package limiter

import "golang.org/x/time/rate"

// Recompute on configuration changes, not on each packet or connection. An
// assignment with a larger ceiling must not raise another assignment's limit.
func (l *Limiter) refreshServiceRates() {
	l.rateMu.Lock()
	defer l.rateMu.Unlock()
	limits := make(map[string]uint64)
	l.InboundInfo.Range(func(_, value interface{}) bool {
		inbound := value.(*InboundInfo)
		inbound.SubscriptionInfo.Range(func(email, value interface{}) bool {
			user := value.(SubscriptionInfo)
			key := bucketKey(email.(string), user)
			limits[key] = determineRate(limits[key], determineRate(inbound.NodeSpeedLimit, user.SpeedLimit))
			return true
		})
		return true
	})
	l.serviceLimits = limits
	l.serviceBuckets.Range(func(key, value interface{}) bool {
		limit, exists := limits[key.(string)]
		bucket := value.(*rate.Limiter)
		if !exists {
			l.serviceBuckets.Delete(key)
			return true
		}
		if limit == 0 {
			// Keep the object held by existing streams, rather than orphaning a
			// still-limited bucket while new streams get another one.
			bucket.SetLimit(rate.Inf)
		} else {
			bucket.SetBurst(int(limit))
			bucket.SetLimit(rate.Limit(limit))
		}
		return true
	})
}
