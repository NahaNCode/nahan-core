package cmd

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/NahaNCode/nahan-core/api/nahan"
	"github.com/NahaNCode/nahan-core/manager"
	"github.com/NahaNCode/nahan-core/service/controller"
	"github.com/NahaNCode/nahan-core/utility/controlplane"
)

// Network-only heartbeat/manifest workers never touch the mutable engine owner.
// The owner serializes jobs, configuration swaps, policy and route changes.
func serveManagedControl(parent context.Context, panel *controlplane.Client, active **manager.Manager, config *manager.Config, manifest *controlplane.Manifest, template *controller.Config, startupError string) error {
	ctx, stop := context.WithCancelCause(parent)
	var workers sync.WaitGroup
	defer func() { stop(nil); workers.Wait() }()
	var heartbeat atomic.Pointer[controlplane.HeartbeatState]
	lastApplyError := startupError
	publish := func() {
		state := panel.CaptureHeartbeat(manifest, lastApplyError)
		heartbeat.Store(&state)
	}
	publish()
	latest := make(chan *controlplane.Manifest, 1)
	workers.Add(2)
	go func() {
		defer workers.Done()
		controlplane.Poll(ctx, 10*time.Second, 27*time.Second, func(attempt context.Context) error {
			return panel.SendHeartbeat(attempt, version, *heartbeat.Load())
		}, stop)
	}()
	go func() {
		defer workers.Done()
		controlplane.Poll(ctx, 10*time.Second, 27*time.Second, func(attempt context.Context) error {
			next, err := panel.Manifest(attempt)
			if err == nil {
				// At most one pending immutable manifest, latest revision wins.
				select {
				case <-latest:
				default:
				}
				select {
				case latest <- next:
				case <-ctx.Done():
				}
			}
			return err
		}, stop)
	}()

	ticker := time.NewTicker(2500 * time.Millisecond)
	defer ticker.Stop()
	var rejectedRevision int64
	lane := 0
	for {
		select {
		case <-ctx.Done():
			if parent.Err() != nil {
				return nil
			}
			return context.Cause(ctx)
		case next := <-latest:
			if next.Revision < manifest.Revision || next.Revision == manifest.Revision || next.Revision == rejectedRevision {
				continue
			}
			attempt, cancel := context.WithTimeout(ctx, 27*time.Second)
			candidate, prepareError := prepareManagedNodesContext(attempt, panel, next, template)
			cancel()
			if prepareError != nil {
				lastApplyError = "configuration retrieval unavailable"
				if !errors.Is(prepareError, errManagedFetch) {
					rejectedRevision, lastApplyError = next.Revision, "configuration preflight failed"
				}
				publish()
				continue
			}
			lastApplyError = "configuration applying"
			publish()
			previous := config.NodesConfig
			panel.CloseEgressPreflight()
			panel.CloseEgressHealth()
			(*active).Close()
			config.NodesConfig = candidate
			*active = manager.New(config)
			if err := (*active).StartChecked(); err != nil {
				rejectedRevision, lastApplyError = next.Revision, "configuration rolled back"
				for _, node := range previous {
					if prepared, ok := node.PreparedAPI.(*nahan.PreparedClient); ok {
						prepared.Reset()
					}
				}
				config.NodesConfig = previous
				*active = manager.New(config)
				if err := (*active).StartChecked(); err != nil {
					return fmt.Errorf("managed rollback failed")
				}
			} else {
				manifest, rejectedRevision, lastApplyError = next, 0, ""
				if err := saveManagedSnapshot(panel, manifest, config.NodesConfig); err != nil {
					lastApplyError = "snapshot persistence failed"
				}
			}
			publish()
		case <-ticker.C:
			if ctx.Err() != nil {
				continue
			}
			// One shared budget for the complete operation, not 30s per sub-request.
			attempt, cancel := context.WithTimeout(ctx, 27*time.Second)
			var err error
			switch lane {
			case 0:
				err = panel.ProcessJobs(attempt)
			case 1:
				err = syncEgressContext(attempt, panel, *active, config)
			case 2:
				err = syncExitRoutingContext(attempt, panel, *active, config)
			case 3:
				err = syncPolicyContext(attempt, panel, *active, config)
			}
			cancel()
			lane = (lane + 1) % 4
			if errors.Is(err, controlplane.ErrUnauthorized) {
				stop(err)
			}
			publish()
		}
	}
}
