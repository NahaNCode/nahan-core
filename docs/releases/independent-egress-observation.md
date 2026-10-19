# Independent Published-Path Observation

Published-path health checks now run periodically without requiring another successful control synchronization. An installed, committed snapshot can restart observation from authenticated persisted state. Missing desired documents, delayed credential imports, and failed health-report delivery no longer silently stop the observer.

## Changes

- One bounded periodic observation worker per core.
- Retry health reporting on the next observation cycle after delivery failures.
- Restore observation for the exact committed publication after startup.
- Ignore results from superseded publications.
- Preserve cancellation for explicit policy changes, manager replacement, and shutdown.
- Add regression coverage for independent scheduling and reporting recovery.

## Security And Rollout

Observation does not renew or grant route authorization, change customer credentials, or modify access policy. This change requires a new core build and update; it is not enabled by deploying the panel backend. Existing production cores are not restarted as part of preparation.
