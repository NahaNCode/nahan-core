# Docker deployment

The image packages the NahaN controller and its embedded Xray core together. It does not contain panel credentials or node configuration; those stay in the mounted `runtime/` directory.

## Run on one host

1. Install Docker Engine and the Docker Compose plugin. On Linux, ensure `/dev/net/tun` exists if the configured Xray outbound uses kernel WireGuard.
2. Download config.json and core.key from the panel's installation-package screen and place them together in a private runtime directory. Preserve the issued ApiHost, CoreID and ServerName. The exported key path is ./core.key, resolved from the container working directory, /etc/NahaN. Do not commit these files.
3. Make it writable by the container user (UID/GID `10001`). For example: `sudo chown -R 10001:10001 runtime`.
4. Build the image. For the exported JSON package, run the container with `--config /etc/NahaN/config.json`; the image's default config.yml path is not the panel's download filename. For Compose, add `command: ["--config", "/etc/NahaN/config.json"]` to the service before starting it.
5. Inspect startup with `docker compose logs -f nahan`; inspect state with `docker compose ps`.

Compose uses host networking so ports and source addresses behave as they do under the existing host service. It grants only `NET_ADMIN` and `NET_BIND_SERVICE`, and maps `/dev/net/tun` for kernel WireGuard. Do not run a second instance against the same node configuration or ports on one host.

## End-to-end verification

After startup, test a client through the node's actual VLESS/Reality configuration and request an external HTTPS endpoint. Require a successful response and the expected outbound IP. A listening port, an established TCP connection, or an `accepted` entry in `access.log` proves only that the request reached NahaN. It does not prove that the outbound returned data.

The previous custom dispatcher returned immediately from `DispatchLink` while its outbound ran in a goroutine. Xray's VLESS inbound closes the link when `DispatchLink` returns, so clients saw `EOF` even though NahaN logged accepted requests. Keep both the sniffing and non-sniffing `DispatchLink` paths synchronous. `Dispatch` has a different contract and still runs its outbound asynchronously.

When testing a candidate image beside the active service, use an isolated runtime copy and a different loopback-only port. Stop and remove that candidate after testing; do not leave two instances reporting the same node to the panel. Cut over the production port only after the client test succeeds, and keep the previous image or service available for rollback.

## Versioned images

The `Publish container image` GitHub Actions workflow publishes to `ghcr.io/<owner>/<repository>` on pushes to `main` and the experiment branch, and on `v*` tags. Each build also receives a full commit-SHA tag. For production, pin `NAHAN_IMAGE` to a full SHA or release tag rather than `latest`:

```sh
NAHAN_IMAGE=ghcr.io/nahancode/nahan-core:sha-<full-commit> docker compose pull
NAHAN_IMAGE=ghcr.io/nahancode/nahan-core:sha-<full-commit> docker compose up -d
```

The first package may be private. Grant the target host a read-only GitHub Packages credential, then authenticate with `docker login ghcr.io` before pulling. The image build itself needs only the repository's normal `GITHUB_TOKEN` package permission.

## Upgrade and rollback

Keep the runtime directory and record the currently deployed immutable image tag. Pull the new tag, then run `docker compose up -d`; Compose replaces the container while preserving the host configuration and runtime data. To roll back, set `NAHAN_IMAGE` to the previous immutable tag and run `docker compose up -d` again. Check the container logs and validate a real client session and outbound traffic after each rollout; process startup alone is not an end-to-end health check.

## High availability

`restart: unless-stopped` restarts NahaN after a process or host restart; it is not high availability. Do not scale this Compose service on one host: instances would contend for the same listener ports and node identity. For multi-host HA, deploy one independently configured instance per host, register each node/identity as supported by the panel, and use an external health-aware failover mechanism (for example, the existing tunnel monitor or a provider load balancer) to withdraw an unhealthy host. Validate client protocol health, not only TCP reachability. Keep each host's runtime credentials separate and back up its configuration securely.
