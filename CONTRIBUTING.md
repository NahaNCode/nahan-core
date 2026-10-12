# Contributing

Maintainer: NahaN <nahancode@gmail.com>.

Submit focused pull requests with synthetic fixtures and regression tests. Use
`gofmt` and the README's patched-modfile procedure. Do not include server data or
credentials. Contributions remain under GPL-3.0; retain upstream notices.

```sh
MODFILE=$(go run ./tools/xray-patch)
go test -p 1 -race -modfile="$MODFILE" ./utility/entryprofile ./utility/controlplane ./api/nahan ./service/controller ./manager
```

Distinguish preflight, receipts, real data-path tests and production reachability.
Do not promise zero downtime based solely on unit tests.
