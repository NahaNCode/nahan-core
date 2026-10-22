FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=development
ARG COMMIT=development

WORKDIR /src
RUN apk add --no-cache git
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go run ./tools/xray-patch > /tmp/xray-modfile \
    && go test -modfile="$(cat /tmp/xray-modfile)" ./internal/regression ./app/xdispatcher ./cmd ./manager ./utility/connectionpolicy ./utility/controlplane ./utility/paneltls ./utility/outbox ./utility/limiter ./utility/egress ./utility/update ./api/nahan ./service/controller \
    && CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -modfile="$(cat /tmp/xray-modfile)" -trimpath -ldflags="-s -w -buildid= -X github.com/NahaNCode/nahan-core/cmd.version=$VERSION -X github.com/NahaNCode/nahan-core/cmd.buildCommit=$COMMIT" -o /out/NahaN .

FROM alpine:3.22
RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -S -g 10001 nahan \
    && adduser -S -D -H -u 10001 -G nahan nahan \
    && mkdir -p /etc/NahaN \
    && chown nahan:nahan /etc/NahaN

COPY --from=build /out/NahaN /usr/local/bin/NahaN
ENV XRAY_LOCATION_ASSET=/etc/NahaN \
    XRAY_LOCATION_CONFIG=/etc/NahaN \
    TZ=UTC
VOLUME ["/etc/NahaN"]
WORKDIR /etc/NahaN
USER nahan:nahan
ENTRYPOINT ["/usr/local/bin/NahaN", "--config", "/etc/NahaN/config.yml"]
