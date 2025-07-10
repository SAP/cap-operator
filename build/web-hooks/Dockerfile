# Build stage for go modules
FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS build

WORKDIR /build

COPY go.mod go.sum .

RUN go mod download

COPY cmd/web-hooks/ cmd/web-hooks/
COPY pkg/ pkg/
COPY internal/util/ internal/util/

ARG TARGETOS TARGETARCH
ENV CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH}

RUN --mount=type=cache,target=/go/pkg \
    --mount=type=cache,target=/root/.cache/go-build \
    go build -o ./bin/webhook ./cmd/web-hooks/main.go

# Run Stage
FROM gcr.io/distroless/static:nonroot AS final

ENTRYPOINT ["/app/webhook"]

COPY --from=build /build/bin/webhook /app/webhook