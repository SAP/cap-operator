# Build stage for go modules
FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS build

WORKDIR /build

COPY go.mod go.sum .

RUN go mod download

COPY cmd/controller/ cmd/controller/
COPY pkg/ pkg/
COPY internal/ internal/

ARG TARGETOS TARGETARCH
ENV CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH}

RUN --mount=type=cache,target=/go/pkg \
    --mount=type=cache,target=/root/.cache/go-build \
    go build -o ./bin/controller ./cmd/controller/

# Run Stage
FROM gcr.io/distroless/static:nonroot AS final

ENTRYPOINT ["/app/controller"]

COPY --from=build /build/bin/controller /app/controller