# Build stage for go modules
FROM golang:1.24-alpine as build
ARG TARGETOS
ARG TARGETARCH
ENV CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH}

WORKDIR /build

COPY go.mod go.mod
COPY go.sum go.sum

RUN go mod download

COPY cmd/web-hooks/ cmd/web-hooks/
COPY pkg/ pkg/
COPY internal/util/ internal/util/

RUN go build -o ./bin/webhook ./cmd/web-hooks/main.go

# Run Stage
FROM gcr.io/distroless/static AS final

ENTRYPOINT ["/app/webhook"]

COPY --from=build /build/bin/webhook /app/webhook