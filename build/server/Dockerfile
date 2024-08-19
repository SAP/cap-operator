# Build stage for go modules
FROM golang:1.23-alpine as build
ARG TARGETOS
ARG TARGETARCH
ENV CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH}

WORKDIR /build

COPY go.mod go.mod
COPY go.sum go.sum

RUN go mod download

COPY cmd/server/ cmd/server/
COPY pkg pkg/
COPY internal/util/ internal/util/

RUN go build -o ./bin/server ./cmd/server/server.go

# Run Stage
FROM gcr.io/distroless/static AS final

ENTRYPOINT ["/app/server"]

COPY --from=build /build/bin/server /app/server