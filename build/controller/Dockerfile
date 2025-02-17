# Build stage for go modules
FROM golang:1.24-alpine as build
ARG TARGETOS
ARG TARGETARCH
ENV CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH}

WORKDIR /build

COPY go.mod go.mod
COPY go.sum go.sum

RUN go mod download

COPY cmd/controller/ cmd/controller/
COPY pkg/ pkg/
COPY internal/ internal/

RUN go build -o ./bin/controller ./cmd/controller/

# Run Stage
FROM gcr.io/distroless/static AS final

ENTRYPOINT ["/app/controller"]

COPY --from=build /build/bin/controller /app/controller