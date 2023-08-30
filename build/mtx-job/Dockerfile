# Build stage for go modules
FROM golang:1.21-alpine as build
ARG TARGETOS
ARG TARGETARCH
ENV CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH}

WORKDIR /build

COPY go.mod go.mod
COPY go.sum go.sum

RUN go mod download

COPY cmd/mtx-job/ cmd/mtx-job/
COPY pkg/ pkg/
COPY internal/util/ internal/util/

RUN go build -o ./bin/mtx-job ./cmd/mtx-job/main.go

# Run Stage
FROM gcr.io/distroless/static AS final

ENTRYPOINT ["/app/mtx-job"]

COPY --from=build /build/bin/mtx-job /app/mtx-job