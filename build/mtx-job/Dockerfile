# Build stage for go modules
FROM golang:1.21-alpine as build

WORKDIR /build

COPY . .

RUN CGO_ENABLED=0 go build -o ./bin/mtx-job ./cmd/mtx-job/main.go

# Run Stage
FROM gcr.io/distroless/static AS final

ENTRYPOINT ["/app/mtx-job"]

COPY --from=build /build/bin/mtx-job /app/mtx-job