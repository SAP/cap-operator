# Build stage for go modules
FROM golang:1.21-alpine as build

WORKDIR /build

COPY . .

RUN CGO_ENABLED=0 go build -o ./bin/webhook ./cmd/web-hooks/main.go

# Run Stage
FROM gcr.io/distroless/static AS final

ENTRYPOINT ["/app/webhook"]

COPY --from=build /build/bin/webhook /app/webhook