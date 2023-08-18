# Build stage for go modules
FROM golang:1.21-alpine as build

WORKDIR /build

COPY . .

RUN CGO_ENABLED=0 go build -o bin/server ./cmd/server/

# Run Stage
FROM gcr.io/distroless/static AS final

ENTRYPOINT ["/app/server"]

COPY --from=build /build/bin/server /app/server