# Build stage for go modules
FROM golang:1.21-alpine as build

WORKDIR /build

COPY . .

RUN CGO_ENABLED=0 go build -o bin/controller ./cmd/controller/

# Run Stage
FROM gcr.io/distroless/static AS final

ENTRYPOINT ["/app/controller"]

COPY --from=build /build/bin/controller /app/controller