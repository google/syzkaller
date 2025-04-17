FROM golang:1.23-alpine AS reporter-builder

WORKDIR /build

# Prepare the dependencies.
COPY go.mod ./
COPY go.sum ./
RUN go mod download
COPY pkg/gcs/ pkg/gcs/

# Build the tool.
COPY syz-cluster/reporter-server/ syz-cluster/reporter-server/
COPY syz-cluster/pkg/ syz-cluster/pkg/
RUN go build -o /bin/reporter-server /build/syz-cluster/reporter-server

# Build the container.
FROM alpine:latest
WORKDIR /app

COPY --from=reporter-builder /bin/reporter-server /bin/reporter-server

EXPOSE 8080

ENTRYPOINT ["/bin/reporter-server"]
