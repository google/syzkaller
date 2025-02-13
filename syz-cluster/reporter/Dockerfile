FROM golang:1.23-alpine AS reporter-builder

WORKDIR /build

# Prepare the dependencies.
COPY go.mod ./
COPY go.sum ./
RUN go mod download
COPY pkg/gcs/ pkg/gcs/

# Build the tool.
COPY syz-cluster/reporter/ syz-cluster/reporter/
COPY syz-cluster/pkg/ syz-cluster/pkg/
RUN go build -o /bin/reporter /build/syz-cluster/reporter

# Build the container.
FROM alpine:latest
WORKDIR /app

COPY --from=reporter-builder /bin/reporter /bin/reporter

EXPOSE 8080

ENTRYPOINT ["/bin/reporter"]
