FROM golang:1.24-alpine AS builder

WORKDIR /build

# Prepare the dependencies.
COPY go.mod ./
COPY go.sum ./
RUN go mod download
COPY dashboard/dashapi/ dashboard/dashapi/
COPY pkg/gcs/ pkg/gcs/
COPY pkg/email/ pkg/email/
COPY pkg/auth/ pkg/auth/
COPY pkg/gcpsecret/ pkg/gcpsecret/

# Build the tool.
COPY syz-cluster/tools/send-test-email/*.go syz-cluster/tools/send-test-email/
COPY dashboard/dashapi/ dashboard/dashapi/
COPY syz-cluster/pkg/ syz-cluster/pkg/
RUN go build -o /bin/send-email /build/syz-cluster/tools/send-test-email

# Create the actual container.
FROM alpine:latest
WORKDIR /app

COPY --from=builder /bin/send-email /bin/send-email

ENTRYPOINT ["/bin/send-email"]
