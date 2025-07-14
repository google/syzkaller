FROM golang:1.24-alpine AS email-reporter-builder

WORKDIR /build

# Prepare the dependencies.
COPY go.mod ./
COPY go.sum ./
RUN go mod download
COPY pkg/ pkg/
COPY prog/ prog/
COPY sys/targets/ sys/targets/
COPY dashboard/dashapi/ dashboard/dashapi/

# Build the tool.
COPY syz-cluster/email-reporter/ syz-cluster/email-reporter/
COPY syz-cluster/pkg/ syz-cluster/pkg/
RUN go build -o /bin/email-reporter /build/syz-cluster/email-reporter

# Build the container.
FROM alpine:latest
WORKDIR /app

COPY --from=email-reporter-builder /bin/email-reporter /bin/email-reporter

ENTRYPOINT ["/bin/email-reporter"]
