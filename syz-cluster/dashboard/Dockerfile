FROM golang:1.23-alpine AS dashboard-builder

WORKDIR /build

# Prepare the dependencies.
COPY go.mod ./
COPY go.sum ./
RUN go mod download

# Build the tool.
COPY syz-cluster/dashboard/ syz-cluster/dashboard/
COPY syz-cluster/pkg/ syz-cluster/pkg/
RUN go build -o /bin/web-dashboard /build/syz-cluster/dashboard

# Build the container.
FROM alpine:latest
WORKDIR /app

COPY --from=dashboard-builder /bin/web-dashboard /bin/web-dashboard

EXPOSE 8081

ENTRYPOINT ["/bin/web-dashboard"]
