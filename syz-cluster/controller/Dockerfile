FROM golang:1.23-alpine AS controller-builder

WORKDIR /build

# Prepare the dependencies.
COPY go.mod ./
COPY go.sum ./
RUN go mod download

# Build the tool.
COPY syz-cluster/controller/ syz-cluster/controller/
COPY syz-cluster/pkg/ syz-cluster/pkg/
RUN go build -o /bin/controller /build/syz-cluster/controller

# Build the container.
FROM alpine:latest
WORKDIR /app

COPY --from=controller-builder /bin/controller /bin/controller

EXPOSE 8080

ENTRYPOINT ["/bin/controller"]
