FROM golang:1.23-alpine AS builder

WORKDIR /build

# Prepare the dependencies.
COPY go.mod ./
COPY go.sum ./
RUN go mod download

# Build the tool.
COPY syz-cluster/db-mgmt/*.go syz-cluster/db-mgmt/
COPY syz-cluster/pkg/ syz-cluster/pkg/
RUN go build -o /bin/db-mgmt /build/syz-cluster/db-mgmt

# Create the actual container.
FROM alpine:latest
WORKDIR /app

COPY --from=builder /bin/db-mgmt /bin/db-mgmt

ENTRYPOINT ["/bin/db-mgmt"]
