SHELL=bash

.PHONY: all
all: fmt mocks test install docker

.PHONY: fmt
fmt:
	go fmt ./...

.PHONY: test
test:
	go test -v -coverprofile=coverage.txt ./...

.PHONY: test.ci
test.ci: test fmt

.PHONY: lint
lint:
	go run github.com/golangci/golangci-lint/cmd/golangci-lint@v1.52.2 run

.PHONY: clean
clean:
	rm -rf mocks