ROOT_DIR:=$(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
GOBIN= $(GOPATH)/bin

define go_install
    go install $(1)
endef

$(GOBIN)/golangci-lint:
	$(call go_install,github.com/golangci/golangci-lint/cmd/golangci-lint@v1.59.1)

$(GOBIN)/gotestsum:
	$(call go_install,gotest.tools/gotestsum@latest)

.PHONY: install
install: $(GOBIN)/golangci-lint $(GOBIN)/gotestsum

.PHONY: clean
clean:
	rm $(GOBIN)/golangci-lint
	rm $(GOBIN)/gotestsum

.PHONY: dependencies-scan
dependencies-scan:
	@echo ">> Scanning dependencies in $(CURDIR)..."
	go list -json -m all | docker run --rm -i sonatypecommunity/nancy:latest sleuth --skip-update-check

.PHONY: lint
lint: $(GOBIN)/golangci-lint
	golangci-lint run --out-format=github-actions --path-prefix=. --verbose -c $(ROOT_DIR)/.golangci.yml --fix

.PHONY: test-%
test-%: $(GOBIN)/gotestsum
	@echo "Running $* tests..."
	gotestsum \
		--format short-verbose \
		--rerun-fails=5 \
		--packages="./..." \
		--junitfile TEST-unit.xml \
		-- \
		-coverprofile=coverage.out \
		-timeout=30m

.PHONY: tools
tools:
	go mod download

.PHONY: test-tools
test-tools: $(GOBIN)/gotestsum

.PHONY: tidy
tidy:
	go mod tidy
