.PHONY: test
test:
	cd testdata && make vendor
	go test -v ./...

.PHONY: install
install:
	go install ./cmd/protogetter
	@echo "Installed in $(shell which protogetter)"
