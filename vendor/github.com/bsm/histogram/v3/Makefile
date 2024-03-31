default: test

test:
	go test ./...

bench:
	go test ./... -run=NONE -bench=. -benchmem

lint:
	golangci-lint run
