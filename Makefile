# Offline verification commands.
.PHONY: build vet test verify

build:
	go build ./...

vet:
	go vet ./...

test:
	go test -race ./...

verify: build vet test
