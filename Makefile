VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: build test vet integration release release-snapshot clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o check_strongswan .

test:
	go test ./...

vet:
	go vet ./...

integration:
	go test -tags integration ./...

release:
	goreleaser release --clean

release-snapshot:
	goreleaser release --snapshot --clean

clean:
	rm -f check_strongswan coverage.out
